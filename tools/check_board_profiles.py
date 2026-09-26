#!/usr/bin/env python3
"""Check unified board configuration without changing the build tree."""
import pathlib
import re
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
KERNEL = ROOT / "release/src-ra-openwrt-4210/linux/linux-4.4.198"
ROUTER = ROOT / "release/src/router"
PROFILES = {
    "R3G": ("mt7603_mt7612", "MT7603E", "MT7612E", "usbX1", "2", "2"),
    "HIWIFI4": ("mt7603_mt7612", "MT7603E", "MT7612E", "usbX2", "2", "2"),
    "E8820S": ("mt7603_mt7612", "MT7603E", "MT7612E", "usbX1", "2", "2"),
    "R6800": ("mt7615", "MT7615E", "MT7615E", "usbX2", "4", "4"),
    "R3P": ("mt7615", "MT7615E", "MT7615E", "usbX1", "4", "4"),
    "RM2100": ("mt7603_mt7615", "MT7603E", "MT7615E", None, "2", "4"),
    "SIM-AX18T": ("mt7915", "MT7915", "NONE", None, "2", "2"),
}


def run(args, source=None, cwd=ROOT):
    return subprocess.run(args, input=source, text=True, cwd=cwd,
                          capture_output=True, check=True).stdout


def macro(source, name):
    start = source.index("define " + name)
    return source[start:source.index("\nendef", start) + len("\nendef")]


def main():
    platform = (ROOT / "release/src-ra-openwrt-4210/platform.mak").read_text()
    platform = platform[platform.index("FIRST_IF_POOL ="):]
    platform = platform[:platform.index("\nendef") + len("\nendef")]
    makefile = (ROOT / "release/src-rt/Makefile").read_text()
    board_macro = macro(makefile, "RouterOptions").split(
        '\tif [ "$(CONFIG_LINUX26)"')[0].rstrip().rstrip("\\") + "\nendef\n"
    init = (ROUTER / "rc/init.c").read_text()
    init = init[init.index("\tcase MODEL_RTAX53U:"):]
    init = init[:init.index("#endif\t/* RTAX53U */")]
    switch = (ROUTER / "shared/sysdeps/ralink/mt7620.c").read_text()
    switch = switch[switch.index("void ATE_mt7621_esw_port_status(void)"):]
    switch = switch[switch.index("\n{"):]
    switch = switch[:switch.index("\n#if defined(RTCONFIG_SWRT_I2CLED)")]
    lan_count = {"R3G": 2, "HIWIFI4": 3, "E8820S": 4, "R6800": 4, "R3P": 3,
                 "RM2100": 3, "SIM-AX18T": 4}
    features = None
    image_names = set()
    with tempfile.TemporaryDirectory(prefix="board-profiles-") as temp:
        cfg = pathlib.Path(temp) / "kernel.config"
        router_cfg = pathlib.Path(temp) / "router.config"
        for board, (base, first, second, usb, streams0, streams1) in PROFILES.items():
            target = ('include release/src-rt/target.mak\n'
                      'check:\n\t@echo $(RT-AX53U)\n')
            options = dict(item.split("=", 1) for item in shlex.split(run(
                ["make", "-s", "-f", "-", "check", "BOARD_PROFILE=" + board], target)))
            assert options["FIRST_IF"] == first and options["SECOND_IF"] == second, board
            expected_dtb = "mt7621-zte-e8820s.dtb" if board == "E8820S" else "mt7621-rfb-ax-nmbm.dtb"
            assert options["DTB"] == expected_dtb, board
            assert options["REAL_NAME"] not in image_names, "firmware filename collision"
            image_names.add(options["REAL_NAME"])
            cfg.write_text((KERNEL / ("config_base." + base)).read_text())
            recipe = platform + "\ncheck:\n\t$(call platformKernelConfig," + str(cfg) + ")\n"
            run(["make", "-s", "-f", "-", "check"] +
                [key + "=" + value for key, value in options.items()], recipe)
            kernel = cfg.read_text()
            assert "CONFIG_FIRST_IF_" + first + "=y" in kernel, board
            assert kernel.count("CONFIG_SECOND_IF_" + second + "=y") == 1, board
            if second != "NONE":
                assert "CONFIG_RT_SECOND_IF_RF_OFFSET=0x8000" in kernel, board
            assert ("CONFIG_MT76X2_AP=m" in kernel) == (second == "MT7612E"), board

            # Reuse one file across all boards to catch stale profile macros.
            router_cfg.touch()
            recipe = board_macro + "check:\n\t$(call RouterOptions," + str(router_cfg) + ")\n"
            run(["make", "-s", "-f", "-", "check", "BUILD_NAME=RT-AX53U",
                 "BOARD_PROFILE=" + board], recipe)
            define = "RTCONFIG_BOARD_" + board.replace("-", "_")
            assert router_cfg.read_text().splitlines() == [define + "=y"], board
            # The legacy userspace Kconfig drops undeclared board symbols.
            stage = pathlib.Path(temp) / board
            stage.mkdir()
            (stage / "shared").mkdir()
            wireless = "RTCONFIG_WLMODULE_" + {
                "MT7612E": "MT7612E_AP", "MT7615E": "MT7615E_AP",
                "NONE": "MT7915D_AP"}[second]
            (stage / ".config").write_text((ROUTER / "config_base").read_text() +
                "\nRTCONFIG_RALINK=y\nRTCONFIG_RALINK_MT7621=y\n" + define + "=y\n" +
                wireless + "=y\nRTCONFIG_RALINK_BSD=y\n")
            run([str(ROUTER / "config/conf"), "-o", str(ROUTER / "config/config.in")],
                "\n" * 5000, cwd=stage)
            header = (stage / "shared/rtconfig.h").read_text()
            assert "#define " + define + " 1" in header, board
            assert "#define RTCONFIG_RALINK_BSD 1" in header, board
            assert len(re.findall(r"^#define RTCONFIG_BOARD_", header, re.M)) == 1, board
            ports = run(["cpp", "-P", "-DRTAX53U", "-D" + define, "-"], switch)
            assert set(re.findall(r"L([1-4])=", ports)) == set(
                str(n) for n in range(1, lan_count[board] + 1)), board
            active = run(["cpp", "-P", "-D" + define, "-DRTCONFIG_EASYMESH", "-"], init)
            support = set(" ".join(re.findall(r'add_rc_support\("([^"]*)"\)', active)).split())
            hardware = {"usbX1", "usbX2", "usb3", "11AX", "mbo", "ofdma", "wpa3"}
            common = support - hardware
            if features is None:
                features = common
            assert common == features, (board, common ^ features)
            assert {"gameMode", "loclist", "pwrctrl", "noupdate"} <= common, board
            assert (support & {"usbX1", "usbX2"}) == ({usb} if usb else set()), board
            for band, streams in enumerate((streams0, streams1)):
                assert 'nvram_set("wl%d_HT_TxStream", "%s")' % (band, streams) in active, board

            sku = ROUTER / "ra_SingleSKU"
            commands = run(["make", "-sn", "install", "INSTALLDIR=/tmp/unused-board-install"] +
                           [key + "=" + value for key, value in options.items()], cwd=sku)
            for line in commands.replace("\\\n", " ").splitlines():
                if line.strip().startswith("install "):
                    args = shlex.split(line)
                    for source in args[1:-1]:
                        if not source.startswith("-"):
                            assert (sku / source).exists(), (board, source)
            profile = (sku / options["SKU_L1PROFILE"]).read_text()
            if board == "SIM-AX18T":
                assert "INDEX0_main_ifname=ra0;rai0" in profile
                assert "INDEX0_apcli_ifname=apcli;apclii" in profile
                assert "/ra_SKU/SingleSKU_mt7615e-sku.dat" in profile
            print(board + ": PASS (kernel, board isolation, features, streams, SKU)")
        run(["make", "-s", "-f", "-", "check", "BUILD_NAME=RT-AX54",
             "BOARD_PROFILE=HIWIFI4"], recipe)
        assert not router_cfg.read_text().strip(), "board macro leaked to another target"
    print("Other build targets: PASS (no board profile macros)")


if __name__ == "__main__":
    main()
