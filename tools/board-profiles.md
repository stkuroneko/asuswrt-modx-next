# Unified RT-AX53U board profiles

Build from `release/src-ra-openwrt-4210` with
`make BOARD_PROFILE=<profile> rt-ax53u`. The default is HIWIFI4.
All profiles share the software feature set in `target.mak`; board-specific
settings describe hardware, driver capabilities and product identity.

| Profile | Wireless | WAN + LAN | USB sockets | Image prefix |
| --- | --- | --- | --- | --- |
| R3G | MT7603 + MT7612 | 1 + 2 | 1 | MI-R3G |
| HIWIFI4 | MT7603 + MT7612 | 1 + 3 | 2 | HIWIFI4 |
| E8820S | MT7603 + MT7612 | 1 + 4 | 1 | ZTE-E8820S |
| R6800 | MT7615 + MT7615 | 1 + 4 | 2 | NETGEAR-R6800 |
| R3P | MT7615 + MT7615 | 1 + 3 | 1 | MI-R3P |
| RM2100 | MT7603 + MT7615 | 1 + 3 | 0 | REDMI-AC2100 |
| SIM-AX18T | MT7915 DBDC | 1 + 4 | 0 | SIMAX1800T |

E8820S uses a dedicated device tree which resets PCIe0 and PCIe1 through
GPIO19 and GPIO4 before device enumeration. This addresses the board-specific
MT7612 cold-boot failure where the 5 GHz interface can randomly disappear.

SIM-AX18T's 1 WAN + 4 LAN layout was confirmed by the owner. Its L1 profile
uses the firmware's `ra0/rai0`, `apcli0/apclii0` names and installed `/ra_SKU`
paths. Its original EEPROM size and offset are retained. MT7615 profiles use
the same second-card default offset (`0x8000`) as their installed L1 profiles;
the driver can override that default from the L1 profile.

The internal product ID remains RT-AX53U. These different boards must not
share an online update image, so all profiles advertise `noupdate`; manual
firmware upload remains available. Firmware filenames distinguish boards.

Run `python3 tools/check_board_profiles.py` from any directory after the
userspace `config/conf` tool has been built. The check runs configuration
generation and userspace Kconfig in temporary directories, checks common
capabilities, LAN status counts, stream counts, image-name uniqueness,
profile isolation and SKU install inputs. It does not replace kernel and
firmware builds or testing on the physical devices.

For release validation, build all seven profiles in sequence, inspect final
`router/shared/rtconfig.h` and kernel `.config`, and test physical WAN/LAN,
both wireless bands, buttons, LEDs and USB on each device. Do not infer
runtime correctness solely from a successful image build.

## Validation on 2026-09-25

All six profile builds returned exit code 0 and produced separate images.
R3G and HIWIFI4 were rebuilt after the final band-steering configuration
fix. All six final headers retain exactly their own board macro and enable
OPENVPN, OOKLA, GAME_MODE, WIREGUARD, SOFTCENTER, EASYMESH and RALINK_BSD.
All six image MD5 checks passed. Logs and final configuration snapshots are
under `/tmp/rtax53u-final-<profile>.{log,h,kernel}`. No device flash or physical
hardware test was performed.

The existing binary `LnxHtmlEnumDict` crashes while processing some captive
portal templates and `dashboard/js/chart.min.js`; the build ignores these
failures and still packages an image. Existing ignored install errors are
also present in the logs. Successful builds therefore do not certify those
web pages or constitute a clean release validation. This tooling issue was
not changed as part of the board merge.
