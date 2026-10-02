# MT7621 board profiles

Build all adapted boards from the `port/mt7621-board-profiles` branch. Run `make` from
`release/src-ra-openwrt-4210` and select one `BOARD_PROFILE`. Do not combine
builds for different profiles in the same command; the build tree is shared.

| `BOARD_PROFILE` | Firmware base / make target | Output name |
| --- | --- | --- |
| `C-Life-XG1` | `rt-ax53u` | `XG1` |
| `H3C-TX180X` | `rt-ax54` | `H3C-TX180X` |
| `JCG-Q20` | `rt-ax54` | `JCG-Q20` |
| `CMCC-A9` | `rt-ax54` | `CMCC-A9` |
| `CMCC-A9.2` | `rt-ax54` | `CMCC-A9-V2` |
| `CR660X` | `rt-ax53u` | `CR660X` |
| `XY-C3N` | `rt-ax53u` | `XY-C3N` |
| `SIM-AX18` | `rt-ax53u` | `SIMAX1800T` |
| `RX6000` | `rt-ax54` | `RX6000` |
| `G-AX1800` | `rt-ax53u` | `G-AX1800` |
| `KOMI-A8` | `rt-ax54` | `KOMI-A8` |

Example:

```sh
cd ~/asuswrt-7621-mesh/release/src-ra-openwrt-4210
make BOARD_PROFILE=KOMI-A8 rt-ax54
```

The `BOARD_PROFILE` selects the original branch's build options, startup
settings, buttons, LEDs, switch port order, and Web display name. The firmware
base remains the one used by that board's original branch. Omit
`BOARD_PROFILE` to build the original ASUS target.

## Switching firmware bases

The original build checks the base stored in the generated top-level `.config`.
When switching between `rt-ax53u` and `rt-ax54`, remove that generated file first:

```sh
cd ~/asuswrt-7621-mesh/release/src-ra-openwrt-4210
rm -f .config
make BOARD_PROFILE=KOMI-A8 rt-ax54
```

Always pair the profile with the target listed above.
