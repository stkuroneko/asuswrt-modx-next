# asuswrt-modx-next

基于 ASUSWRT / SWRT 的固件适配项目。`master` 已统一八款机型的适配，通过 `BOARD_PROFILE` 选择硬件，无需切换机型分支。

各机型共用 RT-AX53U 构建框架和公共软件功能；无线驱动、校准数据、网口映射、GPIO、按键、LED、USB 和显示名称按硬件区分。

## 支持的机型

| BOARD_PROFILE | 机型 | 无线组合 | WAN + LAN | USB 数量 | 固件文件名前缀 |
| --- | --- | --- | --- | --- | --- |
| `R3G` | 小米路由器 3G | MT7603 + MT7612 | 1 + 2 | 1 | `MI-R3G` |
| `HIWIFI4` | 极路由 4 增强版 HC5962 | MT7603 + MT7612 | 1 + 3 | 2 | `HIWIFI4` |
| `E8820S` | 中兴 E8820S | MT7603 + MT7612 | 1 + 4 | 1 | `ZTE-E8820S` |
| `A040WQ` | Nokia A-040W-Q | MT7615 + MT7615 | 1 + 4 | 1 | `NOKIA-A040WQ` |
| `R6800` | NETGEAR R6800 | MT7615 + MT7615 | 1 + 4 | 2 | `NETGEAR-R6800` |
| `R3P` | 小米路由器 Pro | MT7615 + MT7615 | 1 + 3 | 1 | `MI-R3P` |
| `RM2100` | 红米 AC2100 | MT7603 + MT7615 | 1 + 3 | 0 | `REDMI-AC2100` |
| `SIM-AX18T` | SIM-AX18T | MT7915 双频 DBDC | 1 + 4 | 0 | `SIMAX1800T` |

公共构建功能包括 OpenVPN、WireGuard、Ookla 测速、游戏模式、软件中心、EasyMesh 和 Smart Connect。运行效果仍需实机验证；USB、AX 等硬件能力按机型呈现。

## 编译环境

使用普通用户下载源码和编译，**不要使用 root 用户运行 Git 或 make**。安装依赖及创建工具链链接时使用 `sudo`。

原有构建环境为 Ubuntu 18.04 LTS x64 / Linux Mint 19.1。以下保留该环境的依赖清单，较新发行版可能需要调整包名和兼容依赖。

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get -y install \
  build-essential asciidoc binutils bzip2 gawk gettext git libncurses5-dev \
  libz-dev patch python3.5 python2.7 unzip zlib1g-dev lib32gcc1 libc6-dev-i386 \
  subversion flex uglifyjs git-core gcc-multilib p7zip p7zip-full msmtp \
  libssl-dev texinfo libglib2.0-dev xmlto qemu-utils upx libelf-dev autoconf \
  automake libtool autopoint device-tree-compiler g++-multilib antlr3 gperf \
  wget libncurses5:i386 libelf1:i386 lib32z1 lib32stdc++6 gtk-doc-tools \
  intltool binutils-dev cmake lzma liblzma-dev lzma-dev uuid-dev liblzo2-dev \
  xsltproc dos2unix libstdc++5 'docbook-xsl-*' sharutils autogen shtool \
  gengetopt libltdl-dev libtool-bin bison
```

下载源码和工具链，确保网络可以访问依赖下载源：

```bash
git clone https://github.com/stkuroneko/asuswrt-modx-next.git
git clone https://github.com/SWRT-dev/mtk-toolchains.git
cd mtk-toolchains
sudo ln -sfn "$PWD/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24" /opt/
cd ../asuswrt-modx-next
```

上述八款 MT7621 机型使用这套 MIPS 工具链。其他平台需要配置各自的工具链。

## 编译固件

从仓库根目录进入构建目录，显式指定机型：

```bash
cd release/src-ra-openwrt-4210
make BOARD_PROFILE=R3G rt-ax53u
```

其他机型使用相同构建目标：

```bash
make BOARD_PROFILE=HIWIFI4 rt-ax53u
make BOARD_PROFILE=E8820S rt-ax53u
make BOARD_PROFILE=A040WQ rt-ax53u
make BOARD_PROFILE=R6800 rt-ax53u
make BOARD_PROFILE=R3P rt-ax53u
make BOARD_PROFILE=RM2100 rt-ax53u
make BOARD_PROFILE=SIM-AX18T rt-ax53u
```

不指定 `BOARD_PROFILE` 时默认编译 **HIWIFI4**。同一工作区应依次构建各机型，不能同时运行多个机型构建，因为它们共用配置和输出目录。

固件输出到 `release/src-ra-openwrt-4210/image/`，包含机型前缀的 `.trx` 文件及对应 `.md5` 校验文件。文件名区分机型，镜像内部产品标识统一保留为 `RT-AX53U`。

## 闪存布局与启动模式

配套 U-Boot 项目：[stkuroneko/Uboot-mips](https://github.com/stkuroneko/Uboot-mips)。U-Boot 的编译和使用说明请参阅该项目。

八机型统一沿用仓库原版 RT-AX53U 的 NAND + NMBM、硬件 ECC、双固件分区和 `MTK_NAND_BLOCK2` 模式，不使用各机型原厂固件的分区布局。

| 分区 | 起始地址 | 大小 |
| --- | --- | --- |
| Bootloader | `0x000000` | `0x0E0000`（896 KiB） |
| nvram | `0x0E0000` | `0x100000`（1 MiB） |
| Factory | `0x1E0000` | `0x100000`（1 MiB） |
| Factory2 | `0x2E0000` | `0x100000`（1 MiB） |
| Kernel | `0x3E0000` | `0x3200000`（50 MiB） |
| Kernel2 | `0x35E0000` | `0x3200000`（50 MiB） |
| jffs2 | `0x67E0000` | `0x1020000`（16.125 MiB） |

内核加载和入口地址均为 `0x81001000`，设备树串口参数为 `console=ttyS0,115200`，内核根文件系统参数为 `rootfstype=squashfs,jffs2`。

设备的 Bootloader、分区和校准数据必须与此适配方案匹配。此构建流程不会转换设备上的原厂闪存布局，也不代表镜像可以直接从各机型原厂系统刷入。

各机型共用内部产品 ID，但不能混用固件，因此统一关闭在线更新入口，保留手动上传方式；上传时应选择对应机型的镜像。

## 检查与验证状态

在仓库根目录运行配置回归检查，需要已构建的 `release/src/router/config/conf`、C 预处理器和 Python 3.8 或更新版本：

```bash
python3 tools/check_board_profiles.py
```

检查覆盖配置生成、最终板级宏、Smart Connect 依赖、公共能力、LAN 状态数量、无线流数、SKU 安装输入、固件名称唯一性及机型切换隔离。

2026-09-26 验证结果：

- 原有六机型及新增 E8820S 的配置回归检查通过；E8820S 完整构建成功，镜像 MD5 校验通过。A040WQ 配置回归检查和完整构建均已通过，镜像 MD5 校验通过。
- 原有六机型继续使用 RT-AX53U 通用 DTB；E8820S 使用专用 DTB，在 PCIe 枚举前通过 GPIO19 和 GPIO4 同时复位 MT7603 和 MT7612。
- E8820S 实机确认已加载专用 DTB，双 PCIe 复位均成功申请，2.4G 和 5G 无线接口正常启动。
- 镜像头和数据 CRC、FIT 哈希、SquashFS 偏移与长度校验通过，镜像均小于 50 MiB。
- E8820S 已完成实机启动和双频无线接口检查；2.4G LED 的 GPIO 定义仍在实机核对中。其余网口、按键、LED、USB 及长期无线稳定性仍需测试。

已知构建问题：旧工具 `LnxHtmlEnumDict` 处理部分 Captive Portal 模板及 `dashboard/js/chart.min.js` 时出现段错误，构建会忽略这些失败并继续打包；日志中也存在被忽略的安装错误。因此构建成功不等于所有页面及运行功能均已验证。

更多适配说明见 [统一机型配置说明](tools/board-profiles.md)，检查实现见 [check_board_profiles.py](tools/check_board_profiles.py)。

