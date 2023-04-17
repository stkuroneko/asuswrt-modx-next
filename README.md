假如你对OpenWrt开发感兴趣，黑猫强烈推荐佐大的OpenWrt培训班，报名地址：https://forgotfun.org/2018/04/openwrt-training-2018.html


注意：
=
1. **不**要用 **root** 用户 git 和编译！！！
2. 国内用户编译前最好准备好梯子

## 编译

1. 首先装好 Ubuntu 64bit，推荐  Ubuntu  18 LTS x64 /  Mint 19.1

2. 命令行输入 `sudo apt-get update` ，然后输入
`
sudo apt-get -y install build-essential asciidoc binutils bzip2 gawk gettext git libncurses5-dev libz-dev patch python3.5 python2.7 unzip zlib1g-dev lib32gcc1 libc6-dev-i386 subversion flex uglifyjs git-core gcc-multilib p7zip p7zip-full msmtp libssl-dev texinfo libglib2.0-dev xmlto qemu-utils upx libelf-dev autoconf automake libtool autopoint device-tree-compiler g++-multilib antlr3 gperf wget libncurses5:i386 libelf1:i386 lib32z1 lib32stdc++6 gtk-doc-tools intltool binutils-dev cmake lzma liblzma-dev lzma-dev uuid-dev liblzo2-dev xsltproc dos2unix libstdc++5 docbook-xsl-* sharutils autogen shtool gengetopt libltdl-dev libtool-bin
`

3. 使用 `git clone https://github.com/stkuroneko/asuswrt-modx-next.git` 命令下载好源代码

4. 使用 `git clone https://github.com/SWRT-dev/mtk-toolchains` 命令下载toolchains

5. 分别执行 `cd mtk-toolchains`

	`sudo ln -sf $(pwd)/toolchain-aarch64_cortex-a53+neon-vfpv4_gcc-5.4.0_glibc-2.24 /opt/`

	`sudo ln -sf $(pwd)/lede-toolchain-mediatek-mt7629_gcc-5.4.0_musl-1.1.24_eabi.Linux-x86_64 /opt/`

	`sudo ln -sf $(pwd)/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24 /opt/`

	`sudo ln -sf $(pwd)/toolchain-aarch64_cortex-a53_gcc-8.4.0_glibc /opt/`
	
	mt7622继续执行

	`cd toolchain-aarch64_cortex-a53+neon-vfpv4_gcc-5.4.0_glibc-2.24/lib`

	`tar xvJf libc.a.tar.xz`

6. 然后 `cd ../asuswrt-modx-next/release/src-ra-openwrt-4210` 进入目录

7. 输入 `make rt-cmcca9` 即可开始编译你要的固件了。


8. 编译完成后输出固件路径：asuswrt-modx-next/release/src-ra-openwrt-4210/image



