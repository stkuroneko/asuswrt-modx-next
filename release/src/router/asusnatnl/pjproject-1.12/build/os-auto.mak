# build/os-auto.mak.  Generated from os-auto.mak.in by configure.

export OS_CFLAGS   := $(CC_DEF)PJ_AUTOCONF=1 -I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/router/openssl/include  -g -O2 -fPIC -DROUTER=1  -DPJ_IS_BIG_ENDIAN=0 -DPJ_IS_LITTLE_ENDIAN=1

export OS_CXXFLAGS := $(CC_DEF)PJ_AUTOCONF=1 -I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/router/openssl/include  -g -O2 -fPIC -DROUTER=1  

export OS_LDFLAGS  := -L/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/router/openssl    -L/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/lib -L/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/lib/gcc/mipsel-openwrt-linux-musl/5.4.0 -lc -lm -ldl -lgcc_s -lm -lrt -lpthread  -lssl -lcrypto -lpthread    -lstdc++ -lcrypto -lssl

export OS_SOURCES  := 


