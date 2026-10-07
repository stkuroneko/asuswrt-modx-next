# RT-AX54 special profile with no buttons and writable bootloader MTD.
export RT-AX54 := $(filter-out DTB=%,$(RT-AX54))
export RT-AX54 += DTB="mt7621-rfb-ax-special.dtb" REAL_NAME="AX54-SPECIAL"
