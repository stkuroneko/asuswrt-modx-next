# RT-AX53U special profile with no buttons and writable bootloader MTD.
export RT-AX53U := $(filter-out DTB=%,$(RT-AX53U))
export RT-AX53U += DTB="mt7621-rfb-ax-special.dtb" REAL_NAME="AX53U-SPECIAL"
