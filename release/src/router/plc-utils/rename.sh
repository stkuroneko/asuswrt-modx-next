#!/bin/bash

# ====================================================================
#
# --------------------------------------------------------------------

FILES="*/*.vcxproj"

# ====================================================================
#
# --------------------------------------------------------------------

change ${FILES} -e pibfile1 -t lightning_pib_file
change ${FILES} -e pibpeek1 -t lightning_pib_peek
change ${FILES} -e nvmfile1 -t lightning_nvm_file
change ${FILES} -e nvmpeek1 -t lightning_nvm_peek
change ${FILES} -e nvmseek1 -t lightning_nvm_seek
change ${FILES} -e PIBExtent1 -t lightning_pib_size
change ${FILES} -e NVMExtent1 -t lightning_nvm_size

# ====================================================================
#
# --------------------------------------------------------------------

change ${FILES} -e pibfile2 -t panther_pib_file
change ${FILES} -e pibpeek2 -t panther_pib_peek
change ${FILES} -e nvmfile2 -t panther_nvm_file
change ${FILES} -e nvmpeek2 -t panther_nvm_peek
change ${FILES} -e nvmseek2 -t panther_nvm_seek
change ${FILES} -e PIBExtent2 -t panther_pib_size
change ${FILES} -e NVMExtent2 -t panther_nvm_size
