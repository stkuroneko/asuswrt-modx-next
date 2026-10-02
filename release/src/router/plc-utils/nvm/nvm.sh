#!/bin/sh
# file: nvm/nvm.sh

# ====================================================================
# programs;
# --------------------------------------------------------------------

gcc -Wall -o chknvm chknvm.c
gcc -Wall -o chknvm1 chknvm1.c
gcc -Wall -o chknvm2 chknvm2.c
gcc -Wall -o nvmmerge nvmmerge.c
gcc -Wall -o nvmsplit nvmsplit.c
gcc -Wall -o tonvm tonvm.c 

# ====================================================================
# functions;
# --------------------------------------------------------------------

gcc -Wall -c fdmanifest.c
gcc -Wall -c fdrevision.c
gcc -Wall -c nvmfile.c
gcc -Wall -c nvmpeek.c
gcc -Wall -c lightning_nvm_file.c
gcc -Wall -c lightning_nvm_peek.c
gcc -Wall -c lightning_nvm_seek.c
gcc -Wall -c lightning_nvm_size.c
gcc -Wall -c panther_nvm_file.c
gcc -Wall -c panther_nvm_lock.c
gcc -Wall -c panther_nvm_manifest.c
gcc -Wall -c panther_nvm_revision.c
gcc -Wall -c panther_nvm_peek.c
gcc -Wall -c panther_nvm_seek.c
gcc -Wall -c panther_nvm_size.c
gcc -Wall -c NVMSelect.c

# ====================================================================
# cleanse;
# --------------------------------------------------------------------

rm -f *.o

