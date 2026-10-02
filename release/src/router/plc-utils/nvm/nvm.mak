# file: nvm/nvm.mak

# ====================================================================
# programs;
# --------------------------------------------------------------------

chknvm.o: chknvm.c error.h files.h flags.h getoptv.h memory.h nvm.h sdram.h
chknvm1.o: chknvm1.c error.h files.h flags.h getoptv.h memory.h nvm.h sdram.h
chknvm2.o: chknvm2.c error.h files.h flags.h getoptv.h memory.h nvm.h sdram.h
nvmmerge.o: nvmmerge.c error.h files.h flags.h getoptv.h memory.h nvm.h
nvmsplit.o: nvmsplit.c error.h files.h flags.h getoptv.h memory.h nvm.h
tonvm.o: tonvm.c endian.h error.h files.h getoptv.h memory.h number.h nvm.h putoptv.h version.h

# ====================================================================
# functions;
# --------------------------------------------------------------------

NVMSelect.o: NVMSelect.c error.h files.h plc.h
fdpanther_nvm_manifest.o: fdpanther_nvm_manifest.c endian.h error.h files.h nvm.h
fdpanther_nvm_revision.o: fdpanther_nvm_revision.c endian.h error.h files.h nvm.h
lightning_nvm_file.o: lightning_nvm_file.c error.h files.h memory.h nvm.h
lightning_nvm_peek.o: lightning_nvm_peek.c format.h memory.h nvm.h
lightning_nvm_seek.o: lightning_nvm_seek.c endian.h error.h flags.h memory.h nvm.h pib.h
lightning_nvm_size.o: lightning_nvm_size.c endian.h files.h error.h nvm.h
panther_nvm_manifest.o: panther_nvm_manifest.c endian.h error.h format.h nvm.h
manifetch.o: manifetch.c endian.h nvm.h
nvm.o: nvm.c nvm.h
nvmfile.o: nvmfile.c endian.h error.h files.h nvm.h
nvmpeek.o: nvmpeek.c memory.h nvm.h
panther_nvm_file.o: panther_nvm_file.c error.h files.h memory.h nvm.h
panther_nvm_peek.o: panther_nvm_peek.c format.h memory.h nvm.h
panther_nvm_seek.o: panther_nvm_seek.c endian.h error.h flags.h memory.h nvm.h pib.h
panther_nvm_size.o: panther_nvm_size.c endian.h files.h error.h nvm.h
panther_nvm_revision.o: panther_nvm_revision.c endian.h error.h format.h nvm.h

# ====================================================================
# headers;
# --------------------------------------------------------------------

nvm.h: types.h


