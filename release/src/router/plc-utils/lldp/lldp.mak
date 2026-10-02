# file: toys/toys.mak

# ====================================================================
# programs;
# --------------------------------------------------------------------

solicit.1.o: solicit.1.c channel.h error.h flags.h getoptv.h memory.h number.h plc.h putoptv.h types.h 
respond.1.o: respond.1.c channel.h error.h flags.h getoptv.h memory.h mme.h number.h plc.h putoptv.h types.h 
solicit.o: solicit.c LLDP.h channel.h error.h flags.h getoptv.h memory.h number.h plc.h putoptv.h types.h 
respond.o: respond.c LLDP.h channel.h error.h flags.h getoptv.h memory.h number.h plc.h putoptv.h types.h 

# ====================================================================
# functions;
# --------------------------------------------------------------------

TLVPack.o: TLVPack.c types.h LLDP.h
TLVPackOS.o: TLVPackOS.c types.h LLDP.h
TLVPick.o: TLVPick.c types.h LLDP.h
TLVPeek.o: TLVPeek.c types.h LLDP.h
LLDP.o: LLDP.c LLDP.h types.h

# ====================================================================
# header files;
# --------------------------------------------------------------------


