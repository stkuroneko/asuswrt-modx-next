# file: programs/programs.mak

# ====================================================================
# programs;
# --------------------------------------------------------------------

chknvm3.o: chknvm3.cpp CPLFirmware.hpp ogetoptv.hpp 
hpavkey.o: hpavkey.cpp oHPAVKey.hpp ogetoptv.hpp
netifs.o: netifs.cpp ointerfaces.hpp
plcnets.o: plcnets.cpp ogetoptv.hpp ointerfaces.hpp CPLNetworks.hpp 


