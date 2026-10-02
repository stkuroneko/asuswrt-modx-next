#file: classes/classes.mak

# ====================================================================
# files;
# --------------------------------------------------------------------

oerror.o: oerror.cpp oerror.hpp types.h stdafx.hpp
oflagword.o: oflagword.cpp oflagword.hpp stdafx.hpp
ogetoptv.o: ogetoptv.cpp ogetoptv.hpp oputoptv.hpp oversion.hpp stdafx.hpp
oHPAVKey.o: oHPAVKey.cpp oHPAVKey.hpp oflagword.hpp oSHA256.hpp stdafx.hpp types.h
ointerface.o: ointerface.cpp ointerface.hpp omemory.hpp oerror.hpp stdafx.hpp types.h
ointerfaces.o: ointerfaces.cpp ointerfaces.hpp oerror.hpp stdafx.hpp ointerface.hpp types.h
omemory.o: omemory.cpp omemory.hpp types.h stdafx.hpp
oputoptv.o: oputoptv.cpp ogetoptv.hpp oputoptv.hpp oversion.hpp stdafx.hpp
oSHA256.o: oSHA256.cpp oSHA256.hpp stdafx.hpp types.h
oversion.o: oversion.cpp oversion.hpp stdafx.hpp

# ====================================================================
# files;
# --------------------------------------------------------------------

CPLChannel.o: CPLChannel.cpp CPLChannel.hpp stdafx.hpp
CPLMessage.o: CPLMessage.cpp CPLMessage.hpp ohomeplug.hpp stdafx.hpp oethernet.hpp
CPLNetwork.o: CPLNetwork.cpp CPLNetwork.hpp ohomeplug.hpp oerror.hpp stdafx.hpp CPLChannel.hpp ointellon.hpp oethernet.hpp types.h oflagword.hpp 
CPLNetworks.o: CPLNetworks.cpp CPLNetwork.hpp CPLChannel.hpp stdafx.hpp
CPLStation.o: CPLStation.cpp CPLStation.hpp omemory.hpp stdafx.hpp

# ====================================================================
# header files;
# --------------------------------------------------------------------

CPLChannel.hpp: stdafx.hpp oflagword.hpp ointerface.hpp ointellon.hpp oethernet.hpp ohomeplug.hpp
CPLFirmware.hpp: stdafx.hpp CPLChannel.hpp oflagword.hpp ointerface.hpp ointellon.hpp oethernet.hpp ohomeplug.hpp
CPLNetwork.hpp: stdafx.hpp CPLChannel.hpp CPLStation.hpp oflagword.hpp ointerface.hpp ointellon.hpp oethernet.hpp ohomeplug.hpp
CPLNetworks.hpp: stdafx.hpp CPLChannel.hpp CPLNetwork.hpp oflagword.hpp ointerface.hpp ointellon.hpp CPLStation.hpp oethernet.hpp ohomeplug.hpp
CPLParameters.hpp: stdafx.hpp CPLChannel.hpp CPLMessage.hpp oflagword.hpp ointerface.hpp ointellon.hpp oethernet.hpp ohomeplug.hpp
CPLStation.hpp: stdafx.hpp CPLChannel.hpp oflagword.hpp ointerface.hpp ointellon.hpp oethernet.hpp ohomeplug.hpp
oHPAVKey.hpp: stdafx.hpp oSHA256.hpp
oerror.hpp: stdafx.hpp types.h
ogetoptv.hpp: stdafx.hpp oputoptv.hpp oversion.hpp
ohomeplug.hpp: stdafx.hpp oethernet.hpp
ointellon.hpp: stdafx.hpp oethernet.hpp ohomeplug.hpp
ointerfaces.hpp: stdafx.hpp ointerface.hpp

CPLMessage.hpp oSHA256.hp oethernet.hpp oflagword.hpp ointerface.hpp omemory.hpp oputoptv.hpp oversion.hpp: stdafx.hpp
