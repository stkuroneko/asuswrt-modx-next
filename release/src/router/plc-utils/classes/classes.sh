#!/bin/sh   
# file: classes/classes.sh

# ====================================================================
# programs;
# --------------------------------------------------------------------

# ====================================================================
# classes;
# --------------------------------------------------------------------

g++ -Wall -Wextra -Wno-unused-parameter -c oHPAVKey.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c oSHA256.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c oerror.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c oethernet.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c oflagword.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c ogetoptv.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c ohomeplug.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c ointellon.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c ointerface.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c ointerfaces.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLNetwork.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLNetworks.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLStation.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLChannel.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLMessage.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLParameters.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c CPLFirmware.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c omemory.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c oputoptv.cpp 
g++ -Wall -Wextra -Wno-unused-parameter -c oversion.cpp 

# ====================================================================
# cleanse;
# --------------------------------------------------------------------

rm -f *.o 
