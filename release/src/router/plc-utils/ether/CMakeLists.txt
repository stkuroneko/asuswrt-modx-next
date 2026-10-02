# ====================================================================
# programs; 
# --------------------------------------------------------------------

add_executable(efeu efeu.c)
add_executable(efsu efsu.c)
add_executable(efru efru.c)
add_executable(efbu efbu.c)
add_executable(edru edru.c)
add_executable(edsu edsu.c)

if (WIN32)
	add_executable(pcapdevs pcapdevs.c)
#else (WIN32)
#	add_executable(nics nics.c hostnics.c)
#	target_link_libraries(nics tools)
#	add_executable(client client.c)
#	target_link_libraries(client tools)
#	add_executable(server server.c)
#	target_link_libraries(server tools)
endif (WIN32)

# ====================================================================
# dependencies; 
# --------------------------------------------------------------------

target_link_libraries(efeu ether tools)
target_link_libraries(efsu ether tools)
target_link_libraries(efru ether tools)

# ====================================================================
# programs; 
# --------------------------------------------------------------------

if (WIN32)
	target_link_libraries(efbu ether tools ws2_32)
	target_link_libraries(edru ether tools ws2_32)
	target_link_libraries(edsu ether tools ws2_32)
	target_link_libraries(pcapdevs ether tools)
else (WIN32)
	target_link_libraries(efbu ether tools)
	target_link_libraries(edru ether tools)
	target_link_libraries(edsu ether tools)
endif (WIN32)

#
# Platform specific executables.
#

if (WIN32)
	add_executable(pcapdevs pcapdevs.c)
	target_link_libraries(pcapdevs ether tools)
#else (WIN32)
#	add_executable(nics nics.c hostnics.c)
#	target_link_libraries(nics tools)

#	add_executable(client client.c)
#	target_link_libraries(client tools)
#
#	add_executable(server server.c)
#	target_link_libraries(server tools)
endif (WIN32)

#
# Libraries.
#

set(ETHER_SRC openchannel.c closechannel.c sendpacket.c readpacket.c channel.c gethwaddr.c)

if (WIN32)
	set(ETHER_SRC ${ETHER_SRC} getifname.c)
else (WIN32)
	set(ETHER_SRC ${ETHER_SRC} hostnics.c)
endif (WIN32)

add_library(ether ${ETHER_SRC})

if (WIN32)
	target_link_libraries(ether tools Packet wpcap)
else (WIN32)
	target_link_libraries(ether tools)
endif (WIN32)

#
# Install.
#
set(ETHER_INSTALL efeu efsu efru efbu edru edsu)

if (WIN32)
	set(ETHER_INSTALL ${ETHER_INSTALL} pcapdevs)
else (WIN32)
#	set(ETHER_INSTALL ${ETHER_INSTALL} nics client server)
endif (WIN32)

install(TARGETS ${ETHER_INSTALL}
	RUNTIME DESTINATION bin
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID)

