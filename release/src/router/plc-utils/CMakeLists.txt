# ====================================================================
#
# --------------------------------------------------------------------

cmake_minimum_required(VERSION 2.6)
project(PLCUTILS)

# ====================================================================
#
# --------------------------------------------------------------------

add_definitions(-DMAKEFILE -D__GETOPT_H__ -D_GETOPT_DEFINED_)

if (CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "-O2 -Wall -Wextra -Wno-unused-parameter")
	set(CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra -Wno-unused-parameter")
endif (CMAKE_COMPILER_IS_GNUCC)

if (MSVC10)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd\"4996\"")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /wd\"4996\"")
endif (MSVC10)

if (WIN32)
	add_definitions(-DWINPCAP)
	include_directories(BEFORE "${PLCUTILS_SOURCE_DIR}/VisualStudioNET/include")
	link_directories("${PLCUTILS_SOURCE_DIR}/VisualStudioNET/library")
endif (WIN32)

# ====================================================================
#
# --------------------------------------------------------------------

add_subdirectory(tools)
add_subdirectory(ether)
add_subdirectory(key)
add_subdirectory(nvm)
add_subdirectory(pib)
add_subdirectory(ram)
add_subdirectory(mme)
add_subdirectory(mdio)
add_subdirectory(nda)
add_subdirectory(qca)
add_subdirectory(serial)
add_subdirectory(nodes)
add_subdirectory(plc)

