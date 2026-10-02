# ====================================================================
# programs;
# --------------------------------------------------------------------

add_executable(mdioblock mdioblock.c)
add_executable(mdioblock2 mdioblock2.c)
add_executable(mdiodump mdiodump.c)

if (NOT WIN32)
add_executable(mdiogen mdiogen.c)
endif (NOT WIN32)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(mdioblock tools)
target_link_libraries(mdioblock2 tools)
target_link_libraries(mdiodump tools)

if (NOT WIN32)
target_link_libraries(mdiogen tools)
endif (NOT WIN32)

