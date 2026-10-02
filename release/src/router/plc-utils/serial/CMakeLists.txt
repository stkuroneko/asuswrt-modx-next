# ====================================================================
# programs;
# --------------------------------------------------------------------

add_executable(int6kuart int6kuart.c)
add_executable(int6kbaud int6kbaud.c)
add_executable(int6kdetect int6kdetect.c)
add_executable(ptsctl ptsctl.c)
add_executable(weeder weeder.c)

if (NOT WIN32)
	add_executable(ttycat ttycat.c)
	add_executable(ttysend ttysend.c)
	add_executable(ttysig ttysig.c)
	add_executable(ttyrecv ttyrecv.c)
endif (NOT WIN32)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(int6kuart serial tools)
target_link_libraries(int6kbaud serial tools)
target_link_libraries(int6kdetect serial tools)
target_link_libraries(ptsctl tools)
target_link_libraries(weeder tools)
target_link_libraries(relay tools)

if (NOT WIN32)
	target_link_libraries(ttycat serial tools)
	target_link_libraries(ttyrecv serial tools)
	target_link_libraries(ttysend serial tools)
	target_link_libraries(ttysig tools)
endif (NOT WIN32)

# ====================================================================
# libraries;
# --------------------------------------------------------------------

set(SERIAL_SRC serial.c openport.c closeport.c)

if (NOT WIN32)
	set(SERIAL_SRC ${SERIAL_SRC} baudrate.c)
endif (NOT WIN32)

add_library(serial ${SERIAL_SRC})

