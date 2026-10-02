#!/bin/sh
# file: programs/programs.sh

# ====================================================================
# programs;
# --------------------------------------------------------------------

g++ -Wall -Wextra -Wno-unused-parameter -o netifs netifs.cpp
g++ -Wall -Wextra -Wno-unused-parameter -o hpavkey hpavkey.cpp
g++ -Wall -Wextra -Wno-unused-parameter -o example-1 example-1.cpp
g++ -Wall -Wextra -Wno-unused-parameter -o example-2 example-2.cpp
g++ -Wall -Wextra -Wno-unused-parameter -o example-3 example-3.cpp
g++ -Wall -Wextra -Wno-unused-parameter -o example-4 example-4.cpp
g++ -Wall -Wextra -Wno-unused-parameter -o example-5 example-5.cpp

# ====================================================================
# cleanse;
# --------------------------------------------------------------------

rm -f *.o

