#!/bin/sh
# file: toys/toys.sh

# ====================================================================
# programs;
# --------------------------------------------------------------------

# gcc -Wall -Wextra -Wno-unused-parameter -o respond respond.1.c
gcc -Wall -Wextra -Wno-unused-parameter -o respond respond.c
# gcc -Wall -Wextra -Wno-unused-parameter -o solicit solicit.1.c
gcc -Wall -Wextra -Wno-unused-parameter -o solicit solicit.c

# ====================================================================
# functions;
# --------------------------------------------------------------------

# ====================================================================
# cleanse;
# --------------------------------------------------------------------

rm -f *.o

