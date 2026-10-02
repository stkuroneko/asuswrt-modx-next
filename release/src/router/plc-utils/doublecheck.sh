#!/bin/sh

# ====================================================================
#  Copyright (c) 2013 Qualcomm Atheros, Inc.
#  All Rights Reserved. 
#  Qualcomm Atheros Confidential and Proprietary. 
# --------------------------------------------------------------------

#PROJECTS=VisualStudioNET
FOLDERS="classes ether key mdio mme nda nodes nvm pib plc programs ram serial tools slac qca"
CATALOG1=solution.txt
CATALOG2=programs.txt
CATALOG=catalog.txt

# ====================================================================
#   compile all programs stand-alone to verify include statements;
# --------------------------------------------------------------------

for folder in ${FOLDERS}; do
	echo ${folder}
	cd ${folder}
	bash ${folder}.sh
	cd ..
done

