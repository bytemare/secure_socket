# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.

#! /bin/bash

set -e

#
# Parameter gathering and building out-of-source with CMAKE
#



# Check if file exists
check_file()
{
    [ -f $1 ] || ( echo "\n[Error] $1 does not exist !" && exit 1)
}

echo -n "Checking for build files ..."

PARAMETERS="./parameters.conf" && check_file $PARAMETERS
CMAKELISTS="./CMakeLists.txt" && check_file $CMAKELISTS

echo " done."



#
# Source parameter file
#

source $PARAMETERS


# Targets to be created and deleted
CREAT="$RELEASE $DEBUG $LINK $RUNNER $SOCKET_PATH $CLEANER"

# Clean up previous work
rm --force -rf $CREAT


# Build cleaner script
s="rm --force -rf $CREAT"

echo $SHELL_H > $CLEANER
echo $s >> $CLEANER
chmod 500 $CLEANER


# Build Release
mkdir -p $RELEASE
cd $RELEASE
# cmake -DCMAKE_BUILD_TYPE=$RELEASE ..
# make


cd ..

# Build Debug
mkdir -p $DEBUG
cd $DEBUG
cmake -DCMAKE_BUILD_TYPE=$DEBUG ..
make


cd ..


#ln -s ./$BUILD/$EXEC $LINK
#chmod -R 500 *
#chown -R secure_broker *
#chgrp -R secure_broker *


# Build launching script
s=$s"./$DEBUG/$LINK "
s=$s"socket_path=$SOCKET_PATH "
s=$s"mq_name=$MQ_NAME "
s=$s"log_file=$LOG_FILE "
s=$s"domain=$DOMAIN "
s=$s"protocol=$PROTOCOL "
s=$s"max_connections=$MAX_CONNECTIONS "
s=$s"socket_permissions=$SOCKET_PERMISSIONS "
s=$s"authorised_peer_username=$AUTHORISED_PEER_NAME "


echo $SHELL_H > $RUNNER
echo $s >> $RUNNER
chmod 500 $RUNNER
