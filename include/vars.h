/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef secure_socket_VARS_H
#define secure_socket_VARS_H


/**
 * Default Program Parameters
 */
#define IPC_PORT 6666
#define IPC_NB_CNX 200
#define IPC_RAND_LENGTH 32
#define IPC_DOMAIN AF_UNIX
#define IPC_PROTOCOL SOCK_STREAM
#define IPC_SOCKET_PATH_BASE "/tmp/"
#define IPC_MQ_NAME "/secure_socket_MQ"
#define IPC_LOG_FILE "/tmp/secure_socket/log/secure_socket_logs"
#define IPC_AUTHORIZED_PEER_USERNAME "peer-uid"
#define IPC_SOCKET_PERMS "0660"
#define IPC_AUTHORIZED_PEER_PID 0
#define IPC_AUTHORIZED_PEER_UID 0
#define IPC_AUTHORIZED_PEER_GID 0
#define IPC_PEER_BINARY_NAME_FILE_ROOT "/proc/"
#define IPC_PEER_BINARY_NAME_FILE "comm"


/**
 * Paths to Scripts to use
 */


/**
 * Paths to configurations to use
 */



#endif /* secure_socket_VARS_H */
