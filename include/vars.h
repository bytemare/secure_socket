/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef secure_broker_broker_VARS_H
#define secure_broker_broker_VARS_H


/**
 * Default Program Parameters
 */
#define IPC_PORT 6666
#define IPC_NB_CNX 200
#define IPC_DOMAIN AF_UNIX
#define IPC_PROTOCOL SOCK_STREAM
#define IPC_SOCKET_PATH "/tmp/sock_secure_broker"
#define IPC_MQ_NAME "/secure_broker_MQ"
#define IPC_LOG_FILE "/tmp/secure_broker/log/secure_broker_logs"
#define IPC_AUTHORIZED_PEER_USERNAME "peer-uid"
#define IPC_SOCKET_PERMS "0660"
#define IPC_AUTHORIZED_PEER_PID 0
#define IPC_AUTHORIZED_PEER_UID 0
#define IPC_AUTHORIZED_PEER_GID 0
#define IPC_PEER_BINARY_NAME_FILE_FORMAT "/proc/%d/%s"
#define IPC_PEER_BINARY_NAME_FILE "comm"


/**
 * Paths to Scripts to use
 */


/**
 * Paths to configurations to use
 */



#endif /* secure_broker_broker_VARS_H */
