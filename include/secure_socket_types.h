/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef secure_socket_TSM_TYPES_H
#define secure_socket_TSM_TYPES_H

#include <mqueue.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stdbool.h>
#include <values.h>
#include <log.h>

typedef struct _ipc_options{

    /* Logging related parameters */
    uint8_t verbosity;
    char mq_name[PATH_MAX];
    char log_file[PATH_MAX];

    /* Socket related data */
    char socket_path[108]; /* size of sockaddr_un.sun_path array */
    uint8_t domain;
    uint8_t protocol;
    uint16_t port;
    uint8_t max_connections;
    char socket_permissions[5];

    /* Security Parameters related to authentication */
    char authorised_peer_username[32];
    uid_t authorised_peer_uid;
    gid_t authorised_peer_gid;
    pid_t authorised_peer_pid;
    char authorised_peer_process_name[NAME_MAX];
    char authorised_peer_cli_args[PATH_MAX];

} ipc_options;

typedef struct _secure_socket{

    int socket_fd; /* The sockets file descriptor */

    //struct sockaddr in_address; /* A internet address, for client e.g. */
    int optval; /* the optval argument for bind function */

    /* Data relative to domain and, therefore, sockaddr type */
    union address{
        struct sockaddr_un un;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } address;
    struct sockaddr *bind_address; /* pre-casted pointer to choosen address type */
    socklen_t addrlen; /* size of choosen address type */

    /* For logging */
    //mqd_t mq;
    //logging log;
} secure_socket;

typedef struct _thread_context{
    secure_socket *socket;
    logging *log;
} thread_context;

typedef struct _server_context{

    /* Pthread relative structures */
    pthread_attr_t attr;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    /*pthread_mutexattr_t mattr;
    pthread_condattr_t cattr;*/

    /* Socket related data */
    secure_socket *socket;

    /* For logging */

    logging log;

    /*mqd_t mq;
    int fd;
    struct aiocb *aio;
    bool quit_logging;*/ /* Syncing with logging thread */

    /* Instance options and parameters */
    ipc_options *options;
} server_context;

#endif /*secure_socket_TSM_TYPES_H*/
