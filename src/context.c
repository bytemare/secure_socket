/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <mqueue.h>
#include <context.h>
#include <log.h>
#include <aio.h>
#include <threaded_server.h>
#include <ipc_socket.h>
#include <vars.h>
#include <ctype.h>
#include <pwd.h>
#include <tools.h>


/**
 * Builds a context containing a socket and the logging message queue
 * @param socket
 * @param s_ctx
 * @return
 */
thread_context* make_thread_context(ipc_socket *socket, server_context *s_ctx){

    thread_context *ctx;

    LOG_INIT;

    ctx = malloc(sizeof(thread_context));

    if(!ctx){
        LOG_STDOUT(LOG_FATAL, "Error in malloc for context", errno, 3);
        return NULL;
    }

    ctx->socket = socket;
    ctx->log = &s_ctx->log;

    return ctx;
}


/**
 * Initialises the programs options with data from vars.h
 * @param options
 */
ipc_options* initialise_options(){

    LOG_INIT;

    size_t n;
    uint16_t mq_name_max_size;
    uint16_t log_name_max_size;
    uint8_t socket_name_max_size;
    char rand_buffer[IPC_RAND_LENGTH + 1];

    /* Allocate memory */
    ipc_options *options = malloc(sizeof(ipc_options));
    if ( !options ){
        LOG_STDOUT(LOG_FATAL, "malloc failed for ipc_options", errno, 3);
        perror("Error in malloc for ipc_options : ");
        return false;
    }

    /* Set message queue name */
    mq_name_max_size = sizeof(options->mq_name);
    memset(options->mq_name, '\0', mq_name_max_size);
    strlcpy(options->mq_name, IPC_MQ_NAME, (size_t) (mq_name_max_size - 1));
    secure_random_string(rand_buffer, IPC_RAND_LENGTH + 1);
    strlcat(options->mq_name, rand_buffer, IPC_RAND_LENGTH);

    /* Set log file */
    log_name_max_size = sizeof(options->log_file);
    memset(options->log_file, '\0', log_name_max_size);
    strncpy(options->log_file, IPC_LOG_FILE, (size_t) (log_name_max_size - 1));
    secure_random_string(rand_buffer, IPC_RAND_LENGTH + 1);
    strlcat(options->log_file, rand_buffer, IPC_RAND_LENGTH);

    /* Set socket data */
    socket_name_max_size = sizeof(options->socket_path);
    memset(options->socket_path, '\0', socket_name_max_size);
    strncpy(options->socket_path, IPC_SOCKET_PATH_BASE, (size_t) (socket_name_max_size - 1));
    secure_random_string(rand_buffer, IPC_RAND_LENGTH + 1);
    strlcat(options->log_file, rand_buffer, IPC_RAND_LENGTH);

    options->domain = IPC_DOMAIN;
    options->protocol = IPC_PROTOCOL;
    options->port = IPC_PORT;
    options->max_connections = IPC_NB_CNX;
    strcpy(options->socket_permissions, IPC_SOCKET_PERMS);

    /* Socket oriented security */
    strcpy(options->authorised_peer_username, IPC_AUTHORIZED_PEER_USERNAME);
    options->authorised_peer_uid = IPC_AUTHORIZED_PEER_PID;
    options->authorised_peer_gid = IPC_AUTHORIZED_PEER_UID;
    options->authorised_peer_pid = IPC_AUTHORIZED_PEER_GID;
    strcpy(options->authorised_peer_process_name, "");
    strcpy(options->authorised_peer_cli_args, "");

    return 0;
}


/**
 * Parse command line arguments to set parameters already initialised
 * @param ctx
 * @param argc
 * @param argv
 * @return
 */
bool parse_options(ipc_options *options, int argc, char **argv){

    int i;
    char *p, *q;
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH];

    LOG_INIT;

    for( i = 1; i < argc; i++ ) {
        p = argv[i];

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Parsing argument : %s", p);
        LOG_STDOUT(LOG_TRACE, log_buffer, -1, 3)

        if ((q = strchr(p, '=')) == NULL) {
            LOG_STDOUT(LOG_FATAL, "Invalid argument entry format. USAGE : [option]=[value].", -1, 1);
            return false;
        }
        *q++ = '\0';

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Argument value : %s", q);
        LOG_STDOUT(LOG_TRACE, log_buffer, -1, 3)

        if (strcmp(p, "mq_name") == 0) {
            uint16_t mq_name_max_size = sizeof(options->mq_name);
            if( q[0] != '/' && strlen(q) >= mq_name_max_size ){
                snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Invalid name for message queue. First character must be '/' and must be shorter than %d characters.", mq_name_max_size);
                LOG_STDOUT(LOG_FATAL, log_buffer, -1, 2);
                return false;
            }

            memset(options->mq_name, '\0', mq_name_max_size);
            strncpy(options->mq_name, q, (size_t) (mq_name_max_size - 1));
            continue;
        }

        if (strcmp(p, "socket_path") == 0) {
            uint8_t socket_name_max_size = sizeof(options->socket_path);
            if( strlen(q) >= socket_name_max_size ){
                snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Invalid name for socket path. Must be shorter than %d characters.", socket_name_max_size);
                LOG_STDOUT(LOG_FATAL, log_buffer, -1, 2);
                return false;
            }

            memset(options->socket_path, '\0', socket_name_max_size);
            strncpy(options->socket_path, q, (size_t) (socket_name_max_size - 1));

            continue;
        }

        if (strcmp(p, "log_file") == 0) {
            uint16_t log_name_max_size = sizeof(options->log_file);
            if( strlen(q) >= log_name_max_size ){
                snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Invalid name for log file. Must be shorter than %d characters.", log_name_max_size);
                LOG_STDOUT(LOG_FATAL, log_buffer, -1, 2);
                return false;
            }

            memset(options->log_file, '\0', log_name_max_size);
            strncpy(options->log_file, q, (size_t) (log_name_max_size - 1));

            continue;
        }

        if (strcmp(p, "domain") == 0) {
            if ( strcmp(q, "AF_UNIX") == 0 || strcmp(q, "AF_LOCAL") == 0 ){
                options->domain = AF_UNIX;
                continue;
            }
            else if ( strcmp(q, "AF_INET") == 0 ){
                options->domain = AF_INET;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for domain type. Supported values are AF_UNIX/AF_LOCAL or AF_INET.", errno, 9);
            return false;
        }

        if (strcmp(p, "protocol") == 0) {
            if( strcmp(q, "SOCK_STREAM") == 0 ){
                options->protocol = SOCK_STREAM;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for protocol type. Only SOCKET_STREAM is supported for now.", errno, 5);
            return false;
        }

        if (strcmp(p, "port") == 0) {
            int port = (int) strtol(q, NULL, 10);
            if( port > 1 && port < 65635 ){
                options->port = (uint16_t) port;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for port. Must be between 1 and 65635.", errno, 5);
            return false;
        }

        if (strcmp(p, "max_connections") == 0) {
            int mx_cnx = (int) strtol(q, NULL, 10);
            if( mx_cnx > 0 ) {
                options->max_connections = (uint8_t) mx_cnx;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for max_connections. Must be a positive number.", errno, 5);
            return false;
        }


        if (strcmp(p, "socket_permissions") == 0) {
            if( strlen(q) == sizeof(options->socket_permissions) - 1 ){
                int index;
                bool valid = true;
                for (index = 0 ; index < (int) sizeof(options->socket_permissions) - 1; index++){
                    if( !isdigit(q[index]) ){
                        valid = false;
                    }
                    else{

                    }
                }
                if(valid){
                    memset(options->socket_permissions, '\0', sizeof(options->socket_permissions));
                    strncpy(options->socket_permissions, q, sizeof(options->socket_permissions) - 1);
                    continue;
                }
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for socket_permissions. Use '0660'.", errno, 18);
            return false;
        }


        if (strcmp(p, "authorised_peer_username") == 0) {
            if( strlen(q) < 31 ){
                memset(options->authorised_peer_username, '\0', sizeof(options->authorised_peer_username));
                strncpy(options->authorised_peer_username, q, sizeof(options->authorised_peer_username) - 1);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid username : too long.", errno, 6);
            return false;
        }

        if (strcmp(p, "authorised_peer_uid") == 0) {
            int index;
            bool valid = true;
            for (index = 0 ; index < (int) strlen(q); index++){
                if( !isdigit(q[index]) ){
                    valid = false;
                }
            }
            if(valid){
                options->authorised_peer_uid = (unsigned int) strtol(q, NULL, 10);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid uid.", errno, 5);
            return false;

        }

        if (strcmp(p, "authorised_peer_gid") == 0) {
            int index;
            bool valid = true;
            for (index = 0 ; index < (int) strlen(q); index++){
                if( !isdigit(q[index]) ){
                    valid = false;
                }
            }
            if(valid){
                options->authorised_peer_gid = (unsigned int) strtol(q, NULL, 10);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid gid.", errno, 5);
            return false;
        }

        if (strcmp(p, "authorised_peer_pid") == 0) {
            int index;
            bool valid = true;
            for (index = 0 ; index < (int) strlen(q); index++){
                if( !isdigit(q[index]) ){
                    valid = false;
                }
            }
            if(valid){
                options->authorised_peer_pid = (unsigned int) strtol(q, NULL, 10);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid pid.", errno, 5);
            return false;
        }

        if (strcmp(p, "authorised_peer_process_name") == 0) {
            if( strlen(q) < sizeof(options->authorised_peer_process_name) ){
                memset(options->authorised_peer_process_name, '\0', sizeof(options->authorised_peer_process_name));
                strncpy(options->authorised_peer_process_name, q, sizeof(options->authorised_peer_process_name) - 1);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid process name : too long.", errno, 6);
            return false;
        }

        if (strcmp(p, "authorised_peer_cli_args") == 0) {
            if( strlen(q) < sizeof(options->authorised_peer_cli_args) ){
                memset(options->authorised_peer_cli_args, '\0', sizeof(options->authorised_peer_cli_args));
                strncpy(options->authorised_peer_cli_args, q, sizeof(options->authorised_peer_cli_args) - 1);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid peer command line arguments : too long.", errno, 6);
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Invalid argument : %s", p);
        LOG_STDOUT(LOG_FATAL, log_buffer, -1, 1);
        return false;
    }

    LOG_STDOUT(LOG_INFO, "Arguments parsed and validated.", errno, 0);

    return true;
}


server_context* make_server_context(ipc_options *params){

    /*
    time_t t;
    struct tm timer;
    */
    server_context *ctx;

    LOG_INIT;

    ctx = malloc(sizeof(server_context));

    if( !ctx ){
        LOG_STDOUT(LOG_FATAL, "malloc failed for server context", errno, 3);
        perror("Error in malloc for server context : ");
        exit(errno);
    }

    if ( log_initialise_logging_s(&ctx->log, params->verbosity, params->mq_name, params->log_file) ) {
        free_server_context(ctx);
        return NULL;
    }

    ctx->options = params;

    LOG_FILE(LOG_TRACE, "Server context initialised", 0, 0, &ctx->log);

    ctx->log.aio = malloc(sizeof(struct aiocb));
    if(!ctx->log.aio){
        if( write(ctx->log.fd, "malloc failed allocation space for the aiocb structure.", (int)strlen("malloc failed allocation space for the aiocb structure.")) < 0){
            LOG_STDOUT(LOG_CRITICAL, "Malloc fails for aiocb structure and write to log file failed.", errno, 3);
        }
        free_server_context(ctx);
        exit(1);
    }

    ctx->log.aio->aio_fildes = ctx->log.fd;
    ctx->log.aio->aio_buf = NULL;
    ctx->log.aio->aio_nbytes = 0;

    mq_unlink(ctx->options->mq_name);

    // Opening Message Queue
    if( (ctx->log.mq = mq_open(ctx->options->mq_name, O_RDWR | O_CREAT | O_EXCL, 0600, NULL)) == (mqd_t)-1){
        LOG_STDOUT(LOG_CRITICAL, "Error in opening a messaging queue.", errno, 1);
        free_server_context(ctx);
        exit(1);
    }

    set_thread_attributes(ctx);

    ctx->log.quit_logging = false;

    return ctx;

}


/**
 * Frees the memory allocated to a context and its socket if it is still referenced
 * @param ctx
 */
void free_thread_context(thread_context *ctx){
    if(ctx->socket){
        ipc_socket_free(ctx->socket, ctx->log);
    }

    free(ctx);
}

void free_server_context(server_context *ctx){
    if(ctx->socket){
        ipc_socket_free(ctx->socket, &ctx->log);
    }

    log_free_logging(&ctx->log);

    free(ctx->options);

    free(ctx);
}
