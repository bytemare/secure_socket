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
thread_context* make_thread_context(secure_socket *socket, server_context *s_ctx){

    thread_context *ctx;

    LOG_INIT

    ctx = malloc(sizeof(thread_context));

    if(!ctx){
        LOG_STDOUT(LOG_FATAL, "Error in malloc for context", errno, 3, ctx->log)
        return NULL;
    }

    ctx->socket = socket;
    ctx->log = s_ctx->log;

    return ctx;
}


bool is_valid_integer(char *number, size_t authorised_length){
    uint32_t index;
    bool valid = true;
    size_t len = strnlen(number, authorised_length + 1);

    if ( len == authorised_length + 1){
        return false;
    }

    for (index = 0 ; index < len; index++){
        if( !isdigit(number[index]) ){
            valid = false;
        }
    }
    return valid;
}


/**
 * Initialises the programs options with data from vars.h
 * @param options
 */
ipc_parameters* initialise_parameters(){

    char rand_buffer[IPC_RAND_LENGTH + 1];

    LOG_INIT

    /* Allocate memory */
    ipc_parameters *parameters = malloc(sizeof(ipc_parameters));
    if ( !parameters ){
        LOG_STDOUT(LOG_FATAL, "malloc failed for ipc_parameters", errno, 3, NULL)
        return NULL;
    }

    /* Set message queue name */
    memset(parameters->mq_name, 0, sizeof(parameters->mq_name));
    strlcpy(parameters->mq_name, IPC_MQ_NAME, sizeof(parameters->mq_name) - sizeof(rand_buffer));
    secure_random_string(rand_buffer, sizeof(rand_buffer));
    strlcat(parameters->mq_name, rand_buffer, sizeof(parameters->mq_name) - sizeof(IPC_MQ_NAME));

    /* Set log file */
    memset(parameters->log_file, 0, sizeof(parameters->log_file));
    strlcpy(parameters->log_file, IPC_LOG_FILE, sizeof(parameters->log_file) - sizeof(rand_buffer));
    secure_random_string(rand_buffer, sizeof(rand_buffer));
    strlcat(parameters->log_file, rand_buffer, sizeof(parameters->log_file) - sizeof(IPC_LOG_FILE));

    /* Set socket data */
    memset(parameters->socket_path, 0, sizeof(parameters->socket_path));
    strlcpy(parameters->socket_path, IPC_SOCKET_PATH_BASE, sizeof(parameters->socket_path) - sizeof(rand_buffer));
    secure_random_string(rand_buffer, sizeof(rand_buffer));
    strlcat(parameters->socket_path, rand_buffer, sizeof(parameters->socket_path) - sizeof(IPC_SOCKET_PATH_BASE));

    parameters->domain = IPC_DOMAIN;
    parameters->protocol = IPC_PROTOCOL;
    parameters->port = IPC_PORT;
    parameters->max_connections = IPC_NB_CNX;
    strlcpy(parameters->socket_permissions, IPC_SOCKET_PERMS, sizeof(parameters->socket_permissions));

    /* Socket oriented security */
    strlcpy(parameters->authorised_peer_username, IPC_AUTHORIZED_PEER_USERNAME, sizeof(parameters->authorised_peer_username));
    parameters->authorised_peer_uid = IPC_AUTHORIZED_PEER_UID;
    parameters->authorised_peer_pid = IPC_AUTHORIZED_PEER_PID;
    parameters->authorised_peer_gid = IPC_AUTHORIZED_PEER_GID;

    memset(parameters->authorised_peer_process_name, 0, sizeof(parameters->authorised_peer_process_name));
    memset(parameters->authorised_peer_cli_args, 0, sizeof(parameters->authorised_peer_cli_args));

    return parameters;
}


/**
 * Parse command line arguments to set parameters already initialised
 * @param ctx
 * @param argc
 * @param argv
 * @return
 */
bool parse_options(ipc_parameters *options, int argc, char **argv){

    int i;


    LOG_INIT

    for( i = 1; i < argc; i++ ) {
        char *p;
        char *q;
        p = argv[i];

        if ((q = strchr(p, '=')) == NULL) {
            LOG_STDOUT(LOG_FATAL, "Invalid argument entry format. USAGE : [option]=[value].", 0, 1, NULL)
            return false;
        }
        *q++ = '\0';

        if (strcmp(p, "mq_name") == 0) {
            uint16_t mq_name_max_size = sizeof(options->mq_name);
            if( q[0] != '/' && strnlen(q, mq_name_max_size) == mq_name_max_size ){
                //TODO : check all conditions of mq_name, cf 'man mq_overview'
                LOG_BUILD("Invalid name for message queue. First character must be '/' and must be shorter than %d characters.", mq_name_max_size)
                LOG_STDOUT(LOG_FATAL, NULL, 0, 2, NULL)
                return false;
            }

            memset(options->mq_name, 0, mq_name_max_size);
            strlcpy(options->mq_name, q, sizeof(options->mq_name));
            continue;
        }

        if (strcmp(p, "socket_path") == 0) {
            uint8_t socket_name_max_size = sizeof(options->socket_path);
            if( strnlen(q, socket_name_max_size) == socket_name_max_size ){
                LOG_BUILD("Invalid name for socket path. Must be shorter than %d characters.", socket_name_max_size)
                LOG_STDOUT(LOG_FATAL, NULL, 0, 2, NULL)
                return false;
            }

            memset(options->socket_path, 0, socket_name_max_size);
            strlcpy(options->socket_path, q, sizeof(options->socket_path));

            continue;
        }

        if (strcmp(p, "log_file") == 0) {
            uint16_t log_name_max_size = sizeof(options->log_file);
            if( strnlen(q, log_name_max_size) == log_name_max_size ){
                LOG_BUILD("Invalid name for log file. Must be shorter than %d characters.", log_name_max_size)
                LOG_STDOUT(LOG_FATAL, NULL, 0, 2, NULL)
                return false;
            }

            memset(options->log_file, 0, log_name_max_size);
            strlcpy(options->log_file, q, sizeof(options->log_file));

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

            LOG_STDOUT(LOG_FATAL, "Invalid value for domain type. Supported values are AF_UNIX/AF_LOCAL or AF_INET.", errno, 9, NULL)
            return false;
        }

        if (strcmp(p, "protocol") == 0) {
            if( strcmp(q, "SOCK_STREAM") == 0 ){
                options->protocol = SOCK_STREAM;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for protocol type. Only SOCKET_STREAM is supported for now.", errno, 5, NULL)
            return false;
        }

        if (strcmp(p, "port") == 0) {
            int port = (int) strtol(q, NULL, 10);
            if( port > 1 && port < 65635 ){
                options->port = (uint16_t) port;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for port. Must be between 1 and 65635.", errno, 5, NULL)
            return false;
        }

        if (strcmp(p, "max_connections") == 0) {
            int mx_cnx = (int) strtol(q, NULL, 10);
            if( mx_cnx > 0 ) {
                options->max_connections = (uint8_t) mx_cnx;
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for max_connections. Must be a positive number.", errno, 5, NULL)
            return false;
        }


        if (strcmp(p, "socket_permissions") == 0) {
            uint8_t socket_permissions_length = sizeof(options->socket_permissions);

            if ( is_valid_integer(q, socket_permissions_length) ){
                //TODO make proper check on value if it corresponds to valid permissions
                memset(options->socket_permissions, 0, sizeof(options->socket_permissions));
                strlcpy(options->socket_permissions, q, sizeof(options->socket_permissions));
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid value for socket_permissions. Use '0660'.", errno, 18, NULL)
            return false;
        }


        if (strcmp(p, "authorised_peer_username") == 0) {
            if( strnlen(q, sizeof(options->authorised_peer_username)) < sizeof(options->authorised_peer_username) ){
                memset(options->authorised_peer_username, 0, sizeof(options->authorised_peer_username));
                strlcpy(options->authorised_peer_username, q, sizeof(options->authorised_peer_username));
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid username : too long.", errno, 6, NULL)
            return false;
        }

        if (strcmp(p, "authorised_peer_uid") == 0) {
            bool valid = true;
            size_t q_len = strnlen(q, MAXINT);
            if ( q_len == MAXINT ){
                valid = false;
            } else {
                uint32_t index;
                for (index = 0 ; index < q_len; index++){
                    if( !isdigit(q[index]) ){
                        valid = false;
                    }
                }
            }

            if(valid){
                options->authorised_peer_uid = (unsigned int) strtol(q, NULL, 10);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid uid.", errno, 5, NULL)
            return false;

        }

        if (strcmp(p, "authorised_peer_gid") == 0) {
            bool valid = true;
            size_t q_len = strnlen(q, MAXINT);
            if ( q_len == MAXINT ){
                valid = false;
            } else {
                uint32_t index;
                for (index = 0 ; index < q_len; index++){
                    if( !isdigit(q[index]) ){
                        valid = false;
                    }
                }
            }

            if(valid){
                options->authorised_peer_gid = (unsigned int) strtol(q, NULL, 10);
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid gid.", errno, 5, NULL)
            return false;
        }

        if (strcmp(p, "authorised_peer_pid") == 0) {
            if(is_valid_integer(q, IPC_MAX_PID_LENGTH)){
                long int apid= strtol(q, NULL, 10);
                if (apid >= 1 && apid <= (4194304 - 1) ){ /* Maximum value for a pid on 64-bit systems, 2^22*/
                    options->authorised_peer_pid = (pid_t) strtol(q, NULL, 10);
                    continue;
                }
            }

            LOG_STDOUT(LOG_FATAL, "Invalid pid value.", errno, 5, NULL)
            return false;
        }

        if (strcmp(p, "authorised_peer_process_name") == 0) {
            if( strnlen(q, sizeof(options->authorised_peer_process_name)) < sizeof(options->authorised_peer_process_name) ){
                strlcpy(options->authorised_peer_process_name, q, sizeof(options->authorised_peer_process_name));
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid process name : too long.", errno, 6, NULL)
            return false;
        }

        if (strcmp(p, "authorised_peer_cli_args") == 0) {
            if( strnlen(q, sizeof(options->authorised_peer_cli_args)) < sizeof(options->authorised_peer_cli_args) ){
                memset(options->authorised_peer_cli_args, 0, sizeof(options->authorised_peer_cli_args));
                strlcpy(options->authorised_peer_cli_args, q, sizeof(options->authorised_peer_cli_args));
                continue;
            }

            LOG_STDOUT(LOG_FATAL, "Invalid peer command line arguments : too long.", errno, 6, NULL)
            return false;
        }

        if (strcmp(p, "verbosity") == 0){
            if(is_valid_integer(q, 2)){
                long int verbosity = strtol(q, NULL, 10);
                if (verbosity >= LOG_OFF && verbosity <= LOG_UNKNWON) {
                    options->verbosity = (int8_t) verbosity;
                    continue;
                }
            }

            LOG_STDOUT(LOG_FATAL, "Invalid verbosity.", errno, 5, NULL)
            return false;
        }

        LOG_BUILD("Invalid argument : %s", p)
        LOG_STDOUT(LOG_FATAL, NULL, 0, 1, NULL)
        return false;
    }

    LOG_STDOUT(LOG_INFO, "Arguments parsed and validated.", errno, 0, NULL)

    return true;
}


server_context* make_server_context(ipc_parameters *params, logging *log){

    server_context *ctx;

    LOG_INIT

    ctx = malloc(sizeof(server_context));

    if( !ctx ){
        LOG_STDOUT(LOG_FATAL, "malloc failed for server context", errno, 3, ctx->log)
        return NULL;
    }

    /* Link Logging */
    ctx->log = log;

    /* Link parameters */
    ctx->parameters = params;

    /* secure_socket */
    ctx->socket = secure_socket_allocate(ctx);
    if (ctx->socket == NULL) {
        LOG(LOG_FATAL, "Could not allocate memory for secure_socket : ", errno, 2, ctx->log)
        free(ctx);
        return false;
    }

    LOG(LOG_INFO, "Allocated memory for server secure_socket : ", errno, 0, ctx->log)

    /* Socket creation */
    if( secure_socket_create_socket(ctx) == false ){
        secure_socket_free(ctx->socket, ctx->log);
        free(ctx);
        return false;
    }

    LOG(LOG_INFO, "Socket created.", errno, 0, ctx->log)

    set_thread_attributes(&ctx->attr, ctx->log);

    LOG_FILE(LOG_TRACE, "Server context initialised", 0, 0, ctx->log)

    return ctx;
}


/**
 * Frees the memory allocated to a context and its socket. This function returns à NULL pointer to be affected
 * to the pointer given in argument, to avoid heap-use-after-free bugs.
 * @param ctx
 */
thread_context* free_thread_context(thread_context *ctx){

    if(ctx){
        ctx->socket = secure_socket_free(ctx->socket, ctx->log);
        free(ctx);
    }

    return NULL;
}

/**
 * Frees the server context and all nested structures and files descriptors. This function returns à NULL pointer to be affected
 * to the pointer given in argument, to avoid heap-use-after-free bugs.
 * @param ctx
 */
server_context* free_server_context(server_context *ctx){

    if (ctx) {
        secure_socket_free_from_context(ctx);

        free(ctx->parameters);
        ctx->parameters= NULL;

        free(ctx);
    }

    return NULL;
}
