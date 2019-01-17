/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <log.h>
#include <context.h>
#include <threaded_server.h>
#include <sys/stat.h>
#include <ipc_socket.h>

/* BSD */
#include <sys/fcntl.h>
#include <bsd/libutil.h>

/**
 * Set to be created pthreads attributes
 * @param ctx
 */
void set_thread_attributes(server_context *ctx){

    LOG_INIT;

    /* Initialise structure */
    if( pthread_attr_init(&ctx->attr) != 0 ) {
        LOG(LOG_ERROR, "Error in thread attribute initialisation : ", errno, 1, &ctx->log);
    }

    /* Makes the threads KERNEL THREADS, thus allowing multi-processor execution */
    if( pthread_attr_setscope(&ctx->attr, PTHREAD_SCOPE_SYSTEM) != 0) {
        LOG(LOG_ERROR, "Error in thread setscope : ", errno, 1, &ctx->log);
    }

    /* Launches threads as detached, since there's no need to sync whith them after they ended */
    if( pthread_attr_setdetachstate(&ctx->attr, PTHREAD_CREATE_DETACHED) != 0 ){
        LOG(LOG_ERROR, "Error in thread setdetachstate : ", errno, 1, &ctx->log);
    }

    LOG(LOG_TRACE, "Thread attributes set.", 0, 0, &ctx->log);
}

/**
 * Given a path to filename, reads the file and returns an appropriate buffer containing its content and appropriately
 * sets the size pointer to the number of bytes read.
 * @param filename
 * @param length
 * @return
 */
char *read_data_from_source (const char *filename, int *size, logging *log){

    char *destination;
    int file;
    size_t length;
    struct stat file_info;

    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH];

    LOG_INIT;


    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Attempting to read data from file '%s' ", filename);
    LOG(LOG_TRACE, log_buffer, 0, -2, log);

    /*
     * Use of a BSD function here with a lock to prevent a race condition, since the function is used to open a PID file, among others
     */
    file = flopen(filename, O_RDONLY);
    if(file == -1){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Unable to open file '%s', open() failed. ", filename);
        LOG(LOG_ALERT, log_buffer, errno, 3, log);
        return NULL;
    }

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Successfully opened file for reading.");
    LOG(LOG_TRACE, log_buffer, 0, 9, log);

    fstat(file, &file_info);

    if (!S_ISREG(file_info.st_mode)) {
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Error : '%s' is not a regular file !", filename);
        LOG(LOG_ALERT, log_buffer, errno, 4, log);
        close(file);
        return NULL;
    }

    length = (size_t) file_info.st_size;

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "File '%s' is '%d' bytes long.", filename, (int)length);
    LOG(LOG_TRACE, log_buffer, errno, 0, log);


    destination = malloc(length);
    if( !destination ){
        LOG(LOG_ALERT, "malloc for file reading failed : ", errno, 2, log);
        return NULL;
    }

    length = (size_t) read(file, destination, length);

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Read '%d' bytes from '%s'", (int)length, filename);
    LOG(LOG_TRACE, log_buffer, 0, 3, log);
    close(file);

    *size = (int)length;
    return destination;
}


/**
 * Thread handler : executes associated action for client communication
 * @param args
 * @return
 */
static void* handle_client(void *args){

    thread_context *ctx;

    LOG_INIT;

    ctx = (thread_context*)args;

    LOG(LOG_TRACE, "Thread launched. Calling handler.", 0, 0, ctx->log);

    /*handle_client_connection(client);*/
    //handler(ctx);

    LOG(LOG_TRACE, "Connexion closed. Thread now exiting.", 0, 0, ctx->log);

    pthread_exit((void*)0);
}


/**
 * Server function : Daemon mode awaiting connections and executing threads to handle them
 * Accepts up to 10 errors before leaving daemon mode
 * @param server
 * @param nb_cnx
 */
void threaded_server(server_context *ctx, const unsigned int nb_cnx){

    /* Variables for timestamping */
    /*time_t t;
    struct tm timer;*/

    /* List of threads system id's */
    unsigned int count; /* Total accumulated amount of accepted connections */
    unsigned int offset; /* Index between 0 and nb_cnx */
    /*unsigned int nb_threads = 0;*/ /* Used later to determine number of effectively created threads */
    unsigned int nb_authorised_errors; /* Number of errors before exiting daemon mode */

    thread_context **client_ctx; /* Contexts with logging queue and ipc_sockets to deal with clients */
    secure_socket *new_client;

    /* Initialise variables */
    pthread_t tid;

    LOG_INIT;

    count = 0;
    nb_authorised_errors = 50;

    client_ctx = malloc(nb_cnx * sizeof(thread_context*));
    if( client_ctx == NULL){
        LOG(LOG_FATAL, "malloc failed for client/thread_contexts ", errno, 2, &ctx->log);
        return;
    }

    /*t = time(NULL);
    timer = *localtime(&t);

    printf("%04d-%d-%d - %02d:%02d:%02d : Server now running and awaiting connections.\n\tpid : %d\n\tlog file : %s\n\tsocket : %s\n\n",
           timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min, timer.tm_sec,
           getpid(), ctx->options->log_file, ctx->options->socket_path);*/
    LOG(LOG_INFO, "Server now ready and awaiting incoming connections.", 0, 0, &ctx->log);

    /* Enter Daemon mode */
    while(nb_authorised_errors) {

        /* get_next_available_offset() */

        offset = count++%(nb_cnx);

        client_ctx[offset] = make_thread_context(NULL, ctx);

        new_client = ipc_accept_connection(ctx);

        if( new_client == NULL ){
            LOG(LOG_ALERT, "Connection denied.", errno, 3, &ctx->log);
            count--;
            nb_authorised_errors--;
            free_thread_context(client_ctx[offset]);
            continue;
        }

        client_ctx[offset]->socket = new_client;

        /* (void*)handle_client */
        if( pthread_create(&tid, &ctx->attr, &handle_client, client_ctx[offset]) != 0 ){
            LOG(LOG_ALERT, "error creating thread. Connection closed.", errno, 1, &ctx->log);
            client_ctx[offset] = free_thread_context(client_ctx[offset]);
            nb_authorised_errors--;
            continue;
        }

    }

    LOG(LOG_INFO, "Thread Server is quitting daemon mode. Now cleaning up.", 0, 0, &ctx->log);

    if( pthread_attr_destroy(&ctx->attr) != 0 ){
        LOG(LOG_ERROR, "Thread Server could not destroy thread attributes.", errno, 1, &ctx->log);
    }

    free(client_ctx);
}
