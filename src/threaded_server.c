/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>


/* secure_socket */
#include <context.h>
#include <threaded_server.h>
#include <ipc_socket.h>

/* BSD */
#include <sys/fcntl.h>
#include <bsd/libutil.h>
#include <tools.h>
#include <handler.h>


/**
 * Thread handler : executes associated action for client communication
 * @param args
 * @return
 */
static void* handle_client(void *args){

    thread_context *ctx;

    LOG_INIT

    ctx = (thread_context*)args;

    LOG(LOG_TRACE, "Thread launched. Calling handler.", 0, 0, ctx->log)

    /**
     * Launch your client handler here, e.g. :
     * - handle_client_connection(client)
     * - handler(ctx)
     */
    handler(ctx);

    LOG(LOG_TRACE, "Connexion closed. Thread now exiting.", 0, 0, ctx->log)

    free_thread_context(ctx);

    pthread_exit((void*)0);
}


/**
 * Server function : Daemon mode awaiting connections and executing threads to handle them
 * Accepts up to 10 errors before leaving daemon mode
 * @param server
 * @param nb_cnx
 */
void threaded_server(server_context *ctx, const unsigned int nb_cnx){

    /* List of threads system id's */
    unsigned int count; /* Total accumulated amount of accepted connections */
    unsigned int offset; /* Index between 0 and nb_cnx */
    /*
     * TODO
     * Track number of effectively created threads with unsigned int nb_threads = 0
     */
    unsigned int nb_authorised_errors; /* Number of errors before exiting daemon mode */
    int pthread_ret = 0;

    thread_context **client_ctx; /* Contexts with logging queue and ipc_sockets to deal with clients */
    secure_socket *new_client;

    /* Initialise variables */
    pthread_t tid = 0;

    LOG_INIT

    count = 0;
    nb_authorised_errors = 1; /* TODO : study how this situation can be handled in a more appropriate way */

    client_ctx = malloc(nb_cnx * sizeof(thread_context*));
    if( client_ctx == NULL){
        //TODO give size of failed malloc
        LOG(LOG_FATAL, "malloc failed for client/thread_contexts ", errno, 2, ctx->log)
        return;
    }

    LOG(LOG_INFO, "Server now ready and awaiting incoming connections.", 0, 0, ctx->log)

    /* Enter Daemon mode */
    while(nb_authorised_errors--) {

        /* get_next_available_offset() */

        offset = count++%(nb_cnx);

        client_ctx[offset] = make_thread_context(NULL, ctx);

        new_client = ipc_accept_connection(ctx);

        if( new_client == NULL ){
            //TODO give more context on why connection was denied
            LOG(LOG_ALERT, "Connection denied.", errno, 3, ctx->log)
            count--;
            nb_authorised_errors--;
            free_thread_context(client_ctx[offset]);
            continue;
        }

        client_ctx[offset]->socket = new_client;

        /* (void*)handle_client */
        if( ( pthread_ret = pthread_create(&tid, &ctx->attr, &handle_client, client_ctx[offset])) != 0 ){
            //TODO give more context on why thread could not be created
            LOG(LOG_ALERT, "error creating thread. Connection closed.", pthread_ret, 1, ctx->log)
            client_ctx[offset] = free_thread_context(client_ctx[offset]);
            nb_authorised_errors--;
            continue;
        }

    }

    // TODO : this here is a workaround to make the demo work
    int join_ret;
    void *join_res;

    if ( (join_ret = pthread_join(tid, &join_res)) == -1 ){
        LOG(LOG_ERROR, "Could not join client thread.", join_ret, 1, ctx->log)
    } else {
        LOG_BUILD("Joined client thread, which returned %s.", (char *) join_res)
        LOG(LOG_INFO, NULL, 0, 4, ctx->log)
    }

    LOG(LOG_INFO, "Thread Server is quitting daemon mode. Now cleaning up.", 0, 0, ctx->log)

    if( pthread_attr_destroy(&ctx->attr) != 0 ){
        LOG(LOG_ERROR, "Thread Server could not destroy thread attributes.", errno, 1, ctx->log)
    }

    free(client_ctx);
}
