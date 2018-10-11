/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <stdlib.h>
#include <threaded_server.h>
#include <pthread.h>
#include <log.h>
#include <context.h>
#include <ipc_socket.h>


int main(int argc, char** argv) {

    server_context *ctx;
    pthread_t logger;

    LOG_INIT;


    /* Build the main threads server context */
    ctx = make_server_context(argc, argv);

    LOG(LOG_INFO, "Starting Server. Context initialised.", ctx->mq, errno);

    /* Launch Logging Thread */
    if( pthread_create(&logger, NULL, &logging_thread, ctx) != 0 ){
        LOG_TTY(LOG_CRITICAL, "error creating logging thread : ", errno);
        free_server_context(ctx);
        exit(errno);
    }

    /* Server initialization */
    if( !ipc_bind_set_and_listen(INADDR_ANY, ctx) ){
        free_server_context(ctx);
        exit(errno);
    };

    /* Wait for clients */
    threaded_server(ctx, ctx->options.max_connections);

    /* Wait for logging thread to terminate */
    pthread_mutex_lock(&ctx->mutex);
    ctx->quit_logging = true;
    pthread_mutex_unlock(&ctx->mutex);

    /* Put a message to unblock logging thread on message queue */
    LOG(LOG_INFO, "Server awaiting logging thread to terminate ...", ctx->mq, errno);

    pthread_join(logger, NULL);

    /* Inform for shut down */
    log_write(ctx, "\n\nServer now shutting down.\n\n");

    /* Close server connection */
    free_server_context(ctx);

    return 0;
}
