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
    ipc_options params;

    LOG_INIT;


    #ifdef __linux__
    #define WELCOME_STRING "welcome to Linux!"
    #else
    #define WELCOME_STRING "welcome to Windows!"
    #endif

    // Example with hardware
    #if __x86_64__ || __ppc64__
        #define ARCH "Using 64bit"
    #else
    #define ARCH "not using 64bit"
    #endif

    printf("%s\n%s\n", WELCOME_STRING, ARCH);


    /* Parse command line options and parameters */
    initialise_options(&params);

    if( !parse_options(&params, argc, argv) ){
        return 1;
    }

    /* Build the main threads server context */
    ctx = make_server_context(&params);

    LOG_FILE(LOG_INFO, "Starting Server. Context initialised.", errno, 0, &ctx->log);

    /* Launch Logging Thread */
    if( pthread_create(&logger, NULL, &logging_thread, ctx) != 0 ){
        LOG_STDOUT(LOG_FATAL, "error creating logging thread : ", errno, 1);
        LOG_STDOUT(LOG_FATAL, "The server encountered an error. Shutting down.", errno, 2);
        free_server_context(ctx);
        return 1;
    }

    /* Server initialization */
    if( !ipc_bind_set_and_listen(INADDR_ANY, ctx) ){
        LOG_STDOUT(LOG_FATAL, "The server encountered an error. Shutting down.", errno, 1);
        free_server_context(ctx);
        return 1;
    };

    /* Wait for clients */
    threaded_server(ctx, params.max_connections);

    /* Wait for logging thread to terminate */
    pthread_mutex_lock(&ctx->mutex);
    ctx->log.quit_logging = true;
    pthread_mutex_unlock(&ctx->mutex);

    /* Put a message to unblock logging thread on message queue */
    LOG(LOG_INFO, "Server awaiting logging thread to terminate ...", errno, 0, &ctx->log);

    pthread_join(logger, NULL);

    /* Inform for shut down */
    LOG_FILE(LOG_INFO, "Server now shutting down.", 0, 0, &ctx->log);

    /* Close server connection */
    free_server_context(ctx);

    return 0;
}
