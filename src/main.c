/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifdef __linux__
#define WELCOME_STRING "Linux"
#else
#define WELCOME_STRING "Windows"
#endif

// hardware
#if __x86_64__ || __ppc64__
#define ARCH "64 bit"
#else
#define ARCH "not 64 bit"
#endif

#include <stdlib.h>
#include <threaded_server.h>
#include <log.h>
#include <context.h>
#include <ipc_socket.h>


int main(int argc, char** argv) {

    server_context *ctx;
    ipc_parameters *params;
    logging log;

    LOG_INIT

#if DEBUG
    printf("##### DEBUG MODE #####\n");
    printf("Executing on %s %s.\n", ARCH, WELCOME_STRING);
#endif

    /* Parse command line parameters and parameters */
    if( !( params = initialise_parameters()) ){
        return EXIT_FAILURE;
    }

    if( !parse_options(params, argc, argv) ){
        free(params);
        return EXIT_FAILURE;
    }

    /* Launch Logging Thread */
    if( !log_start(&log, params->verbosity, params->mq_name, params->log_file) ){
        LOG_STDOUT(LOG_FATAL, "Couldn't not start logging. Shutting down.", errno, 1, &log)
        free(params);
        return EXIT_FAILURE;
    }

    /* Build the main threads server context */
    if ( (ctx = make_server_context(params, &log) ) == NULL ){
        LOG_STDOUT(LOG_FATAL, "Could not create server context. Startup aborted.", errno, 1, &log)
        log_close(&log);
        return EXIT_FAILURE;
    }

    LOG_FILE(LOG_INFO, "Starting Server. Context initialised.", errno, 0, ctx->log)

    /* Server initialization */
    if( !ipc_bind_set_and_listen(INADDR_ANY, ctx) ){
        LOG_STDOUT(LOG_FATAL, "The server encountered an error. Shutting down.", errno, 1, &log)
        free_server_context(ctx);
        log_close(&log);
        return EXIT_FAILURE;
    }

    /* Wait for clients in a loop */
    threaded_server(ctx, params->max_connections);

    /* Inform for shut down */
    LOG_FILE(LOG_INFO, "Server now shutting down.", 0, 0, ctx->log)

    /* Close server connection */
    free_server_context(ctx);

    /* Stop Logging */
    log_close(&log);

    return EXIT_SUCCESS;
}
