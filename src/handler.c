/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

/* secure_socket */
#include <context.h>
#include <threaded_server.h>
#include <ipc_socket.h>
#include <unistd.h>

void handler(thread_context *ctx){

    int read_size;
    char client_message[2000];

    read_size = ipc_recv(ctx->socket, client_message, 2000, ctx);

    if (read_size == -1){
        perror("error in recv :");
        return;
    }

    if (read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }

    printf("\033[0;32mServer received '%s'\033[0m\n", client_message);
    printf("\033[0;32mServer sending '%s'\033[0m\n", client_message);

    ipc_send(ctx->socket, read_size, client_message, ctx);
}
