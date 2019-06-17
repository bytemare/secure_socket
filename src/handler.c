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

    //read_size = (int) recv(ctx->socket->socket_fd , client_message , 2000 , 0);
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

    printf("Server received '%s'\n", client_message);
    printf("Server sending '%s'\n", client_message);

    /*if(write(ctx->socket->socket_fd , client_message , strlen(client_message)) == -1){
        perror("SERVER : write returned with error\n");
        return;
    }*/

    ipc_send(ctx->socket, read_size, client_message, ctx);

    return;

}