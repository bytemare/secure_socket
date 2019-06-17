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

    printf("waiting for client message\n");

    read_size = (int) recv(ctx->socket->socket_fd , client_message , 2000 , 0);

    if (read_size == -1){
        perror("error in recv :");
        return;
    }

    if (read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }

    printf("received '%s'\n", client_message);

    printf("sending ACK");

    if(write(ctx->socket->socket_fd , "secure_socket ACK" , strlen("secure_socket ACK") == -1)){
        perror("SERVER : write returned with error\n");
        return;
    }

    return;

}