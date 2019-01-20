/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef secure_socket_CONTEXT_H
#define secure_socket_CONTEXT_H

#include <mqueue.h>
#include <unistd.h>
#include <secure_socket_types.h>

ipc_options* initialise_options();

bool parse_options(ipc_options *options, int argc, char **argv);

thread_context* make_thread_context(secure_socket *socket, server_context *ctx);

server_context* make_server_context(ipc_options *params, logging *log);

thread_context* free_thread_context(thread_context *ctx);

server_context* free_server_context(server_context *ctx);



#endif /*secure_socket_CONTEXT_H*/
