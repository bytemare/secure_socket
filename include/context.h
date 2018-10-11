/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef secure_broker_broker_CONTEXT_H
#define secure_broker_broker_CONTEXT_H

#include <mqueue.h>
#include <unistd.h>
#include <broker_types.h>


thread_context* make_thread_context(ipc_socket *socket, server_context *ctx);

server_context* make_server_context(int argc, char **argv);

void free_thread_context(thread_context *ctx);

void free_server_context(server_context *ctx);



#endif /*secure_broker_broker_CONTEXT_H*/
