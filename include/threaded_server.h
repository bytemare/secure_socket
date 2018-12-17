/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef C_SERVER_THREADED_SERVER_H
#define C_SERVER_THREADED_SERVER_H

#include <mqueue.h>
#include <aio.h>
#include <broker_types.h>

char* read_data_from_source (const char *filename, int *size, logging *log);

void* logging_thread(void *args);

//void set_thread_attributes(server_context *ctx);

void threaded_server(server_context *ctx, unsigned int nb_cnx);

#endif /*C_SERVER_THREADED_SERVER_H*/
