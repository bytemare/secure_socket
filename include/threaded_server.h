/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef C_SERVER_THREADED_SERVER_H
#define C_SERVER_THREADED_SERVER_H

#include <log.h>
#include <secure_socket_types.h>

void threaded_server(server_context *ctx, unsigned int nb_cnx);

#endif /*C_SERVER_THREADED_SERVER_H*/
