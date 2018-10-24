/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef IPC_SOCKET_H
#define IPC_SOCKET_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <mqueue.h>

#include <broker_types.h>


bool ipc_send(ipc_socket *sock, int length, char *data, thread_context *ctx);

int ipc_recv(ipc_socket *sock, char *data, unsigned int length, thread_context *ctx);

bool ipc_bind_set_and_listen(in_addr_t address, server_context *ctx);

ipc_socket* ipc_accept_connection(server_context *ctx);

struct ucred* ipc_get_ucred(ipc_socket *sock);


void ipc_close_socket(int socket_fd);

void ipc_socket_free(ipc_socket *com, logging *log);

void set_socket_owner_and_permissions(server_context *ctx, gid_t real_gid, mode_t perms);

bool ipc_validate_peer(server_context *ctx);

#endif /* IPC_SOCKET_H */
