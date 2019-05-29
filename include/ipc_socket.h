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

#include <secure_socket_types.h>


#define IPC_MAX_PID_LENGTH 5
#define IPC_PEER_BINARY_NAME_FILE_ROOT "/proc/"
#define IPC_PEER_BINARY_NAME_FILE "comm"

secure_socket* secure_socket_allocate(server_context *ctx);

bool secure_socket_create_socket(server_context *ctx);

bool ipc_send(secure_socket *sock, int length, char *data, thread_context *ctx);

int ipc_recv(secure_socket *sock, char *data, unsigned int length, thread_context *ctx);

bool ipc_bind_set_and_listen(in_addr_t address, server_context *ctx);

secure_socket* ipc_accept_connection(server_context *ctx);

struct ucred* ipc_get_ucred(server_context *ctx);


void ipc_close_socket(secure_socket *sock);

secure_socket* secure_socket_free(secure_socket *sock, logging *log);

void secure_socket_free_from_context(server_context *ctx);

bool set_socket_owner_and_permissions(server_context *ctx, char *group_name, gid_t real_gid, mode_t perms);

bool ipc_validate_peer(server_context *ctx);

#endif /* IPC_SOCKET_H */
