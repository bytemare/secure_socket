/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2019 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef SECURE_SOCKET_SECURE_SOCKET_BASE_H
#define SECURE_SOCKET_SECURE_SOCKET_BASE_H

struct sockaddr *socket_bind_unix(struct sockaddr_un *un, const char* socket_path, socklen_t *socklen);

struct sockaddr *socket_bind_inet(struct sockaddr_in *in, uint8_t domain, uint16_t port, in_addr_t address, socklen_t *socklen);

#endif //SECURE_SOCKET_SECURE_SOCKET_BASE_H
