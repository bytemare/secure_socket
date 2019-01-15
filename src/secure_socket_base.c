/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2019 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "secure_socket_base.h"

/**
 * Fill a UNIX socket sockaddr_un struct.
 * @param un
 * @param socket_path
 * @param socklen
 * @return struct sockaddr *bind_address
 */
struct sockaddr *socket_bind_unix(struct sockaddr_un *un, const char* socket_path, socklen_t *socklen){

    /* Destroy ancient socket if interrupted abruptly*/
    unlink(socket_path);

    /* Make sure we do not overflow the path buffer */
    if( strlen(socket_path) >= sizeof(un->sun_path)){
        return NULL;
    }

    un->sun_family = AF_UNIX;

    //bzero((char*)server->address.un.sun_path, sizeof(server->address.un.sun_path));
    bzero(un->sun_path, sizeof(un->sun_path));
    strncpy(un->sun_path, socket_path, sizeof(un->sun_path) - 1);

    *socklen = (socklen_t) (strlen(un->sun_path) + sizeof(un->sun_family));

    return (struct sockaddr*)un;
}

/**
 * Fill an internet socket sockaddr_in struct.
 * @param in
 * @param domain
 * @param port
 * @param address
 * @param socklen
 * @return struct sockaddr *bind_address
 */
struct sockaddr *socket_bind_inet(struct sockaddr_in *in, uint8_t domain, uint16_t port, in_addr_t address, socklen_t *socklen){
    in->sin_family = (sa_family_t) domain;
    in->sin_port = htons(port);
    in->sin_addr.s_addr = address;

    *socklen = (socklen_t) sizeof(struct sockaddr_in);

    return (struct sockaddr*)in;
}