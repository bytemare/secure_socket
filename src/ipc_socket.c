/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

/*#define _GNU_SOURCE  declare this before anything else */

#include <unistd.h>
#include <stdlib.h>
#include <log.h>
#include <string.h>
#include <pthread.h>
#include <ipc_socket.h>
#include <grp.h>
#include <sys/stat.h>
#include <threaded_server.h>
#include <vars.h>


/**
 * Allocates memory for an ipc_socket instance, calling an error when failing
 * @return allocated non-instanciated ipc_socket, NULL if failed
 */
ipc_socket* new_socket(server_context *ctx){

    ipc_socket *sock;

    LOG_INIT;

    sock = malloc(sizeof(ipc_socket));

    if( sock == NULL){
        LOG(LOG_ERROR, "malloc() failed for : ipc_socket. ", ctx->mq, errno);
        printf("malloc failed for ipc socket.\n");
        return NULL;
    }

    /*sock->addrlen = sizeof (sock->in_address);*/ /* TODO what's this ? */

    return sock;
}




/**
 * Given the domain, initialises the sockets address structure (un, in or in6)
 * @param server
 * @param domain
 * @param address
 * @param port
 * @param socket_address
 * @param ctx
 * @return -1 if failed, or length of address structure
 */
int set_bind_address(server_context *ctx, in_addr_t address){

    int len;
    ipc_socket *server;

    LOG_INIT;

    server = ctx->socket;

    LOG(LOG_INFO, "Setting up address to bind on ...", ctx->mq, errno);

    switch(ctx->options.domain){

        case AF_UNIX:{
            /*
        server->address.sa_family = (sa_family_t) domain;
        strcpy(server->address.sa_data, socket_address);
        unlink(server->address.sa_data);

        len = (socklen_t) (strlen(socket_address) + sizeof(domain));
        server->bind_address = &server->address;
        */

            /* Destroy ancient socket if interrupted abruptly*/
            unlink(ctx->options.socket_path);

            /* Make sure we do not overflow the path buffer */
            if( strlen(ctx->options.socket_path) >= sizeof(server->address.un.sun_path)){
                LOG(LOG_CRITICAL, "Socket path is too long : overflow avoided !", ctx->mq, errno);
                len = -1;
                break;
            }

            server->address.un.sun_family = AF_UNIX;

            bzero((char*)server->address.un.sun_path, sizeof(server->address.un.sun_path));
            strncpy(server->address.un.sun_path, ctx->options.socket_path, sizeof(server->address.un.sun_path) - 1);

            len = (socklen_t ) (strlen(server->address.un.sun_path) + sizeof(server->address.un.sun_family));

            server->bind_address = (struct sockaddr*)&server->address.un;
            break;
        }

        case AF_INET:{
            server->address.in.sin_family = (sa_family_t) ctx->options.domain;
            server->address.in.sin_port = htons(ctx->options.port);
            server->address.in.sin_addr.s_addr = address;

            len = sizeof(struct sockaddr_in);

            server->bind_address = (struct sockaddr*)&server->address.in;
            break;
        }

        default:
            LOG(LOG_CRITICAL, "domain type not recognised !", ctx->mq, errno);
            len = -1;

    }

    return len;
}



/**
 * Bind the application to an address via a socket contained in a ipc_socket structure
 * @param domain : address domain: AF_UNIX, AF_INET etc.
 * @param address
 * @param port
 * @return ipc_socket structure
 */
bool ipc_server_bind(in_addr_t address, server_context *ctx){

    int len;

    LOG_INIT;

    if (ctx->options.domain != AF_UNIX) {
        if (ctx->options.domain != AF_LOCAL && ctx->options.domain != AF_INET) {
            LOG_TTY(LOG_CRITICAL,
                    "This server does not support other socket types than Unix Sockets, yet. Please use AF_UNIX.",
                    errno);
            return false;
        }
    }

    ctx->socket = new_socket(ctx);
    if (ctx->socket == NULL) {
        LOG(LOG_ERROR, "server_bind() could not allocate socket : ", ctx->mq, errno);
        return false;
    }
    LOG(LOG_INFO, "Allocated memory for server ipc_socket : ", ctx->mq, errno);


    ctx->socket->mq = ctx->mq;


    /* Socket creation */
    ctx->socket->socket_fd = socket(ctx->options.domain, ctx->options.protocol, 0);
    if( ctx->socket->socket_fd < 0 ){
        LOG(LOG_ERROR, "socket() failed : ", ctx->mq, errno);
        ipc_socket_free(ctx->socket, &ctx->mq);
        return false;
    }

    LOG(LOG_INFO, "Socket created.", ctx->mq, errno);


    if ( (len = set_bind_address(ctx, address)) <= 0 ){
        LOG(LOG_INFO, "Could not properly set socket address type.", ctx->mq, errno);
        ipc_socket_free(ctx->socket, &ctx->mq);
        return false;
    }

    /* Set REUSEADDR socket option */
    if( setsockopt(ctx->socket->socket_fd, SOL_SOCKET, SO_PASSCRED || SO_REUSEADDR, &ctx->socket->optval, sizeof(int)) == -1){
        LOG(LOG_ERROR, "set socket option messed up for some reason : ", ctx->mq, errno);
    }

    /* Bind to address */
    if (bind(ctx->socket->socket_fd, ctx->socket->bind_address, (socklen_t) len) != 0) {
        LOG(LOG_ERROR, "Error binding socket : ", ctx->mq, errno);
        ipc_socket_free(ctx->socket, &ctx->mq);
        return false;
    }

    LOG(LOG_INFO, "Socket bound.", ctx->mq, errno);

    return true;
}

/**
 * Sets the socket in a listen state queuing n connections (number of accepted connections)
 * @param server
 * @return
 */
bool ipc_server_listen(server_context *ctx, const unsigned int nb_cnx){

    LOG_INIT;

    /* Listen for connections */
    if (listen(ctx->socket->socket_fd, nb_cnx) != 0) {
        LOG(LOG_ERROR, "error on listening : ", ctx->mq, errno);
        ipc_socket_free(ctx->socket, &ctx->mq);
        return false;
    }

    LOG(LOG_INFO, "Server now listening on socket.", ctx->mq, errno);

    return true;
}

/**
 * Decorator combining binding and listening. Return true/false depending on success.
 * @param port
 * @param address
 * @return
 */
bool ipc_bind_set_and_listen(in_addr_t address, server_context *ctx) {

    /* Create directory in which to place the socket file */

    /* Bind the server to a socket */
    if (!ipc_server_bind(address, ctx)) {
        return false;
    }

    /* Force permissions on socket file */
    set_socket_owner_and_permissions(ctx, 0, (mode_t) strtoul(ctx->options.socket_permissions, 0, 8));

    /* Listen for connections */
    if ( !ipc_server_listen(ctx, ctx->options.max_connections) ){
        return false;
    }

    return true;
}


/**
 * Sets the current thread in a blocking state if socket was flagged to, and waits for an incoming connection
 * @param server
 * @param client
 * @return true or false whether connection could be accepted
 */
ipc_socket* ipc_accept_connection(server_context *ctx){

    socklen_t len;
    ipc_socket *client;

    LOG_INIT;

    client = new_socket(ctx);
    if (client == NULL) {
        LOG(LOG_ERROR, "accept_connection() could not allocate socket : ", ctx->mq, errno);
        return NULL;
    }

    LOG(LOG_INFO, "Allocated memory for communication ipc_socket : ", ctx->mq, errno);


    switch(ctx->options.domain){

        case AF_UNIX:{
            client->address.un.sun_family = AF_UNIX;

            client->bind_address = (struct sockaddr*)&client->address.un;
            break;
        }

        default:
            LOG(LOG_CRITICAL, "Other domains than AF_UNIX are not handled yet !", ctx->mq, errno);
            ipc_socket_free(client, &ctx->mq);
            return NULL;
    }

    len = sizeof(client->bind_address);

    /*client->socket_fd = accept(server->socket_fd, (struct sockaddr *)&client->address, &client->addrlen);*/
    client->socket_fd = accept(ctx->socket->socket_fd, client->bind_address, &len);
    if (client->socket_fd < 0) {
        LOG(LOG_ERROR, "accept() connection failed : ", ctx->mq, errno);
        ipc_socket_free(client, &ctx->mq);
        return NULL;
    }

    LOG(LOG_INFO, "Connection accepted.", ctx->mq, errno);

    if( !ipc_validate_peer(ctx)){
        LOG(LOG_ERROR, "Peer has not been authenticated. Dropping connection.", ctx->mq, errno);
        ipc_socket_free(client, &ctx->mq);
        return NULL;
    }



    return client;
}

/**
 * Sends data buffer through given  socket
 * @param sock
 * @param data
 * @return true or false, whether send succeded
 */
bool ipc_send(ipc_socket *sock, int length, char *data, thread_context *ctx){

    /* unsigned const int length = (unsigned const int ) strlen(data); */
    int sent;
    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH] = {0};

    LOG_INIT;

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Attempting to send %d bytes.", length);
    LOG(LOG_INFO, log_buffer, ctx->mq, errno);

    if ( data == NULL || length <= 0 ){
        LOG(LOG_ERROR, "Either data is NULL or length is lower or equal to 0. Can't send that on socket.", ctx->mq, errno);
        return false;
    }


   while(length > 0){

	    if ((sent = (int) send(sock->socket_fd, data, (size_t) length, 0)) == -1 ){
            LOG(LOG_ERROR, "send() failed : ", ctx->mq, errno);
	        return false;
	    }
       snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Send %d bytes.", sent);
       LOG(LOG_INFO, log_buffer, ctx->mq, errno);

	data += sent;
	length -= sent;
   }

    LOG(LOG_INFO, "Finished sending.", ctx->mq, errno);

    return true;
}

/**
 * Blocks on socket and retrieves length bytes and copies them into data. Appends a \0 at length.
 * @param sock
 * @param data
 * @param length
 * @return number of bytes received
 */
int ipc_recv(ipc_socket *sock, char *data, unsigned int length, thread_context *ctx){

    int received;
    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH] = {0};

    LOG_INIT;

    LOG(LOG_INFO, "Attempting to receive data", ctx->mq, errno);

    received = (int) recv(sock->socket_fd, data, length, 0);

    if( received == -1 ){
        LOG(LOG_ERROR, "recv() on socket failed :", ctx->mq, errno);
        return -1;
    }

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Received %d bytes.", received);
    LOG(LOG_INFO, log_buffer, ctx->mq, errno);

    if (received <= (int) length) {
        data[received + 1] = '\0';
    }
    else{
        data[length - 1] = '\0';
    }

    return received;
}

/**
 * Returns the ucred structure corresponding to the other sides credentials
 * @param sock
 * @return struct ucred
 */
struct ucred* ipc_get_ucred(ipc_socket *sock){

    socklen_t len;
    struct ucred *creds = malloc(sizeof(struct ucred));
    if ( creds == NULL ){
        /*ERROR("ipc_get_ucred() : malloc failed for ucred.")*/
    }
    len = sizeof(struct ucred);

    if ( getsockopt(sock->socket_fd, SOL_SOCKET, SO_PEERCRED, creds, &len) < 0 ){
        /*ERROR("ipc_get_ucred() : could not retrieve ucred.");*/
        return NULL;
    }

    return creds;
}

/* TODO */
/**
 * Returns the pid of the correspondent process on the other side of the socket
 * @param sock
 * @return
 */
/*
pid_t ipc_get_peer_pid(ipc_socket *sock){
    struct ucred *creds = ipc_get_ucred(sock);
    pid_t pid = creds->pid;
    free(creds);
    return pid;
}
*/

/**
 * Closes a socket given its file descriptor
 * @param socketfd
 */
void ipc_close_socket(int socket_fd){
    close(socket_fd);
}

/**
 * Closes a socket and frees the memory allocated to the ipc_socket
 * @param com
 */
void ipc_socket_free(ipc_socket *sock, const mqd_t *mq){
    LOG_INIT;
    ipc_close_socket(sock->socket_fd);
    free(sock);
    LOG(LOG_INFO, "Closed socket and freed structure.", *mq, errno);
}



/**
 * Changes access and permissions on specified file.
 * If real_gid is given (i.e. different from 0) than grants group access to this group. If real_gid is 0, than the
 * group_name is used to retrieve the gid to grant access to.
 * perms is the mode_t describing the permissions to apply, like "0770" : use strtoul("0770", 0, 8)
 * @param file_path
 * @param real_gid
 * @param group_name
 * @param perms
 * @param ctx
 * @return
 */
void set_socket_owner_and_permissions(server_context *ctx, gid_t real_gid, mode_t perms){

    uid_t uid;
    struct group  *grp;

    LOG_INIT;

    LOG(LOG_INFO, "Applying access and permission changes on file.", ctx->mq, errno);

    /**
     * Set ownership of file
     */
    uid = getuid();
    if(!real_gid){

        /* Get group structure */
        errno = 0;
        grp = getgrnam(ctx->options.authorised_peer_username);

        /* Get group id */
        if (grp == NULL) {
            LOG(LOG_ERROR, "Could not retrieve group structure. Access to group will not be applied.", ctx->mq, errno);
        }
        else {
            real_gid = grp->gr_gid;
        }
    }

    if (real_gid && chown(ctx->options.socket_path, uid, real_gid) == -1) {
        LOG(LOG_ERROR, "chown() failed.", ctx->mq, errno);
    }

    /**
     * Change file permissions
     */
    if( chmod(ctx->options.socket_path, perms) < 0){
        LOG(LOG_ERROR, "chmod() failed.", ctx->mq, errno);
    }

}


/**
 * Given the peer pid, retrieves the corresponding binary name and returns whether it is accepted or not
 * @param ctx
 * @param peer_pid
 * @return bool
 */
bool ipc_validate_proc(server_context *ctx, pid_t peer_pid){

    int peer_name_length;
    char proc_file[NAME_MAX];
    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH] = {0};
    char *peer_binary;
    size_t authorised_length;
    size_t peer_binary_length;
    int result;

    LOG_INIT;

    snprintf(proc_file, NAME_MAX, IPC_PEER_BINARY_NAME_FILE_FORMAT, (int)peer_pid, IPC_PEER_BINARY_NAME_FILE);

    peer_binary = read_data_from_source(proc_file, &peer_name_length, &ctx->mq);
    if( peer_binary == NULL ){
        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Could not read process file '%s'. Process not authenticated.", proc_file);
        return false;
    }

    authorised_length = strlen(ctx->options.authorised_peer_process_name);
    peer_binary_length = strlen(peer_binary);

    if (peer_binary_length != authorised_length + 1){
        free(peer_binary);
        LOG(LOG_ERROR, "Peer process name does not match the authorised one. Process not authenticated.", ctx->mq, errno);
        return false;
    }

    result = strncmp(ctx->options.authorised_peer_process_name, peer_binary, authorised_length);

    free(peer_binary);

    return result == 0;
}



/**
 * Given a set of validations to perform, returns true or false whether expectations are met
 * @param ctx
 * @param validate_pid
 * @param validate_uid
 * @param validate_gid
 * @param validate_binary
 * @return
 */
bool ipc_validate_peer(server_context *ctx){

    struct ucred *creds = ipc_get_ucred(ctx->socket);

    pid_t peer_pid = creds->pid;
    uid_t peer_uid = creds->uid;
    gid_t peer_gid = creds->gid;

    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH] = {0};

    LOG_INIT;


    if(ctx->options.authorised_peer_pid){
        if( ctx->options.authorised_peer_pid != peer_pid) {
            return false;
        }

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Peer authenticated by pid %d.", peer_pid);
        LOG(LOG_INFO, log_buffer, ctx->mq, errno);
    }

    if(ctx->options.authorised_peer_uid){
        if( ctx->options.authorised_peer_uid != peer_uid) {
            return false;
        }

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Peer authenticated by uid %d.", peer_uid);
        LOG(LOG_INFO, log_buffer, ctx->mq, errno);
    }

    if(ctx->options.authorised_peer_gid){
        if( ctx->options.authorised_peer_gid != peer_gid){
            return false;
        }

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Peer authenticated by gid %d.", peer_gid);
        LOG(LOG_INFO, log_buffer, ctx->mq, errno);
    }


    if(strcmp(ctx->options.authorised_peer_process_name, "") != 0){ // TODO : what's going on here ?
        if(!ipc_validate_proc(ctx, peer_pid)){
            return false;
        }

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Peer authenticated by process name '%s'.", ctx->options.authorised_peer_process_name);
        LOG(LOG_INFO, log_buffer, ctx->mq, errno);
    }

    return true;
}





