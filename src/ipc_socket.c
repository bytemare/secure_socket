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

/* BSD */
#include <bsd/sys/types.h>
#include <bsd/unistd.h>


/**
 * Allocates memory for an ipc_socket instance, calling an error when failing
 * @return allocated non-instanciated ipc_socket, NULL if failed
 */
ipc_socket* new_socket(server_context *ctx){

    ipc_socket *sock;

    LOG_INIT;

    sock = malloc(sizeof(ipc_socket));

    if( sock == NULL){
        LOG(LOG_FATAL, "malloc() failed for : ipc_socket. ", errno, 3, &ctx->log);
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

    LOG(LOG_TRACE, "Setting up address to bind on ...", errno, 0, &ctx->log);

    switch(ctx->options->domain){

        case AF_UNIX:{
            /*
        server->address.sa_family = (sa_family_t) domain;
        strcpy(server->address.sa_data, socket_address);
        unlink(server->address.sa_data);

        len = (socklen_t) (strlen(socket_address) + sizeof(domain));
        server->bind_address = &server->address;
        */

            /* Destroy ancient socket if interrupted abruptly*/
            unlink(ctx->options->socket_path);

            /* Make sure we do not overflow the path buffer */
            if( strlen(ctx->options->socket_path) >= sizeof(server->address.un.sun_path)){
                LOG(LOG_CRITICAL, "Socket path is too long : overflow avoided !", errno, 1, &ctx->log);
                len = -1;
                break;
            }

            server->address.un.sun_family = AF_UNIX;

            bzero((char*)server->address.un.sun_path, sizeof(server->address.un.sun_path));
            strncpy(server->address.un.sun_path, ctx->options->socket_path, sizeof(server->address.un.sun_path) - 1);

            len = (socklen_t ) (strlen(server->address.un.sun_path) + sizeof(server->address.un.sun_family));

            server->bind_address = (struct sockaddr*)&server->address.un;
            break;
        }

        case AF_INET:{
            server->address.in.sin_family = (sa_family_t) ctx->options->domain;
            server->address.in.sin_port = htons(ctx->options->port);
            server->address.in.sin_addr.s_addr = address;

            len = sizeof(struct sockaddr_in);

            server->bind_address = (struct sockaddr*)&server->address.in;
            break;
        }

        default:
            LOG(LOG_CRITICAL, "domain type not recognised !", errno, 0, &ctx->log);
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

    if (ctx->options->domain != AF_UNIX) {
        if (ctx->options->domain != AF_LOCAL && ctx->options->domain != AF_INET) {
            LOG(LOG_FATAL,
                    "This server does not support other socket types than Unix Sockets, yet. Please use AF_UNIX.",
                    0, 1, &ctx->log);
            return false;
        }
    }

    ctx->socket = new_socket(ctx);
    if (ctx->socket == NULL) {
        LOG(LOG_FATAL, "server_bind() could not allocate socket : ", errno, 2, &ctx->log);
        return false;
    }

    LOG(LOG_INFO, "Allocated memory for server ipc_socket : ", errno, 0, &ctx->log);


    //ctx->socket->mq = ctx->mq;


    /* Socket creation */
    ctx->socket->socket_fd = socket(ctx->options->domain, ctx->options->protocol, 0);
    if( ctx->socket->socket_fd < 0 ){
        LOG(LOG_FATAL, "socket() failed : ", errno, 2, &ctx->log);
        ipc_socket_free(ctx->socket, &ctx->log);
        return false;
    }

    LOG(LOG_INFO, "Socket created.", errno, 0, &ctx->log);


    if ( (len = set_bind_address(ctx, address)) <= 0 ){
        LOG(LOG_FATAL, "Could not properly set socket address type.", errno, 1, &ctx->log);
        ipc_socket_free(ctx->socket, &ctx->log);
        return false;
    }

    /* Set REUSEADDR socket option */
    if( setsockopt(ctx->socket->socket_fd, SOL_SOCKET, SO_PASSCRED || SO_REUSEADDR, &ctx->socket->optval, sizeof(int)) == -1){
        LOG(LOG_ALERT, "set socket option messed up for some reason : ", errno, 1, &ctx->log);
    }

    /* Bind to address */
    if (bind(ctx->socket->socket_fd, ctx->socket->bind_address, (socklen_t) len) != 0) {
        LOG(LOG_FATAL, "Error binding socket : ", errno, 1, &ctx->log);
        ipc_socket_free(ctx->socket, &ctx->log);
        return false;
    }

    LOG(LOG_INFO, "Socket bound.", errno, 0, &ctx->log);

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
        LOG(LOG_FATAL, "error on listening : ", errno, 1, &ctx->log);
        ipc_socket_free(ctx->socket, &ctx->log);
        return false;
    }

    LOG(LOG_INFO, "Server now listening on socket.", errno, 0, &ctx->log);

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
    set_socket_owner_and_permissions(ctx, 0, (mode_t) strtoul(ctx->options->socket_permissions, 0, 8));

    /* Listen for connections */
    if ( !ipc_server_listen(ctx, ctx->options->max_connections) ){
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
        LOG(LOG_ALERT, "accept_connection() could not allocate socket : ", errno, 2, &ctx->log);
        return NULL;
    }

    LOG(LOG_INFO, "Allocated memory for communication ipc_socket : ", errno, 0, &ctx->log);


    switch(ctx->options->domain){

        case AF_UNIX:{
            client->address.un.sun_family = AF_UNIX;
            client->bind_address = (struct sockaddr*)&client->address.un;
            break;
        }

        default:
            LOG(LOG_ALERT, "Other domains than AF_UNIX are not handled yet !", errno, 0, &ctx->log);
            ipc_socket_free(client, &ctx->log);
            return NULL;
    }

    len = sizeof(client->bind_address);

    /*client->socket_fd = accept(server->socket_fd, (struct sockaddr *)&client->address, &client->addrlen);*/
    client->socket_fd = accept(ctx->socket->socket_fd, client->bind_address, &len);
    if (client->socket_fd < 0) {
        LOG(LOG_ERROR, "accept() connection failed : ", errno, 0, &ctx->log);
        ipc_socket_free(client, &ctx->log);
        return NULL;
    }

    LOG(LOG_INFO, "Connection initated.", errno, 0, &ctx->log);

    if( !ipc_validate_peer(ctx)){
        LOG(LOG_ALERT, "Peer has not been authenticated. Dropping connection.", errno, 0, &ctx->log);
        ipc_socket_free(client, &ctx->log);
        return NULL;
    }

    LOG(LOG_INFO, "Peer successfully authenticated. Connection accepted.", errno, 0, &ctx->log);

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
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    LOG_INIT;

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Attempting to send %d bytes.", length);
    LOG(LOG_TRACE, log_buffer, errno, 0, ctx->log);

    if ( data == NULL || length <= 0 ){
        LOG(LOG_ALERT, "Either data is NULL or length is lower or equal to 0. Can't send that on socket.", errno, 0, ctx->log);
        return false;
    }


   while(length > 0){

	    if ((sent = (int) send(sock->socket_fd, data, (size_t) length, 0)) == -1 ){
            LOG(LOG_ALERT, "send() failed : ", errno, 1, ctx->log);
	        return false;
	    }
       snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Send %d bytes.", sent);
       LOG(LOG_TRACE, log_buffer, errno, 5, ctx->log);

	data += sent;
	length -= sent;
   }

    LOG(LOG_INFO, "Finished sending.", errno, 0, ctx->log);

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
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    LOG_INIT;

    LOG(LOG_TRACE, "Attempting to receive data", errno, 0, ctx->log);

    received = (int) recv(sock->socket_fd, data, length, 0);

    if( received == -1 ){
        LOG(LOG_ALERT, "recv() on socket failed :", errno, 3, ctx->log);
        return -1;
    }

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Received %d bytes.", received);
    LOG(LOG_TRACE, log_buffer, errno, 8, ctx->log);

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
    /* TODO */
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
void ipc_socket_free(ipc_socket *com, logging *log){
    LOG_INIT;
    ipc_close_socket(com->socket_fd);
    free(com);
    LOG(LOG_INFO, "Closed socket and freed structure.", errno, 0, log);
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

    LOG(LOG_INFO, "Applying access and permission changes on file.", errno, 0, &ctx->log);

    /**
     * Set ownership of file
     */
    uid = getuid();
    if(!real_gid){

        /* Get group structure */
        errno = 0;
        grp = getgrnam(ctx->options->authorised_peer_username);

        /* Get group id */
        if (grp == NULL) {
            LOG(LOG_ALERT, "Could not retrieve group structure. Access to group will not be applied.", errno, 4, &ctx->log);
        }
        else {
            real_gid = grp->gr_gid;
        }
    }

    if (real_gid && chown(ctx->options->socket_path, uid, real_gid) == -1) {
        LOG(LOG_ALERT, "chown() on socket failed.", errno, 1, &ctx->log);
    }

    /**
     * Change file permissions
     */
    if( chmod(ctx->options->socket_path, perms) < 0){
        LOG(LOG_ALERT, "chmod() on socket failed.", errno, 1, &ctx->log);
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
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};
    char *peer_binary;
    size_t authorised_length;
    size_t peer_binary_length;
    int result;

    LOG_INIT;

    snprintf(proc_file, NAME_MAX, IPC_PEER_BINARY_NAME_FILE_FORMAT, (int)peer_pid, IPC_PEER_BINARY_NAME_FILE);

    peer_binary = read_data_from_source(proc_file, &peer_name_length, &ctx->log);
    if( peer_binary == NULL ){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Could not read process file '%s'. Process not authenticated.", proc_file);
        LOG(LOG_INFO, log_buffer, errno, 3, &ctx->log);
        return false;
    }

    authorised_length = strlen(ctx->options->authorised_peer_process_name);
    peer_binary_length = strlen(peer_binary);

    if (peer_binary_length != authorised_length + 1){
        free(peer_binary);
        LOG(LOG_ERROR, "Peer process name does not match the authorised one. Process not authenticated.", errno, 3, &ctx->log);
        return false;
    }

    result = strncmp(ctx->options->authorised_peer_process_name, peer_binary, authorised_length);

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

    LOG_INIT;
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    struct ucred *creds = ipc_get_ucred(ctx->socket);

    pid_t peer_pid = creds->pid;
    uid_t peer_uid = creds->uid;
    gid_t peer_gid = creds->gid;

    /* BSD function for test and checking */
    uid_t peer_uid_bsd = 0;
    gid_t peer_gid_bsd = 0;
    if (getpeereid(ctx->socket->socket_fd, &peer_uid_bsd, &peer_gid_bsd) == -1){
        LOG(LOG_WARNING, "Could not use BSD getpeerid", errno, 1, &ctx->log);
    }

    /* Check consistency between methods */
    if ( peer_uid_bsd != 0 && peer_uid_bsd != peer_uid ){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Inconsistency in peer uid : ucreds %d vs bsd getpeerid %d.", peer_pid, peer_uid_bsd);
        LOG(LOG_CRITICAL, log_buffer, 0, 2, &ctx->log);
        return false;
    }

    if ( peer_gid_bsd != 0 && peer_gid_bsd != peer_gid ){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Inconsistency in peer gid : ucreds %d vs bsd getpeerid %d.", peer_gid, peer_gid_bsd);
        LOG(LOG_CRITICAL, log_buffer, 0, 2, &ctx->log);
        return false;
    }

    /* Test against authorised values */
    if(ctx->options->authorised_peer_pid){
        if( ctx->options->authorised_peer_pid != peer_pid) {
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer pid %d is not authorised.", peer_pid);
            LOG(LOG_INFO, log_buffer, errno, 2, &ctx->log);
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by pid %d.", peer_pid);
        LOG(LOG_INFO, log_buffer, errno, 0, &ctx->log);
    }

    if(ctx->options->authorised_peer_uid){
        if( ctx->options->authorised_peer_uid != peer_uid) {
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer uid %d, is not authorised.", peer_uid);
            LOG(LOG_INFO, log_buffer, errno, 2, &ctx->log);
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by uid %d.", peer_uid);
        LOG(LOG_INFO, log_buffer, errno, 0, &ctx->log);
    }

    if(ctx->options->authorised_peer_gid){
        if( ctx->options->authorised_peer_gid != peer_gid){
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer gid %d is not authorised.", peer_gid);
            LOG(LOG_INFO, log_buffer, errno, 2, &ctx->log);
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by gid %d.", peer_gid);
        LOG(LOG_INFO, log_buffer, errno, 0, &ctx->log);
    }


    if(strlen(ctx->options->authorised_peer_process_name) > 0){
        if(!ipc_validate_proc(ctx, peer_pid)){
            LOG(LOG_ERROR, "Peer process name does not match the authorised one. Process not authenticated.", errno, 2, &ctx->log);
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by process name '%s'.", ctx->options->authorised_peer_process_name);
        LOG(LOG_INFO, log_buffer, errno, 0, &ctx->log);
    }

    return true;
}





