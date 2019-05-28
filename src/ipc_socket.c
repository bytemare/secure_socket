/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

/*#define _GNU_SOURCE  declare this before anything else */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <grp.h>
#include <sys/stat.h>

/* BSD */
#include <sys/types.h>
#include <bsd/unistd.h>

/* Secure_socket */
#include <ipc_socket.h>
#include <secure_socket_base.h>
#include <threaded_server.h>
#include <vars.h>
#include <log.h>


/**
 * Allocates memory for an ipc_socket instance, calling an error when failing
 * @return allocated non-instanciated ipc_socket, NULL if failed
 */
secure_socket *secure_socket_allocate(server_context *ctx) {

    secure_socket *sock;

    LOG_INIT

    sock = malloc(sizeof(secure_socket));

    if( sock == NULL){
        LOG(LOG_FATAL, "malloc() failed for : secure_socket. ", errno, 3, ctx->log)
        return NULL;
    }

    sock->socket_fd = -1;
    sock->optval = 1;

    /*  TODO what's this ? : sock->addrlen = sizeof (sock->in_address) */

    return sock;
}


/**
 * Closes a socket given its file descriptor
 * @param socketfd
 */
void ipc_close_socket(secure_socket *sock){
    close(sock->socket_fd);
    sock->socket_fd = -1;
}


/**
 * Closes the socket file descriptor and frees the structure. This function returns à NULL pointer to be affected
 * to the pointer given in argument, to avoid heap-use-after-free bugs.
 * Usage example : sock = secure_socket_free(sock, log)
 * @param sock
 * @param log
 * @return NULL
 */
secure_socket* secure_socket_free(secure_socket *sock, logging *log){
    LOG_INIT
    ipc_close_socket(sock);
    free(sock);
    LOG(LOG_INFO, "Closed socket and freed structure.", errno, 0, log)
    return NULL;
}



bool secure_socket_create_socket(server_context *ctx){

    LOG_INIT

    ctx->socket->socket_fd = socket(ctx->options->domain, ctx->options->protocol, 0);
    if( ctx->socket->socket_fd < -1 ){
        LOG(LOG_FATAL, "socket() failed : ", errno, 2, ctx->log)
        secure_socket_free_from_context(ctx);
        return false;
    }

    return true;
}



/**
 * Given the domain, initialises the sockets address structure (un, in or in6)
 * @param server
 * @param domain
 * @param address
 * @param port
 * @param socket_address
 * @param ctx
 * @return -1 if failed, 0 on success
 */
uint8_t set_bind_address(server_context *ctx, in_addr_t address){

    secure_socket *server;

    LOG_INIT

    server = ctx->socket;

    LOG(LOG_TRACE, "Setting up address to bind on ...", errno, 0, ctx->log)



    if ( ctx->options->domain == AF_UNIX ){
        server->bind_address = socket_bind_unix(&server->address.un, ctx->options->socket_path, &ctx->socket->addrlen);

        if ( server->bind_address == NULL ){
            LOG(LOG_CRITICAL, "Socket path is too long : overflow avoided !", errno, 1, ctx->log)
            ctx->socket->addrlen = 0;
            return 1;
        }

        return 0;
    }

    if ( ctx->options->domain == AF_INET ){
        server->bind_address = socket_bind_inet(&server->address.in, ctx->options->domain, ctx->options->port, address, &ctx->socket->addrlen);
        return 0;
    }

    if ( ctx->options->domain == AF_INET6){
        LOG(LOG_CRITICAL, "IPv6 domain type is not supported.", errno, 0, ctx->log)
    } else {
        LOG(LOG_CRITICAL, "domain type is invalid or not recognised !", errno, 0, ctx->log)
    }

    ctx->socket->addrlen = 0;

    return 1;
}


/**
 * Bind the application to an address via a socket contained in a ipc_socket structure
 * @param domain : address domain: AF_UNIX, AF_INET etc.
 * @param address
 * @param port
 * @return true or false, depending on success
 */
bool ipc_server_bind(in_addr_t address, server_context *ctx){

    LOG_INIT

    if (ctx->options->domain != AF_UNIX && (ctx->options->domain != AF_LOCAL && ctx->options->domain != AF_INET) ) {
        LOG(LOG_FATAL,
                "This server does not support other socket types than Unix Sockets, yet. Please use AF_UNIX.",
                0, 1, ctx->log)
        return false;

    }

    if ( set_bind_address(ctx, address) ){
        LOG(LOG_FATAL, "Could not properly set socket address type.", errno, 1, ctx->log)
        secure_socket_free_from_context(ctx);
        return false;
    }

    /* Set socket options */
    if( setsockopt(ctx->socket->socket_fd, SOL_SOCKET, SO_REUSEADDR, &ctx->socket->optval, sizeof(ctx->socket->optval)) == -1){
        LOG(LOG_ALERT, "SO_REUSEADDR socket option messed up for some reason : ", errno, 1, ctx->log)
    }

    if( setsockopt(ctx->socket->socket_fd, SOL_SOCKET, SO_PASSCRED, &ctx->socket->optval, sizeof(ctx->socket->optval)) == -1){
        LOG(LOG_ALERT, "SO_PASSCRED socket option messed up for some reason : ", errno, 1, ctx->log)
    }

    /* Bind to address */
    if (bind(ctx->socket->socket_fd, ctx->socket->bind_address, ctx->socket->addrlen) != 0) {
        LOG(LOG_FATAL, "Error binding socket : ", errno, 1, ctx->log)
        secure_socket_free_from_context(ctx);
        return false;
    }

    LOG(LOG_INFO, "Socket bound.", errno, 0, ctx->log)

    return true;
}

/**
 * Sets the socket in a listen state queuing n connections (number of accepted connections)
 * @param server
 * @return
 */
bool ipc_server_listen(server_context *ctx, const unsigned int nb_cnx){

    LOG_INIT

    /* Listen for connections */
    if (listen(ctx->socket->socket_fd, (int)nb_cnx) != 0) {
        LOG(LOG_FATAL, "error on listening : ", errno, 1, ctx->log)
        secure_socket_free_from_context(ctx);
        return false;
    }

    LOG(LOG_INFO, "Server now listening on socket.", errno, 0, ctx->log)

    return true;
}

/**
 * Decorator combining binding and listening. Return true/false depending on success.
 * @param port
 * @param address
 * @return
 */
bool ipc_bind_set_and_listen(in_addr_t address, server_context *ctx) {

    /* TODO: what's that ?
     * Create directory in which to place the socket file */

    /* Bind the server to a socket */
    if (!ipc_server_bind(address, ctx)) {
        return false;
    }

    /* Force permissions on socket file to peer's user group */
    set_socket_owner_and_permissions(ctx, ctx->options->authorised_peer_username, ctx->options->authorised_peer_uid, (mode_t) strtoul(ctx->options->socket_permissions, 0, 8));

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
secure_socket* ipc_accept_connection(server_context *ctx){

    socklen_t len;
    secure_socket *client_socket;

    LOG_INIT

    client_socket = secure_socket_allocate(ctx);
    if (client_socket == NULL) {
        LOG(LOG_ALERT, "accept_connection() could not allocate socket : ", errno, 2, ctx->log)
        return NULL;
    }

    LOG(LOG_INFO, "Allocated memory for communication secure_socket : ", errno, 0, ctx->log)

    if (ctx->options->domain) {
        client_socket->address.un.sun_family = AF_UNIX;
        client_socket->bind_address = (struct sockaddr*)&client_socket->address.un;
    } else {
        LOG(LOG_ALERT, "Other domains than AF_UNIX are not handled yet !", errno, 0, ctx->log)
        client_socket = secure_socket_free(client_socket, ctx->log);
        secure_socket_free(client_socket, ctx->log);
        return NULL;
    }

    len = sizeof(client_socket->bind_address);

    /* Old code :
     * client_socket->socket_fd = accept(server->socket_fd, (struct sockaddr *)&client_socket->address, &client_socket->addrlen) */
    client_socket->socket_fd = accept(ctx->socket->socket_fd, client_socket->bind_address, &len);
    if (client_socket->socket_fd < 0) {
        LOG(LOG_ERROR, "accept() connection failed : ", errno, 0, ctx->log)
        secure_socket_free(client_socket, ctx->log);
        return NULL;
    }

    LOG(LOG_INFO, "Connection initated.", errno, 0, ctx->log)

    if( !ipc_validate_peer(ctx)){
        LOG(LOG_ALERT, "Peer has not been authenticated. Dropping connection.", errno, 0, ctx->log)
        secure_socket_free(client_socket, ctx->log);
        return NULL;
    }

    LOG(LOG_INFO, "Peer successfully authenticated. Connection accepted.", errno, 0, ctx->log)

    return client_socket;
}

/**
 * Sends data buffer through given socket
 * @param sock
 * @param data
 * @return true or false, whether send succeded
 */
bool ipc_send(secure_socket *sock, int length, char *data, thread_context *ctx){

    int sent;
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    LOG_INIT

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Attempting to send %d bytes.", length);
    LOG(LOG_TRACE, log_buffer, errno, 0, ctx->log)

    if ( data == NULL || length <= 0 ){
        LOG(LOG_ALERT, "Either data is NULL or length is lower or equal to 0. Can't send that on socket.", errno, 0, ctx->log)
        return false;
    }

   while(length > 0){

	    if ((sent = (int) send(sock->socket_fd, data, (size_t) length, 0)) == -1 ){
            LOG(LOG_ALERT, "send() failed : ", errno, 1, ctx->log)
	        return false;
	    }
       snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Send %d bytes.", sent);
       LOG(LOG_TRACE, log_buffer, errno, 5, ctx->log)

	data += sent;
	length -= sent;
   }

    LOG(LOG_INFO, "Finished sending.", errno, 0, ctx->log)

    return true;
}

/**
 * Blocks on socket and retrieves length bytes and copies them into data. Appends a \0 at length.
 * @param sock
 * @param data
 * @param length
 * @return number of bytes received
 */
int ipc_recv(secure_socket *sock, char *data, unsigned int length, thread_context *ctx){

    int received;
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    LOG_INIT

    LOG(LOG_TRACE, "Attempting to receive data", errno, 0, ctx->log)

    received = (int) recv(sock->socket_fd, data, length, 0);

    if( received == -1 ){
        LOG(LOG_ALERT, "recv() on socket failed :", errno, 3, ctx->log)
        return -1;
    }

    snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Received %d bytes.", received);
    LOG(LOG_TRACE, log_buffer, errno, 8, ctx->log)

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
struct ucred* ipc_get_ucred(server_context *ctx){

    socklen_t len;
    struct ucred *creds = malloc(sizeof(struct ucred));

    LOG_INIT

    if ( creds == NULL ){
        LOG(LOG_TRACE, "ipc_get_ucred() : malloc failed for ucred.", errno, 0, ctx->log)
        return NULL;
    }
    len = sizeof(struct ucred);

    if ( getsockopt(ctx->socket->socket_fd, SOL_SOCKET, SO_PEERCRED, creds, &len) < 0 ){
        LOG(LOG_TRACE, "ipc_get_ucred() : could not retrieve ucred.", errno, 0, ctx->log)
        return NULL;
    }

    return creds;
}

/* TODO : keep it or delete it*/
/**
 * Returns the pid of the correspondent process on the other side of the socket
 * @param sock
 * @return
 *
pid_t ipc_get_peer_pid(secure_socket *sock){
    struct ucred *creds = ipc_get_ucred(sock);
    pid_t pid = creds->pid;
    free(creds);
    creds = NULL;
    return pid;
}
*/


/**
 * Closes a socket and frees the memory allocated to the ipc_socket
 * @param com
 */
void secure_socket_free_from_context(server_context *ctx){
    if( ctx->socket ){
        ctx->socket = secure_socket_free(ctx->socket, ctx->log);
    }
}


/**
 * Retrieve effective group ID from group list given the name.
 * Using reentrant function getgrnam_r instead of getgrnam.
 * @param group_name
 * @return gid on success; 0 on failure
 */
gid_t get_group_id(char *group_name, logging *log){

    int err_r;

    char *temp;
    char *gr_buf = NULL;
    long getgr_buf_size;
    long default_getgr_buf_size = 4096;
    const long int secure_socket_max_grbuf_size = 65536;
    struct group *gr_ptr = NULL;
    struct group group_buff;

    LOG_INIT
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    /* Get size for buffer memory
     * Idea comes from https://github.com/collectd/collectd/pull/2937
     */
    getgr_buf_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (getgr_buf_size <= 0) {
        getgr_buf_size = sysconf(_SC_PAGESIZE);
    }
    if (getgr_buf_size <= 0) {
        getgr_buf_size = default_getgr_buf_size;
    }

    /* Plot :
     * The getgr{nam/id}_r reentrant functions need space allocated for the buffer to contain a list. If the group
     * you are retrieving contains too many elements, there might be a chance not enough space was allocated
     * beforehand. So we increase that space until a sufficiently large space was allocated or a maximum reached.
     */
    do {
        temp = realloc(gr_buf, (size_t) getgr_buf_size);
        if ( temp == NULL ) {
            free(gr_buf);
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "realloc() failed for group '%s' with size %ld.", group_name, getgr_buf_size);
            LOG(LOG_ERROR, log_buffer, errno, 2, log)
            return 0;
        }

        gr_buf = temp;

        /* Try to retrieve the group by name */
        if ( (err_r = getgrnam_r(group_name, &group_buff, gr_buf, (size_t) getgr_buf_size, &gr_ptr)) != 0 ){
            /* If we are in here, it is because getgrnam_r has encountered an error,
             * and returned it, but without setting errno.
             */

            if ( err_r == ERANGE ){
                /* If this error is encountered (meaning "Insufficient buffer space supplied.",
                 * it means we need to increase the allocated space and retry.
                 */
                getgr_buf_size += default_getgr_buf_size;

            } else {

                /* Others errors are not handles yet */
                free(gr_buf);
                LOG(LOG_ERROR, "Error: getgrnam_r failed with an unhandled error.", err_r, 4, log)
                return 0;
            }
        } else {

            /* Whatever happens next, we will free the buffer */
            free(gr_buf);

            if ( gr_ptr == NULL ){
                snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Could not find group '%s'.", group_name);
                LOG(LOG_ERROR, log_buffer, 0, 2,log)
                return 0;
            }

            /* Here, we have found the group ID and everything went fine */
            return group_buff.gr_gid;
        }
    } while ( getgr_buf_size <= secure_socket_max_grbuf_size); /* Loop until we hit a maximum */

    free(gr_buf);

    if ( getgr_buf_size > secure_socket_max_grbuf_size ){
        /* Here, we could not allocate enough space, so we quit */
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Could not allocate enough space for group '%s' with size %ld.", group_name, getgr_buf_size);
        LOG(LOG_ERROR, log_buffer, 0, 2, log)
    }

    return 0;
}


/**
 * Changes access and permissions on socket.
 * If real_gid is given (i.e. different from 0) than grants group access to this group. If real_gid is 0, than the
 * group_name given in context is used to retrieve the gid to grant access to.
 * perms is the mode_t describing the permissions to apply, like "0770" : use strtoul("0770", 0, 8)
 * @param file_path
 * @param real_gid
 * @param group_name
 * @param perms
 * @param ctx
 * @return
 */
bool set_socket_owner_and_permissions(server_context *ctx, char *group_name, gid_t real_gid, mode_t perms){

    uid_t uid;

    LOG_INIT
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    LOG(LOG_INFO, "Applying access and permission changes on socket.", errno, 0, ctx->log)

    /**
     * Set ownership of socket
     */
    uid = getuid();

    /* Get effective group ID */
    if(!real_gid){
        if ( (real_gid = get_group_id(group_name, ctx->log)) == 0 ){
            LOG(LOG_ERROR, "Could not retrieve group ID structure. Access to group will not be applied.", errno, 0, ctx->log)
            return false;
        }
    }

    /* Now that real_gid is set, we can grant access */
    if (chown(ctx->options->socket_path, uid, real_gid) == -1) {
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Could not chown for owner '%u' and group '%s' on socket '%s'. Access to group will not be applied.", uid, group_name, ctx->options->socket_path);
        LOG(LOG_ALERT, log_buffer, errno, 2, ctx->log)
        return false;
    }

    /**
     * Change file permissions
     */
    if( chmod(ctx->options->socket_path, perms) < 0){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Could not chmod '%u' on socket '%s'. Permissions will not be applied.", perms, ctx->options->socket_path);
        LOG(LOG_ALERT, log_buffer, errno, 2, ctx->log)
        return false;
    }

    return true;
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

    LOG_INIT

    snprintf(proc_file, NAME_MAX, IPC_PEER_BINARY_NAME_FILE_FORMAT, (int)peer_pid, IPC_PEER_BINARY_NAME_FILE);

    peer_binary = read_data_from_source(proc_file, &peer_name_length, ctx->log);
    if( peer_binary == NULL ){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Could not read process file '%s'. Process not authenticated.", proc_file);
        LOG(LOG_INFO, log_buffer, errno, 3, ctx->log)
        return false;
    }

    authorised_length = strlen(ctx->options->authorised_peer_process_name);
    peer_binary_length = strlen(peer_binary);

    if (peer_binary_length != authorised_length + 1){
        free(peer_binary);
        LOG(LOG_ERROR, "Peer process name does not match the authorised one. Process not authenticated.", errno, 3, ctx->log)
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

    LOG_INIT
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};

    struct ucred *creds = ipc_get_ucred(ctx);

    if ( creds == NULL ){
        LOG(LOG_CRITICAL, "Retrieve ucreds : aborting validation.", errno, 3, ctx->log)
        return false;
    }

    pid_t peer_pid = creds->pid;
    uid_t peer_uid = creds->uid;
    gid_t peer_gid = creds->gid;

    /* BSD function for test and checking */
    uid_t peer_uid_bsd = 0;
    gid_t peer_gid_bsd = 0;
    if (getpeereid(ctx->socket->socket_fd, &peer_uid_bsd, &peer_gid_bsd) == -1){
        LOG(LOG_WARNING, "Could not use BSD getpeerid", errno, 1, ctx->log)
    }

    /* Check consistency between methods */
    if ( peer_uid_bsd != 0 && peer_uid_bsd != peer_uid ){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Inconsistency in peer uid : ucreds %d vs bsd getpeerid %d.", peer_pid, peer_uid_bsd);
        LOG(LOG_CRITICAL, log_buffer, 0, 2, ctx->log)
        return false;
    }

    if ( peer_gid_bsd != 0 && peer_gid_bsd != peer_gid ){
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Inconsistency in peer gid : ucreds %d vs bsd getpeerid %d.", peer_gid, peer_gid_bsd);
        LOG(LOG_CRITICAL, log_buffer, 0, 2, ctx->log)
        return false;
    }

    /* Test against authorised values */
    if(ctx->options->authorised_peer_pid){
        if( ctx->options->authorised_peer_pid != peer_pid) {
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer pid %d is not authorised.", peer_pid);
            LOG(LOG_INFO, log_buffer, errno, 2, ctx->log)
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by pid %d.", peer_pid);
        LOG(LOG_INFO, log_buffer, errno, 0, ctx->log)
    }

    if(ctx->options->authorised_peer_uid){
        if( ctx->options->authorised_peer_uid != peer_uid) {
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer uid %d, is not authorised.", peer_uid);
            LOG(LOG_INFO, log_buffer, errno, 2, ctx->log)
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by uid %d.", peer_uid);
        LOG(LOG_INFO, log_buffer, errno, 0, ctx->log)
    }

    if(ctx->options->authorised_peer_gid){
        if( ctx->options->authorised_peer_gid != peer_gid){
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer gid %d is not authorised.", peer_gid);
            LOG(LOG_INFO, log_buffer, errno, 2, ctx->log)
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by gid %d.", peer_gid);
        LOG(LOG_INFO, log_buffer, errno, 0, ctx->log)
    }


    if(strlen(ctx->options->authorised_peer_process_name) > 0){
        if(!ipc_validate_proc(ctx, peer_pid)){
            LOG(LOG_ERROR, "Peer process name does not match the authorised one. Process not authenticated.", errno, 2, ctx->log)
            return false;
        }

        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Peer authenticated by process name '%s'.", ctx->options->authorised_peer_process_name);
        LOG(LOG_INFO, log_buffer, errno, 0, ctx->log)
    }

    return true;
}





