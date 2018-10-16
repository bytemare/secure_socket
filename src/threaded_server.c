/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <log.h>
#include <context.h>
#include <threaded_server.h>
#include <sys/stat.h>
#include <ipc_socket.h>

/**
 * Set to be created pthreads attributes
 * @param ctx
 */
void set_thread_attributes(server_context *ctx){

    LOG_INIT;

    /* Initialise structure */
    if( pthread_attr_init(&ctx->attr) != 0 ) {
        LOG_TTY(LOG_WARNING, "Error in thread attribute initialisation : ", errno);
    }

    /* Makes the threads KERNEL THREADS, thus allowing multi-processor execution */
    if( pthread_attr_setscope(&ctx->attr, PTHREAD_SCOPE_SYSTEM) != 0) {
        LOG_TTY(LOG_WARNING, "Error in thread setscope : ", errno);
    }

    /* Launches threads as detached, since there's no need to sync whith them after they ended */
    if( pthread_attr_setdetachstate(&ctx->attr, PTHREAD_CREATE_DETACHED) != 0 ){
        LOG_TTY(LOG_WARNING, "Error in thread setdetachstate : ", errno);
    }
}

/**
 * Given a path to filename, reads the file and returns an appropriate buffer containing its content and appropriately
 * sets the size pointer to the number of bytes read.
 * @param filename
 * @param length
 * @return
 */
char *read_data_from_source (const char *filename, int *size, const mqd_t *mq){

    char *destination;
    int file;
    size_t length;
    struct stat file_info;

    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH];

    LOG_INIT;

    /*
     *
     */

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Attempting to read data from file '%s' ", filename);
    LOG(LOG_INFO, log_buffer, *mq, errno);


    file = open(filename, O_RDONLY);

    if(file == -1){
        perror("[-] Could not open file.");
        return NULL;
    }

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Successfully opened file for reading.");
    LOG(LOG_INFO, log_buffer, *mq, errno);

    fstat(file, &file_info);

    if (!S_ISREG(file_info.st_mode)) {
        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Error : '%s' is not a regular file !", filename);
        LOG(LOG_ERROR, log_buffer, *mq, errno);
        close(file);
        return NULL;
    }

    length = (size_t) file_info.st_size;

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "File '%s' is '%d' bytes long.", filename, (int)length);
    LOG(LOG_INFO, log_buffer, *mq, errno);


    destination = malloc(length);
    if( !destination ){
        LOG(LOG_ERROR, "malloc for file reading failed : ", *mq, errno);
        return NULL;
    }

    length = (size_t) read(file, destination, length);

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "Read '%d' bytes from '%s'", (int)length, filename);
    LOG(LOG_INFO, log_buffer, *mq, errno);
    close(file);

    *size = (int)length;
    return destination;
}


/**
 * Thread handler : executes associated action for client communication
 * @param args
 * @return
 */
static void* handle_client(void *args){

    thread_context *ctx;

    LOG_INIT;

    ctx = (thread_context*)args;

    LOG(LOG_INFO, "Thread launched.", ctx->mq, errno);

    /*handle_client_connection(client);*/
    //handler(ctx);

    free_thread_context(ctx);

    LOG(LOG_INFO, "Connexion closed. Thread now exiting.", ctx->mq, errno);

    pthread_exit((void*)0);
}


/**
 * Performs a file write in the file specified in given context
 * @param ctx
 * @param message
 */
void log_write(server_context *ctx, char *message){
    /*ctx->aio->aio_buf = message;
    ctx->aio->aio_nbytes = (int)strlen(message);
    aio_write(ctx->aio);*/

    time_t t;
    struct tm timer;

    if(write(ctx->fd, message, strlen(message)) == -1){
        t = time(NULL);
        timer = *localtime(&t);
        printf("%04d-%d-%d - %02d:%02d:%02d [%s] : Could not write to log file ! %s\n", timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min, timer.tm_sec, LOG_CRITICAL, strerror(errno));
    }
    memset(message, 0, strlen(message));
}




/**
 * POSIX message queues have a standard size defined in /proc/sys/fs/mqueue/msgsize_max
 * mq_receive call has to specify a buffer at least as big as this size
 * @return
 */
int get_mq_max_message_size(server_context *ctx){

    FILE *fp;
    int max_size = 0, ret;
    char strerror_ret[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};
    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH] = {0};
    char *mq_max_message_size_source = "/proc/sys/fs/mqueue/msgsize_max";
    time_t t = time(NULL);
    struct tm timer = *localtime(&t);

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: Logging Thread : getting maximum message size from system ...\n",
             timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
             timer.tm_sec, LOG_INFO, (int) getpid(), (unsigned long int)pthread_self());
    log_write(ctx, log_buffer);

    fp = fopen(mq_max_message_size_source, "r");
    if (fp == NULL) {
        max_size = 8192;
        t = time(NULL);
        timer = *localtime(&t);

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: Could not open '%s'. Taking default max value %d.\n",
                 timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                 timer.tm_sec, LOG_ERROR, (int) getpid(), (unsigned long int)pthread_self(), mq_max_message_size_source, max_size);
    }
    else {
        errno = 0;
        ret = fscanf(fp, "%d\n", &max_size); /* TODO clean this here up, there should be a better way of doing this*/

        if (ret == 1){
            fclose(fp);
            t = time(NULL);
            timer = *localtime(&t);
            snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH,
                     "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: Maximum size message for messaging queue is %d.\n",
                     timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                     timer.tm_sec, LOG_INFO, (int) getpid(), (unsigned long int) pthread_self(), max_size);
        }
        else if ( errno != 0){
            if( strerror_r(errno, strerror_ret, LOG_MAX_ERRNO_LENGTH) ) {
                snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] Error in fscanf() : %s\n",
                         timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                         timer.tm_sec, LOG_ERROR, strerror_ret);
            }
            else{
                snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] Error in strerror_r() : cannot interprete errno from fscanf (errno = %d).\n",
                         timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                         timer.tm_sec, LOG_ERROR, errno);
            }
        }
        else{
            snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: No matching pattern in file for message size.\n",
                     timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                     timer.tm_sec, LOG_INFO, (int) getpid(), (unsigned long int)pthread_self());
        }
    }

    log_write(ctx, log_buffer);

    return max_size;
}


/**
 * Thread handler for log related actions. Waits on a POSIX messaging queue for incoming messages, and writes them into log file.
 * @param args
 * @return
 */
void* logging_thread(void *args){

    server_context *ctx;
    char strerror_ret[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};
    char log_buffer[LOG_DEBUG_MAX_LOG_LENGTH] = {0};
    time_t t;
    struct tm timer;
    int nb_bytes;
    int mq_max_size;
    unsigned int prio;
    char *buffer;


    ctx = (server_context*) args;

    t = time(NULL);
    timer = *localtime(&t);

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: Logging thread started.\n",
             timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
             timer.tm_sec, LOG_INFO, (int) getpid(), (unsigned long int)pthread_self());
    log_write(ctx, log_buffer);

    mq_max_size = get_mq_max_message_size(ctx);
    prio = 0;
    buffer = calloc((size_t )mq_max_size+1, sizeof(char));

    if(!buffer){
        t = time(NULL);
        timer = *localtime(&t);

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: calloc() failed for buffer. Logging thread is not working !!! Exiting now.\n",
                 timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                 timer.tm_sec, LOG_CRITICAL, (int) getpid(), (unsigned long int)pthread_self());
        log_write(ctx, log_buffer);
    }
    else {

        t = time(NULL);
        timer = *localtime(&t);

        snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: %s\n",
                 timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                 timer.tm_sec, LOG_INFO, (int) getpid(), (unsigned long int)pthread_self(), "Logging thread awaiting new messages.");
        log_write(ctx, buffer);

        pthread_mutex_lock(&ctx->mutex);

        while (!ctx->quit_logging) {

            pthread_mutex_unlock(&ctx->mutex);

            memset(buffer, '\0', (size_t )mq_max_size+1);
            nb_bytes = (int) mq_receive(ctx->mq, buffer, (size_t )mq_max_size, &prio);

            if (nb_bytes == -1) {
                t = time(NULL);
                timer = *localtime(&t);

                if( strerror_r(errno, strerror_ret, LOG_MAX_ERRNO_LENGTH) ) {
                    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH,
                             "%04d-%d-%d - %02d:%02d:%02d [%s] Error in mq_receive : %s\n",
                             timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                             timer.tm_sec, LOG_ERROR, strerror_ret);
                }
                else{
                    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH,
                             "%04d-%d-%d - %02d:%02d:%02d [%s] Error in strerror_r() for mq_receive (errno = %d).\n",
                             timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
                             timer.tm_sec, LOG_ERROR, errno);
                }
                log_write(ctx, log_buffer);
            }
            else {
                /* Write the nb_bytes to file */
                log_write(ctx, buffer);
            }

            pthread_mutex_lock(&ctx->mutex);

        }

        free(buffer);

    }

    t = time(NULL);
    timer = *localtime(&t);

    snprintf(log_buffer, LOG_DEBUG_MAX_LOG_LENGTH, "%04d-%d-%d - %02d:%02d:%02d [%s] pid %d - pthread %lu ::: %s\n",
             timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
             timer.tm_sec, LOG_INFO, (int) getpid(), (unsigned long int)pthread_self(), "Logging thread now quitting.");
    log_write(ctx, log_buffer);


    ctx->quit_logging = false;

    pthread_cond_signal(&ctx->cond);

    pthread_mutex_unlock(&ctx->mutex);

    pthread_exit((void*)0);

}






/**
 * Server function : Daemon mode awaiting connections and executing threads to handle them
 * Accepts up to 10 errors before leaving daemon mode
 * @param server
 * @param nb_cnx
 */
void threaded_server(server_context *ctx, const unsigned int nb_cnx){

    /* Variables for timestamping */
    time_t t;
    struct tm timer;

    /* List of threads system id's */
    unsigned int count; /* Total accumulated amount of accepted connections */
    unsigned int offset; /* Index between 0 and nb_cnx */
    /*unsigned int nb_threads = 0;*/ /* Used later to determine number of effectively created threads */
    unsigned int nb_authorised_errors; /* Number of errors before exiting daemon mode */

    thread_context **client_ctx; /* Contexts with logging queue and ipc_sockets to deal with clients */
    ipc_socket *new_client;

    /* Initialise variables */
    pthread_t tid;

    LOG_INIT;

    count = 0;
    nb_authorised_errors = 50;



    client_ctx = malloc(nb_cnx * sizeof(thread_context*));
    if( client_ctx == NULL){
        LOG(LOG_ERROR, "malloc failed for client/thread_contexts ", ctx->mq, errno);
        return;
    }

    t = time(NULL);
    timer = *localtime(&t);

    printf("%04d-%d-%d - %02d:%02d:%02d : Server now running and awaiting connections.\n\tpid : %d\n\tlog file : %s\n\tsocket : %s\n\n",
           timer.tm_year + 1900, timer.tm_mon + 1, timer.tm_mday, timer.tm_hour, timer.tm_min,
           timer.tm_sec, getpid(), ctx->options.log_file, ctx->options.socket_path);
    LOG(LOG_INFO, "Server now ready and awaiting incoming connections.", ctx->mq, errno);

    /* Enter Daemon mode */
    while(nb_authorised_errors) {

        /* get_next_available_offset() */

        offset = count++%(nb_cnx);

        client_ctx[offset] = make_thread_context(NULL, ctx);

        new_client = ipc_accept_connection(ctx);

        if( new_client == NULL ){
            LOG(LOG_ERROR, "ipc_accept_connection returned NULL pointer. Connection denied.", ctx->mq, errno);
            count--;
            nb_authorised_errors--;
            free_thread_context(client_ctx[offset]);
            continue;
        }

        client_ctx[offset]->socket = new_client;

        /* (void*)handle_client */
        if( pthread_create(&tid, &ctx->attr, &handle_client, client_ctx[offset]) != 0 ){
            LOG(LOG_ERROR, "error creating thread. Connection closed.", ctx->mq, errno);
            free_thread_context(client_ctx[offset]);
            nb_authorised_errors--;
            continue;
        }

    }

    LOG(LOG_INFO, "Thread Server is quitting daemon mode. Now cleaning up.", ctx->mq, errno);

    if( pthread_attr_destroy(&ctx->attr) != 0 ){
        LOG(LOG_INFO, "Thread Server could not destroy thread attributes.", ctx->mq, errno);
    }

    free(client_ctx);
}
