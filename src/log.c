/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */


/**
 * __STDC_LIB_EXT1__ must be defined by the implementation, and
 * Set __STDC_WANT_LIB_EXT1__ to 1 before including stdio.h, to ensure bounds-checked functions (here for fscanf_s).
 */
#define __STDC_WANT_LIB_EXT1__ 1

#include <stdio.h>
#include <log.h>


/**
 * Starts the logging thread.
 * @param log
 */
bool log_start_thread(logging *log, int8_t verbosity, char *mq_name, char *log_file){

    LOG_INIT
    int ret;

    /* Initialise logging structure with default parameters and current verbosity */
    log_init_log_params(log, verbosity);

    if( log->verbosity == LOG_OFF ){
        return true;
    }

    if ( log_initialise_logging_s(log, mq_name, log_file) ){
        return false;
    }

    if ( (ret = pthread_create(&log->thread, &log->attr, &logging_thread, log) ) ){
        LOG_STDOUT(LOG_FATAL, "Error creating logging thread : ", ret, 1, log)
        return false;
    }

    return true;
}


/**
 * Starts the logging thread.
 * @param log
 */
bool log_start(logging *log, int8_t verbosity, char *mq_name, char *log_file){
    return log_start_thread(log, verbosity, mq_name, log_file);
}


/**
 * Prints given arguments into buffer pointed to by target given a string format.
 *
 * Format string function used is vasprintf. It uses an intermediary buffer and allocate enough space to hold the whole
 * string, therefore avoiding memory corruption, leaks, and format string vulnerabilities. Because of variable argument
 * list, this function can not be inlined.
 *
 * String insertion is operated by strlcpy.
 * @param target
 * @param max_buf_size
 * @param size_dec
 * @param format
 * @param ...
 * @return
 */
bool log_s_vasprintf(char *target, size_t max_buf_size, size_t size_dec, const char *format, ...){

    int bytes = 0;
    char *buffer = NULL;

    va_list va;
    va_start(va, format);
    bytes = vasprintf(&buffer, format, va);
    va_end(va);
    if ( bytes == -1 || buffer == NULL){
        // TODO handle error
        printf("error : bytes == -1 || buffer == NULL\n");
        return false;
    }
    if ( strnlen(buffer, max_buf_size) == max_buf_size || (size_t) bytes > max_buf_size - 1 ){
        // TODO handle this error
        printf("error on strnlen\n"
               "buffer : '%s'\n"
               "strlen : %lu\n"
               "max: %lu\n"
               "bytes: %d\n",
               buffer, strlen(buffer), max_buf_size, bytes);
        free(buffer);
        return false;
    }
    memset(target, 0, max_buf_size);
    strlcpy(target, buffer, max_buf_size - size_dec);
    free(buffer);
    return true;
}


/**
 * Opens the specified file for writing and tries to obtain an exclusive write lock.
 * @param fd
 * @return 0, 1 on failure with stdout logging
 */
uint8_t log_util_open_file_lock(logging *log, const char *filename){

    LOG_INIT

    /* Open log file with BSD function to obtain exclusive lock on file */
    /* This may not be the best idea. TODO: study what, between BSD and POSIX locks, is better suited. We may want to detect a lock and kill another process to get it."*/
    log->fd = flopen(filename, O_CREAT|O_WRONLY|O_APPEND|O_SYNC|O_NONBLOCK, S_IRUSR|S_IWUSR);
    if( log->fd == -1 ){
        if( errno == EWOULDBLOCK){
            LOG_STDOUT(LOG_FATAL, "The log file is locked by another process. Free the file and try again.", errno, 3, log)
        }
        else{
            LOG_STDOUT(LOG_FATAL, "Error in opening log file.", errno, 6, log)
        }
        return 1;
    }

    return 0;
}


/**
 * Closes the message queue and unlinks the associated name
 * @param mq_des
 * @param mq_name
 */
__always_inline void log_close_single_mq(mqd_t mq_des, const char *mq_name){
    if ( mq_des != -1 ){
        mq_close(mq_des);
        mq_unlink(mq_name);
    }
}

/**
 * Closes all message queues
 * @param log
 */
__always_inline void log_close_mqs(logging *log){
    log_close_single_mq(log->mq_send, log->mq_name);
    log_close_single_mq(log->mq_recv, log->mq_name);
}


/**
 * Opens a message queue in reading mode to retrieve logs writing requests to the logging thread
 * @param log
 * @return
 */
uint8_t log_util_open_server_mq(logging *log){
    LOG_INIT

    // TODO : check arguments here
    if( (log->mq_recv = mq_open(log->mq_name, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC , S_IRUSR | S_IWUSR, log->mq_attr)) == (mqd_t)-1) {
        LOG_STDOUT(LOG_FATAL, "Error in opening the receiver logging messaging queue.", errno, 1, log)
        return 1;
    }

    return 0;
}

/**
 * Opens a message queue in writing mode to send logs writing requests to the logging thread
 * @param log
 * @return
 */
uint8_t log_util_open_client_mq(logging *log){
    LOG_INIT

    /* Double check if message queue already exist */
    if ( log->mq_recv == -1 ) {
        LOG_STDOUT(LOG_FATAL, "Trying to open the sender message queue, but receiver message queue was not opened. This code should not be reached.", 0, 1, log)
        return 1;
    }

    /* If creating a mq succeeds with O_EXCL flag, it means that message queue was not set up before, and we don't want that */
    if ( (log->mq_send = mq_open(log->mq_name, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, log->mq_attr)) != (mqd_t)-1 ) {
        LOG_STDOUT(LOG_FATAL, "Trying to open the sender message queue, but receiver message queue was not opened. This code should not be reached.", 0, 1, log)
        log_close_single_mq(log->mq_send, log->mq_name);
        return 1;
    }

    /* Open the queue in read only mode */
    if( (log->mq_send = mq_open(log->mq_name, O_WRONLY | O_CLOEXEC )) == (mqd_t)-1) {
        LOG_STDOUT(LOG_FATAL, "Error in opening the sender logging messaging queue.", errno, 1, log)
        return 1;
    }

    return 0;
}


/**
 * Opens a message queue in log with given name. Checks for overflow on mq_name.
 * @param log
 * @param mq_name
 * @return 0 on success, 1 on failure
 */
uint8_t log_util_open_mq(logging *log, const char *mq_name){

    LOG_INIT

    /* Unlink potential previous message queue if it had the same name */
    if ( mq_unlink(mq_name) == -1 ){
        if ( errno == EACCES ){
            //TODO
            printf("can't unlink message queue %s\n", mq_name);
            return 1;
        }
        if ( errno == ENAMETOOLONG){
            //TODO
            printf("mq name is too long. This should not happen ! %s\n", mq_name);
            return 1;
        }
    }

    /* Check bounds to avoid truncation */
    if (strnlen(mq_name, sizeof(log->mq_name)) == sizeof(log->mq_name)){
        LOG_STDOUT(LOG_FATAL, "Error in opening the logging messaging queue. Size is >= to maximum buffer size.", errno, 1, log)
        return 1;
    }

    if ( strlcpy(log->mq_name, mq_name, sizeof(log->mq_name)) >= sizeof(log->mq_name) ){
        LOG_STDOUT(LOG_WARNING, "Message queue name is too long and will not be truncated. This should not happen.", errno, 1, log)
        return 1;
    }

    /* Opening Message Queues */
    if ( log_util_open_server_mq(log) ){
        return 1;
    }

    if ( log_util_open_client_mq(log) ){
        log_close_single_mq(log->mq_recv, log->mq_name);
        return 1;
    }

    return 0;
}


/**
 * Allocates and initialises the asynchronous I/O structure.
 * @param log
 * @return 0 on success, 1 on failure
 */
uint8_t log_util_open_aio(logging *log){

    LOG_INIT

    log->aio = malloc(sizeof(struct aiocb));
    if(!log->aio){
        LOG_FILE(LOG_ALERT, "malloc failed allocating space for the logging aiocb structure.", errno, 2, log)
        return 1;
    }

    log->aio->aio_fildes = log->fd;
    log->aio->aio_buf = NULL;
    log->aio->aio_nbytes = 0;

    return 0;
}


/**
 * POSIX message queues have a standard size defined in /proc/sys/fs/mqueue/msgsize_max
 * mq_receive call has to specify a buffer at least as big as this size
 * @return
 */
long int get_mq_max_message_size(logging *log){

    FILE *fp;
    int max_size = 0;

    const char *mq_max_message_size_source = LOG_MQ_SOURCE_MAX_MESSAGE_SIZE_FILE;

    LOG_INIT


    LOG_FILE(LOG_TRACE, "Logging Thread : getting maximum message size from system", errno, 0, log)

    fp = fopen(mq_max_message_size_source, "r");
    if (fp == NULL) {
        LOG_BUILD("Logging Thread : Could not open '%s'. Taking default max value %d.", mq_max_message_size_source, LOG_MQ_MAX_MESSAGE_SIZE)
        LOG_FILE(LOG_TRACE, NULL, errno, 3, log)
    }
    else {
        int ret;
        errno = 0;

        ret = fscanf(fp, "%d", &max_size); /* TODO clean this here up, there should be a better way of doing this*/

        if (ret == 1){
            fclose(fp);
            LOG_BUILD("Maximum size message for messaging queue is %d.", max_size)
            LOG_FILE(LOG_INFO, NULL, errno, 5, log)
        }
        else if ( errno != 0){
            LOG_FILE(LOG_WARNING, "Error in fscanf(). Message size set to default.", errno, 8, log)
            max_size = LOG_MQ_MAX_MESSAGE_SIZE;
        }
        else{
            LOG_FILE(LOG_WARNING, "Message queue : no matching pattern to an integer in file for message size. Message size set to default.", errno, 12, log)
            max_size = LOG_MQ_MAX_MESSAGE_SIZE;
        }
    }

    LOG_FILE(LOG_TRACE, "Size for message in mq is set.", errno, 0, log)

    return max_size;
}


/**
 * Initialise logging structure's components
 * @param log
 * @param verbosity
 */
__always_inline void log_init_log_params(logging *log, int8_t verbosity){
    log->verbosity = verbosity;
    log->fd = -1;
    log->aio = NULL;
    log->quit_logging = false;

    log->thread = 0;
    set_thread_attributes(&log->attr, log);

    log->mq_send = -1;
    log->mq_recv = -1;
    log->mq_attr.mq_flags = 0;
    log->mq_attr.mq_maxmsg = LOG_MQ_MAX_NB_MESSAGES;
    log->mq_attr.mq_curmsgs = 0;
    memset(log->mq_name, 0, sizeof(log->mq_name));
    log->mq_attr.mq_msgsize = LOG_MQ_MAX_MESSAGE_SIZE;
}


/**
 * Given a previously declared logging structure, initialises it by setting the verbosity, and opening the message and
 * log file descriptor.
 * Returns 0 on success, 1 on error
 * @param log
 * @param verbosity
 * @param mq_name
 * @param filename
 * @return 0 on success, 1 on error
 */
__always_inline uint8_t log_initialise_logging_s(logging *log, char *mq_name, char *filename) {

    LOG_INIT

    /* Open log file */
    if ( log_util_open_file_lock(log, filename) ){
        return 1;
    }

    /* Open message queue */
    if ( log_util_open_mq(log, mq_name) ){
        close(log->fd);
        return 1;
    }

    /* Initialise asynchronous I/O structure */
    if ( log_util_open_aio(log) ) {
        close(log->fd);
        log_close_mqs(log);
        return 1;
    }

    LOG_FILE(LOG_INFO, "Initialised logging structure.", 0, 0, log)

    return 0;
}


/**
 * Set to be created pthreads attributes
 * @param attr
 * @param log
 */
void set_thread_attributes(pthread_attr_t *attr, logging *log){

    LOG_INIT

    /* Initialise structure */
    if( pthread_attr_init(attr) != 0 ) {
        LOG_STDOUT(LOG_ERROR, "Error in thread attribute initialisation", errno, 1, log)
    }

    /* Ensures the threads are KERNEL THREADS, thus allowing multi-processor execution */
    if( pthread_attr_setscope(attr, PTHREAD_SCOPE_SYSTEM) != 0) {
        LOG_STDOUT(LOG_ERROR, "Error in thread setscope", errno, 1, log)
    }

    /* Launches threads as detached, since there's no need to sync whith them after they ended */
    /*if( pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED) != 0 ){
        LOG_STDOUT(LOG_ERROR, "Error in thread setdetachstate", errno, 1, log)
    }*/

    LOG_STDOUT(LOG_TRACE, "Thread attributes set.", 0, 0, log)
}

void terminate_logging_thread_blocking(logging *log){

    LOG_INIT
    int join_ret;
    void *join_res;

    LOG(LOG_INFO, "Terminating logging thread. Awaiting for mutex.", errno, 0, log)

    /* Wait for logging thread to terminate */
    pthread_mutex_lock(&log->mutex);
    log->quit_logging = true;
    pthread_mutex_unlock(&log->mutex);

    /* Put a message to unblock logging thread on message queue */
    LOG(LOG_INFO, "Server awaiting logging thread to terminate ...", errno, 0, log)

    if ( (join_ret = pthread_join(log->thread, &join_res)) == -1 ){
        LOG_STDOUT(LOG_ERROR, "Could not join logging thread.", join_ret, 1, log)
    } else {
        LOG_BUILD("Joined logging thread, which returned %s.", (char *)join_res)
        LOG_FILE(LOG_INFO, NULL, 0, 4, log)
    }
}


/**
 * Free the allocated spaces for the logging structure components, closes and unlinks the message queue
 * @param log
 */
__always_inline void log_free_logging(logging *log){

    log_close_mqs(log);

    close(log->fd);

    pthread_attr_destroy(&log->attr);

    free(log->aio);
    log->aio = NULL;
}

/**
 * Called when logging is to be terminated, closes and frees the ressources associated to logging.
 * @param log
 */
void log_close(logging *log) {
    /* TODO : verify if this is always good */
    if(log->verbosity > LOG_OFF) {
        terminate_logging_thread_blocking(log);
        log_free_logging(log);
    }
}


/**
 * Thread handler for log related actions. Waits on a POSIX messaging queue for incoming messages, and writes them into log file.
 * @param args
 * @return
 */
void* logging_thread(void *args){

    logging *log;
    long mq_max_size;
    unsigned int prio;
    char *buffer;

    log = (logging*) args;

    LOG_INIT

    LOG_FILE(LOG_TRACE, "Logging thread started.", errno, 0, log)

    mq_max_size = log->mq_attr.mq_msgsize;
    prio = 0;
    buffer = calloc((size_t )mq_max_size+1, sizeof(char));

    if(!buffer){
        LOG_FILE(LOG_ALERT, "calloc() failed for buffer. Logging thread is not working !!! Exiting now.", errno, 3, log)
    }
    else {

        LOG_FILE(LOG_TRACE, "Logging thread awaiting new messages.", errno, 0, log)

        pthread_mutex_lock(&log->mutex);

        if ( mq_getattr(log->mq_recv, &log->mq_attr) == -1 ){
            //TODO : handle this error
        }
        while (log->mq_attr.mq_curmsgs || !log->quit_logging ) {

            //LOG_STDOUT(LOG_INFO, "Logging thread entered whiled loop.", 0, 0, log)

            int nb_bytes;
            pthread_mutex_unlock(&log->mutex);

            memset(buffer, 0, (size_t )mq_max_size+1);
            nb_bytes = (int) mq_receive(log->mq_recv, buffer, (size_t )mq_max_size, &prio);

            //LOG_STDOUT(LOG_INFO, "Logging thread received a message", 0, 0, log)
            //printf("### LOG : Logging thread received \n\t%s\n", buffer);

            if (nb_bytes == -1) {
                LOG_FILE(LOG_ALERT, "Logging : Error in mq_receive", errno, 3, log)
            }
            else {
                log_write_to_file(log, buffer, (size_t) nb_bytes);
            }

            //printf("### LOG : %lu current messages.\n", log->mq_attr.mq_curmsgs);

            pthread_mutex_lock(&log->mutex);

            if ( mq_getattr(log->mq_recv, &log->mq_attr) == -1 ){
                //TODO : handle this error
            }
        }

        //printf("### LOG : log thread left while loop.\n");

        //printf("### LOG : Leaving logging with %lu left messages.\n", log->mq_attr.mq_curmsgs);

        free(buffer);
    }

    LOG_FILE(LOG_TRACE, "Logging thread now quitting.", errno, 0, log)

    log->quit_logging = false;

    pthread_cond_signal(&log->cond);

    pthread_mutex_unlock(&log->mutex);

    pthread_exit((void*)0);

}

