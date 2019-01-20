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
 * POSIX message queues have a standard size defined in /proc/sys/fs/mqueue/msgsize_max
 * mq_receive call has to specify a buffer at least as big as this size
 * @return
 */
int get_mq_max_message_size(logging *log){

    FILE *fp;
    int max_size = 0, ret;
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};
    char *mq_max_message_size_source = LOG_MQ_SOURCE_MAX_MESSAGE_SIZE;

    LOG_INIT;


    LOG_FILE(LOG_TRACE, "Logging Thread : getting maximum message size from system", errno, 0, log);

    fp = fopen(mq_max_message_size_source, "r");
    if (fp == NULL) {
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Logging Thread : Could not open '%s'. Taking default max value %d.", mq_max_message_size_source, LOG_MQ_MAX_MESSAGE_SIZE);
        LOG_FILE(LOG_TRACE, log_buffer, errno, 3, log);
    }
    else {
        errno = 0;

        ret = fscanf(fp, "%d", &max_size); /* TODO clean this here up, there should be a better way of doing this*/

        if (ret == 1){
            fclose(fp);
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Maximum size message for messaging queue is %d.", max_size);
            LOG_FILE(LOG_INFO, log_buffer, errno, 5, log);
        }
        else if ( errno != 0){
            LOG_FILE(LOG_WARNING, "Error in fscanf(). Message size set to default.", errno, 8, log);
            max_size = LOG_MQ_MAX_MESSAGE_SIZE;
        }
        else{
            LOG_FILE(LOG_WARNING, "Message queue : no matching pattern to an integer in file for message size. Message size set to default.", errno, 12, log);
            max_size = LOG_MQ_MAX_MESSAGE_SIZE;
        }
    }

    LOG_FILE(LOG_TRACE, "Size for message in mq is set.", errno, 0, log);

    return max_size;
}

/*
void log_to_file(server_context *ctx, char *message){
    if (write(ctx->log.fd, message, strlen(message)) == -1){
        LOG_STDOUT(LOG_ALERT, "Call to write() to log to file failed.", errno, 1);
        printf("\tOriginal log message :\n");
        printf("\t%s", message);
    }
    memset(message, 0, strlen(message));
}
*/

/**
 * Set to be created pthreads attributes
 * @param attr
 * @param log
 */
void set_thread_attributes(pthread_attr_t *attr, logging *log){

    LOG_INIT;

    /* Initialise structure */
    if( pthread_attr_init(attr) != 0 ) {
        LOG(LOG_ERROR, "Error in thread attribute initialisation : ", errno, 1, log);
    }

    /* Makes the threads KERNEL THREADS, thus allowing multi-processor execution */
    if( pthread_attr_setscope(attr, PTHREAD_SCOPE_SYSTEM) != 0) {
        LOG(LOG_ERROR, "Error in thread setscope : ", errno, 1, log);
    }

    /* Launches threads as detached, since there's no need to sync whith them after they ended */
    if( pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED) != 0 ){
        LOG(LOG_ERROR, "Error in thread setdetachstate : ", errno, 1, log);
    }

    LOG(LOG_TRACE, "Thread attributes set.", 0, 0, log);
}

void terminate_logging_thread_blocking(logging *log){

    LOG_INIT;

    LOG(LOG_INFO, "Terminating logging thread. Awaiting for mutex.", errno, 0, log);

    /* Wait for logging thread to terminate */
    pthread_mutex_lock(&log->mutex);
    log->quit_logging = true;
    pthread_mutex_unlock(&log->mutex);

    /* Put a message to unblock logging thread on message queue */
    LOG(LOG_INFO, "Server awaiting logging thread to terminate ...", errno, 0, log);

    pthread_join(log->thread, NULL);
}


void log_close(logging *log) {

    terminate_logging_thread_blocking(log);

}


/**
 * Starts the logging thread.
 * @param log
 */
bool log_start_thread(logging *log, uint8_t verbosity, char *mq_name, char *log_file){

    int ret;
    LOG_INIT;

    if ( log_initialise_logging_s(log, verbosity, mq_name, log_file) ){
        return false;
    }

    if ( (ret = pthread_create(&log->thread, NULL, &logging_thread, log) ) ){
        LOG_STDOUT(LOG_FATAL, "Error creating logging thread : ", ret, 1);
        return false;
    }

    return true;
}



/**
 * Thread handler for log related actions. Waits on a POSIX messaging queue for incoming messages, and writes them into log file.
 * @param args
 * @return
 */
void* logging_thread(void *args){

    logging *log;
    int nb_bytes;
    int mq_max_size;
    unsigned int prio;
    char *buffer;

    log = (logging*) args;

    LOG_INIT;

    LOG_FILE(LOG_TRACE, "Logging thread started.", errno, 0, log);

    mq_max_size = get_mq_max_message_size(log);
    prio = 0;
    buffer = calloc((size_t )mq_max_size+1, sizeof(char));

    if(!buffer){
        LOG_FILE(LOG_ALERT, "calloc() failed for buffer. Logging thread is not working !!! Exiting now.", errno, 3, log);
    }
    else {

        LOG_FILE(LOG_TRACE, "Logging thread awaiting new messages.", errno, 0, log);

        pthread_mutex_lock(&log->mutex);

        while (!log->quit_logging) {

            pthread_mutex_unlock(&log->mutex);

            memset(buffer, '\0', (size_t )mq_max_size+1);
            nb_bytes = (int) mq_receive(log->mq, buffer, (size_t )mq_max_size, &prio);

            if (nb_bytes == -1) {
                LOG_FILE(LOG_ALERT, "Logging : Error in mq_receive", errno, 3, log);
            }
            else {
                log_write_to_file(log, buffer);
            }

            pthread_mutex_lock(&log->mutex);
        }

        free(buffer);
    }

    LOG_FILE(LOG_TRACE, "Logging thread now quitting.", errno, 0, log);

    log->quit_logging = false;

    pthread_cond_signal(&log->cond);

    pthread_mutex_unlock(&log->mutex);

    pthread_exit((void*)0);

}

