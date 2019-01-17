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
#include <secure_socket_types.h>
#include <log.h>




/**
 * POSIX message queues have a standard size defined in /proc/sys/fs/mqueue/msgsize_max
 * mq_receive call has to specify a buffer at least as big as this size
 * @return
 */
int get_mq_max_message_size(server_context *ctx){

    FILE *fp;
    int max_size = 0, ret;
    char log_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH] = {0};
    char *mq_max_message_size_source = LOG_MQ_SOURCE_MAX_MESSAGE_SIZE;

    LOG_INIT;


    LOG_FILE(LOG_TRACE, "Logging Thread : getting maximum message size from system", 0, 0, &ctx->log);

    fp = fopen(mq_max_message_size_source, "r");
    if (fp == NULL) {
        snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Logging Thread : Could not open '%s'. Taking default max value %d.", mq_max_message_size_source, LOG_MQ_MAX_MESSAGE_SIZE);
        LOG_FILE(LOG_TRACE, log_buffer, errno, 3, &ctx->log);
    }
    else {
        errno = 0;

        ret = fscanf(fp, "%d", &max_size); /* TODO clean this here up, there should be a better way of doing this*/

        if (ret == 1){
            fclose(fp);
            snprintf(log_buffer, LOG_MAX_ERROR_MESSAGE_LENGTH, "Maximum size message for messaging queue is %d.", max_size);
            LOG_FILE(LOG_INFO, log_buffer, 0, 5, &ctx->log);
        }
        else if ( errno != 0){
            LOG_FILE(LOG_WARNING, "Error in fscanf(). Message size set to default.", errno, 8, &ctx->log);
            max_size = LOG_MQ_MAX_MESSAGE_SIZE;
        }
        else{
            LOG_FILE(LOG_WARNING, "Message queue : no matching pattern to an integer in file for message size. Message size set to default.", 0, 12, &ctx->log);
            max_size = LOG_MQ_MAX_MESSAGE_SIZE;
        }
    }

    LOG_FILE(LOG_TRACE, "Size for message in mq set.", 0, 0, &ctx->log);

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
 * Thread handler for log related actions. Waits on a POSIX messaging queue for incoming messages, and writes them into log file.
 * @param args
 * @return
 */
void* logging_thread(void *args){

    server_context *ctx;
    int nb_bytes;
    int mq_max_size;
    unsigned int prio;
    char *buffer;

    ctx = (server_context*) args;

    LOG_INIT;

    LOG_FILE(LOG_TRACE, "Logging thread started.", 0, 0, &ctx->log);

    mq_max_size = get_mq_max_message_size(ctx);
    prio = 0;
    buffer = calloc((size_t )mq_max_size+1, sizeof(char));

    if(!buffer){
        LOG_FILE(LOG_ALERT, "calloc() failed for buffer. Logging thread is not working !!! Exiting now.", errno, 3, &ctx->log);
    }
    else {

        LOG_FILE(LOG_TRACE, "Logging thread awaiting new messages.", 0, 0, &ctx->log);

        pthread_mutex_lock(&ctx->mutex);

        while (!ctx->log.quit_logging) {

            pthread_mutex_unlock(&ctx->mutex);

            memset(buffer, '\0', (size_t )mq_max_size+1);
            nb_bytes = (int) mq_receive(ctx->log.mq, buffer, (size_t )mq_max_size, &prio);

            if (nb_bytes == -1) {
                LOG_FILE(LOG_ALERT, "Logging : Error in mq_receive", errno, 3, &ctx->log);
            }
            else {
                log_write_to_file(&ctx->log, buffer);
            }

            pthread_mutex_lock(&ctx->mutex);
        }

        free(buffer);
        buffer = NULL;
    }

    LOG_FILE(LOG_TRACE, "Logging thread now quitting.", 0, 0, &ctx->log);

    ctx->log.quit_logging = false;

    pthread_cond_signal(&ctx->cond);

    pthread_mutex_unlock(&ctx->mutex);

    pthread_exit((void*)0);

}