/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <time.h>




/**
 * Log levels
 */
#define LOG_CRITICAL                    "CRITICAL"
#define LOG_ERROR                       "ERROR"
#define LOG_WARNING                     "WARNING"
/*#define LOG_DEBUG                       "DEBUG"
#define LOG_TRACE                       "TRACE"*/
#define LOG_INFO                        "INFO"


/**
 * Error related constants
 */

/*
 * Date format
 *
 */
#define DATE_FORMAT "%04d-%d-%d - %02d:%02d:%02d"

/*
 * Log format
 * Date format - [Log level] ::: Custom message : System error message.\n
 *
 * Debug log format
 * Date format - [Log level] pid - pthread id ::: Custom message : System error message - filename function line number.\n
 *
 */
#define LOG_FORMAT "%s [%s] ::: %s%s.\n"
#define LOG_DEBUG_FORMAT "%s [%s] pid %d - pthread %lu ::: %s%s - in file %s function %s @ line %d.\n"

#define LOG_MAX_LVL_LENGTH              8
/*#define LOG_DATE_LENGTH                 11*/
/*#define LOG_TIME_LENGTH                 8*/
#define LOG_MAX_TIMESTAMP_LENGTH        22
#define LOG_MAX_ERRNO_LENGTH            100
#define LOG_MAX_ERROR_MESSAGE_LENGTH    100

#define LOG_FORMAT_NB_SPACES_AND_CHARS         16 /* 9 + 7 */
#define LOG_MAX_LOG_LENGTH                      (LOG_MAX_TIMESTAMP_LENGTH + LOG_MAX_LVL_LENGTH + LOG_MAX_ERROR_MESSAGE_LENGTH + LOG_MAX_ERRNO_LENGTH + LOG_FORMAT_NB_SPACES_AND_CHARS)

/* Debug Related values */
#define LOG_DEBUG_MAX_PID_LENGTH                5
#define LOG_DEBUG_MAX_THREAD_ID_LENGTH          20 /* obtained with (unsigned int) floor (log10 (UINTMAX_MAX)) + 1 */
#define LOG_DEBUG_MAX_FILE_NAME_LENGTH          50
#define LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH      50
#define LOG_DEBUG_MAX_LINE_NUMBER_LENGTH        5
#define LOG_DEBUG_NB_SPACES_AND_CHARS           62 /* I count 55, I forgot why it's 62 ( 55 + 7) */
#define LOG_DEBUG_MAX_LOG_LENGTH                (LOG_MAX_TIMESTAMP_LENGTH + LOG_DEBUG_MAX_PID_LENGTH + LOG_DEBUG_MAX_THREAD_ID_LENGTH + LOG_MAX_LVL_LENGTH + LOG_MAX_ERROR_MESSAGE_LENGTH + LOG_MAX_ERRNO_LENGTH + LOG_DEBUG_MAX_FILE_NAME_LENGTH + LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH + LOG_DEBUG_MAX_LINE_NUMBER_LENGTH + LOG_DEBUG_NB_SPACES_AND_CHARS)



/**
 * Initialisation, date/time generation and errno catching macros
 */

/*
 * Declare and initialise arrays and variables for subsequent log macros
 * #pragma to ignore compilation warning for unused variables/parameters
 */

/*#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"*/
#define LOG_INIT\
    int log_len;
    char *str_ret;\
    char log_err[LOG_MAX_ERRNO_LENGTH];\
    char log_entry_buffer[LOG_DEBUG_MAX_LOG_LENGTH];\
    time_t log_t;\
    struct tm log_timer;
/*#pragma GCC diagnostic pop*/


/**
 * Zero-out memory buffers and reset timer
 * This is needed when there's more than one log call per function.
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline void log_reset(char *log_err, char *log_entry_buffer, time_t *log_t, struct tm *log_timer){
    memset(log_err, '\0', LOG_MAX_ERRNO_LENGTH);\
    memset(log_entry_buffer, '\0', LOG_DEBUG_MAX_LOG_LENGTH);\
    *log_t = time(NULL);\
    *log_timer = *localtime(log_t);
}

/**
 * Store current date and time at start of buffer
 * @param log_entry_buffer
 * @param log_timer
 */
__always_inline void log_get_date_time(char *log_entry_buffer, struct tm *log_timer){
    snprintf(log_entry_buffer, LOG_MAX_TIMESTAMP_LENGTH - 1, DATE_FORMAT, log_timer->tm_year + 1900, log_timer->tm_mon + 1, log_timer->tm_mday, log_timer->tm_hour, log_timer->tm_min, log_timer->tm_sec);
}


/**
 * Interpret last encountered error to be logged
 * @param error_number
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline void log_get_errno(int error_number, char *log_err, char *log_entry_buffer, time_t *log_t, struct tm *log_timer){

    if(error_number){\
        sprintf(log_err, ": ");\
        str_ret = strerror_r(error_number, log_err + strlen(log_err), LOG_MAX_ERRNO_LENGTH - 1);\
        if( strerror_r(error_number, log_err + strlen(log_err), LOG_MAX_ERRNO_LENGTH - 1) == NULL){;\
            log_reset(log_err, log_entry_buffer, log_t, log_timer);\
            log_get_date_time(log_entry_buffer, log_timer);\
            printf(LOG_DEBUG_FORMAT, log_entry_buffer, LOG_CRITICAL, (int) getpid(), (unsigned long int)pthread_self(), "strerror_r failed : returned NULL. Error interpretation can not be done !", "", __FILE__, __func__, __LINE__ );\
        }\
    }
}


/**
 * Build the basic log line structure, to be completed by the calling function
 * @param error_number
 * @param log_len
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline void log_build(int error_number, int *log_len, char *log_err, char *log_entry_buffer, time_t *log_t, struct tm *log_timer){
    log_reset(log_err, log_entry_buffer, log_t, log_timer);
    log_get_date_time(log_entry_buffer, log_timer);
    *log_len = (int) strlen(log_entry_buffer);
    log_get_errno(error_number, log_err, log_entry_buffer, log_t, log_timer);
}



/**
 * Logs to be sent to message queue
 */
#ifdef DEBUG
    #define LOG(message_level, message, mq, error_number)\
        log_build(error_number, &log_len, log_err, log_entry_buffer, &log_t, &log_timer);\
        snprintf(log_entry_buffer + log_len, LOG_DEBUG_MAX_LOG_LENGTH - log_len - 1, LOG_DEBUG_FORMAT, "", message_level, (int) getpid(), (unsigned long int)pthread_self(), message, log_err, __FILE__, __func__, __LINE__ );\
        mq_send(mq, log_entry_buffer, strlen(log_entry_buffer), 1);
#else
    #define LOG(message_level, message, mq, error_number)\
        log_build(error_number, &log_len, log_err, log_entry_buffer, &log_t, &log_timer);\
        snprintf(log_entry_buffer + log_len, LOG_MAX_LOG_LENGTH - log_len - 1, LOG_FORMAT, "", message_level, message, log_err);\
        mq_send(mq, log_entry_buffer, strlen(log_entry_buffer), 1);
#endif


/**
 * Logs to be printed to standard output
 */
#ifdef DEBUG
    #define LOG_TTY(message_level, message, error_number)\
        LOG_BUILD(message_level, message, error_number);\
        snprintf(log_entry_buffer + log_len, LOG_DEBUG_MAX_LOG_LENGTH - log_len - 1, LOG_DEBUG_FORMAT, "", message_level, (int) getpid(), (unsigned long int)pthread_self(), message, log_err, __FILE__, __func__, __LINE__ );\
        printf("%s", log_entry_buffer);
#else
    #define LOG_TTY(message_level, message, error_number)\
        log_build(error_number, &log_len, log_err, log_entry_buffer, &log_t, &log_timer);\
        snprintf(log_entry_buffer + log_len, LOG_MAX_LOG_LENGTH - log_len - 1, LOG_FORMAT, "", message_level, message, log_err);\
        printf("%s", log_entry_buffer);
#endif


#endif /* LOG_H */
