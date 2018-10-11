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
#define LOG_DEBUG                       "DEBUG"
#define LOG_TRACE                       "TRACE"
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
 * Date format - [Log level] pid - pthread id ::: Custom message : System error message - filename function line number
 *
 */
#define LOG_FORMAT "%s [%s] pid %d - pthread %lu ::: %s%s - in file %s function %s @ line %d.\n"

#define LOG_MAX_LVL_LENGTH              8
/*#define LOG_DATE_LENGTH                 11*/
/*#define LOG_TIME_LENGTH                 8*/
#define LOG_MAX_TIMESTAMP_LENGTH        22
#define LOG_MAX_PID_LENGTH              5
#define LOG_MAX_THREAD_ID_LENGTH        20 /* obtained with (unsigned int) floor (log10 (UINTMAX_MAX)) + 1 */
#define LOG_MAX_ERRNO_LENGTH            100
#define LOG_MAX_ERROR_MESSAGE_LENGTH    100
#define LOG_MAX_FILE_NAME_LENGTH        50
#define LOG_MAX_FUNCTION_NAME_LENGTH    50
#define LOG_MAX_LINE_NUMBER_LENGTH      5
#define LOG_NB_SPACES_AND_CHARS         62
#define LOG_MAX_LOG_LENGTH              (LOG_MAX_TIMESTAMP_LENGTH + LOG_MAX_PID_LENGTH + LOG_MAX_THREAD_ID_LENGTH + LOG_MAX_LVL_LENGTH + LOG_MAX_ERROR_MESSAGE_LENGTH + LOG_MAX_ERRNO_LENGTH + LOG_MAX_FILE_NAME_LENGTH + LOG_MAX_FUNCTION_NAME_LENGTH + LOG_MAX_LINE_NUMBER_LENGTH + LOG_NB_SPACES_AND_CHARS)


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
    char *str_ret;
    char log_err[LOG_MAX_ERRNO_LENGTH];\
    char log_entry_buffer[LOG_MAX_LOG_LENGTH];\
    time_t log_t;\
    struct tm log_timer;
/*#pragma GCC diagnostic pop*/
/*#pragma GCC diagnostic pop*/


#define LOG_RESET\
    memset(log_entry_buffer, '\0', LOG_MAX_LOG_LENGTH);\
    memset(log_err, '\0', LOG_MAX_ERRNO_LENGTH);\
    log_t = time(NULL);\
    log_timer = *localtime(&log_t);

#define LOG_GET_DATE_TIME\
    snprintf(log_entry_buffer, LOG_MAX_TIMESTAMP_LENGTH - 1, DATE_FORMAT, log_timer.tm_year + 1900, log_timer.tm_mon + 1, log_timer.tm_mday, log_timer.tm_hour, log_timer.tm_min, log_timer.tm_sec);\

#define LOG_GET_ERRNO(error_number)\
    if(error_number){\
        sprintf(log_err, ": ");\
        str_ret = strerror_r(error_number, log_err + strlen(log_err), LOG_MAX_ERRNO_LENGTH - 1);\
        if( strerror_r(error_number, log_err + strlen(log_err), LOG_MAX_ERRNO_LENGTH - 1) == NULL){;\
            LOG_RESET;\
            LOG_GET_DATE_TIME;\
            printf(LOG_FORMAT, log_entry_buffer, LOG_CRITICAL, (int) getpid(), (unsigned long int)pthread_self(), "strerror_r failed : returned NULL. Error interpretation can not be done !", "", __FILE__, __func__, __LINE__ );\
        }\
    }


#define LOG_BUILD(message_level, message, error_number)\
    LOG_RESET;\
    LOG_GET_DATE_TIME;\
    log_len = strlen(log_entry_buffer);\
    LOG_GET_ERRNO(error_number);\
    snprintf(log_entry_buffer + log_len, LOG_MAX_LOG_LENGTH - log_len - 1, LOG_FORMAT, "", message_level, (int) getpid(), (unsigned long int)pthread_self(), message, log_err, __FILE__, __func__, __LINE__ );\

/**
 * Logs to be sent to message queue
 */

#define LOG(message_level, message, mq, error_number)\
    LOG_BUILD(message_level, message, error_number);\
    mq_send(mq, log_entry_buffer, strlen(log_entry_buffer), 1);\

/**
 * Logs to be printed to standard output
 */

#define LOG_TTY(message_level, message, error_number)\
    LOG_BUILD(message_level, message, error_number);\
    printf("%s", log_entry_buffer);


#endif /* LOG_H */
