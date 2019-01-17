/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <mqueue.h>
#include <aio.h>
#include <limits.h>

/* BSD */
#include <sys/fcntl.h>
#include <bsd/libutil.h>
#include <bsd/string.h>




/**
 * Logging verbosity levels
 */
/*#define LOG_VERBOSITY_1 1 // Fatal + Alert    : <= 1
#define LOG_VERBOSITY_2 3 // + Critic + Error   : <= 3
#define LOG_VERBOSITY_3 5 // + Warning + Notice : <= 5
#define LOG_VERBOSITY_4 7 // + Info + Debug     : <= 7
#define LOG_VERBOSITY_5 8 // + Trace            : <= 8*/


/**
 * Logging severity levels
 */
#define LOG_FATAL       0
#define LOG_ALERT       1
#define LOG_CRITICAL    2
#define LOG_ERROR       3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7
#define LOG_TRACE       8
#define LOG_NOTSET      9
#define LOG_UNKNWON     10
#define LOG_OFF         11

/**
 * Log levels Interpretation
 */
#define LOG_FATAL_CHAR      "FATAL"
#define LOG_ALERT_CHAR      "ALERT"
#define LOG_CRITICAL_CHAR   "CRITICAL"
#define LOG_ERROR_CHAR      "ERROR"
#define LOG_WARNING_CHAR    "WARNING"
#define LOG_NOTICE_CHAR     "NOTICE"
#define LOG_INFO_CHAR       "INFO"
#define LOG_DEBUG_CHAR      "DEBUG"
#define LOG_TRACE_CHAR      "TRACE"
#define LOG_NOTSET_CHAR     "NOTSET"
#define LOG_UNKNOWN_CHAR    "UNKNOWN"
#define LOG_OFF_CHAR        "OFF"

/**
 * Structure to hold all necessary information regarding logging
 */
typedef struct _logging{
    uint8_t  verbosity;
    mqd_t mq;
    char mq_name[NAME_MAX];
    int fd;
    struct aiocb *aio;
    bool quit_logging; /* Syncing with logging thread */

    pthread_mutex_t mutex;
    pthread_cond_t cond;
} logging;


/**
 * Error related constants
 */

/* Allows grouping of locating the log */
/*#define LOG_BUG_LOCATOR()\
    __FILE__, __func__, __LINE__\*/


/*
 * Date format
 *
 */
#define DATE_FORMAT "%04d-%d-%d - %02d:%02d:%02d"


/*
 * Log format
 * Date format - [Log level] pid - pthread id ::: Custom message : System error message - filename function line number.\n
 *
 * Prefix with pid and pthreadid, and suffix with filename, function and line of log call should only be used in debug mode
 *
 */
#define LOG_LINE_FORMAT "%s - [%s] %s%s%s%s.\n" /* datetime + log level + debug prefix + message + errno + debug suffix*/

#define LOG_DEBUG_PREFIX_FORMAT "pid %d - pthread %lu ::: " /* 21 chars */
#define LOG_DEBUG_SUFFIX_FORMAT " - in file %s, function %s at line %d." /* Length of 33 characters without inserted strings */

#define LOG_MQ_MAX_MESSAGE_SIZE         8192
#define LOG_MQ_SOURCE_MAX_MESSAGE_SIZE "/proc/sys/fs/mqueue/msgsize_max"


#define LOG_MAX_LVL_LENGTH              8
/*#define LOG_DATE_LENGTH                 11*/
/*#define LOG_TIME_LENGTH                 8*/
#define LOG_MAX_TIMESTAMP_LENGTH        22
#define LOG_MAX_ERRNO_LENGTH            100
#define LOG_MAX_ERROR_MESSAGE_LENGTH    150

#define LOG_DEBUG_MAX_PID_LENGTH                5
#define LOG_DEBUG_MAX_THREAD_ID_LENGTH          20 /* obtained with (unsigned int) floor (log10 (UINTMAX_MAX)) + 1 */
#define LOG_DEBUG_MAX_FILE_NAME_LENGTH          NAME_MAX
#define LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH      61
#define LOG_DEBUG_MAX_LINE_NUMBER_LENGTH        5

#define LOG_DEBUG_PREFIX_MAX_LENGTH (21 + LOG_DEBUG_MAX_PID_LENGTH + LOG_DEBUG_MAX_THREAD_ID_LENGTH)
#define LOG_DEBUG_SUFFIX_MAX_LENGTH (33 + LOG_DEBUG_MAX_FILE_NAME_LENGTH + LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH + LOG_DEBUG_MAX_LINE_NUMBER_LENGTH)

#define LOG_MAX_LINE_LENGTH (LOG_MAX_TIMESTAMP_LENGTH + 4 + LOG_MAX_LVL_LENGTH + 2 + LOG_MAX_ERROR_MESSAGE_LENGTH + LOG_MAX_ERRNO_LENGTH + 3)
#define LOG_MAX_DEBUG_LINE_LENGTH (LOG_MAX_LINE_LENGTH + LOG_DEBUG_PREFIX_MAX_LENGTH + LOG_DEBUG_SUFFIX_MAX_LENGTH) /* 637 */







/**
 * Initialisation, date/time generation and errno catching macros
 */



/**
 * Structure to hold all buffers regarding logging in calling function
 */
typedef struct _logging_buffs{
    char log_err[LOG_MAX_ERRNO_LENGTH];\
    char log_entry_buffer[LOG_MAX_DEBUG_LINE_LENGTH];\
    char log_date_buffer[LOG_MAX_TIMESTAMP_LENGTH];\
    char log_debug_prefix_buffer[LOG_DEBUG_PREFIX_MAX_LENGTH];\
    char log_debug_suffix_buffer[LOG_DEBUG_SUFFIX_MAX_LENGTH];\
    time_t log_t;\
    struct tm log_timer;
} logging_buffs;


/**
 * Initialises variables and buffers for building the log line in the scope of calling function
 */
/*#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"*/
#define LOG_INIT\
    logging_buffs log_buffs;
/*#pragma GCC diagnostic pop*/

/**
 * Logs the given message and errno according to the indicated message level and verbosity,
 * by sending it to the message queue
 */
#define LOG(message_level, message, error_number, error_delta, log)\
    log_to_mq(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ + 1 - (error_delta), log);\

/**
 * Same as LOG, but writes directly to log file
 */
#define LOG_FILE(message_level, message, error_number, error_delta, log)\
    log_to_file(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ + 1 - (error_delta), log);\

/**
 * Same as LOG, but prints out to standard ouput
 */
#define LOG_STDOUT(message_level, message, error_number, error_delta)\
    log_build(&log_buffs, LOG_ALERT, message, error_number, __FILE__, __func__, __LINE__ + 1 - (error_delta), LOG_TRACE);\
    log_to_stdout(&log_buffs);\



/**
 * Zero-out memory buffers and reset timer
 * This is needed when there's more than one log call per function.
 * The prefix and suffix buffers are memsetted only if needed, at their
 * respective use for filling, to spare the cycles used for the expensive memset.
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline void log_reset(logging_buffs *log_buffs){
    memset(log_buffs->log_err, '\0', LOG_MAX_ERRNO_LENGTH);
    memset(log_buffs->log_entry_buffer, '\0', LOG_MAX_DEBUG_LINE_LENGTH );
    memset(log_buffs->log_date_buffer, '\0', LOG_MAX_TIMESTAMP_LENGTH);
    log_buffs->log_t = time(NULL);
    log_buffs->log_timer = *localtime(&log_buffs->log_t);
}


/**
 * Store current date and time at start of buffer
 * @param log_entry_buffer
 * @param log_timer
 */
__always_inline void log_get_date_time(logging_buffs *log_buffs){
    snprintf(log_buffs->log_date_buffer, LOG_MAX_TIMESTAMP_LENGTH - 1, DATE_FORMAT, log_buffs->log_timer.tm_year + 1900, log_buffs->log_timer.tm_mon + 1, log_buffs->log_timer.tm_mday, log_buffs->log_timer.tm_hour, log_buffs->log_timer.tm_min, log_buffs->log_timer.tm_sec);
}


/**
 * Builds the debug prefix containing the pid and thread id, and stores it in given buffer
 * @param log_debug_prefix_buffer
 * @param message_level
 * @param verbosity
 */
__always_inline void log_debug_get_process_thread_id(char *log_debug_prefix_buffer, const int message_level,
                                                     const int verbosity){
    if(message_level <= verbosity){
        memset(log_debug_prefix_buffer, '\0', LOG_DEBUG_PREFIX_MAX_LENGTH);
        snprintf(log_debug_prefix_buffer, LOG_DEBUG_PREFIX_MAX_LENGTH - 1, LOG_DEBUG_PREFIX_FORMAT, (int) getpid(), (unsigned long int)pthread_self());
    }
}

/**
 * Builds the debug suffix containing filename, function, and line of indicated error, and stores it in given buffer
 * @param log_debug_suffix_buffer
 * @param file
 * @param function
 * @param line
 * @param message_level
 * @param verbosity
 */
__always_inline void log_debug_get_bug_location(char *log_debug_suffix_buffer, const char *file, const char *function,
                                                const int line, const int message_level, const int verbosity){
    //if(message_level <= verbosity){
    if( message_level <= LOG_ALERT && message_level <= verbosity){
        memset(log_debug_suffix_buffer, '\0', LOG_DEBUG_SUFFIX_MAX_LENGTH);
        snprintf(log_debug_suffix_buffer, LOG_DEBUG_SUFFIX_MAX_LENGTH - 1, LOG_DEBUG_SUFFIX_FORMAT, file, function, line);
    }
}

/**
 * Interpret last encountered errno to be logged
 * @param error_number
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline void log_get_errno(logging_buffs *log_buffs, const int error_number, const int message_level, const int verbosity){
    if(error_number >= 0 && message_level <= verbosity){
        sprintf(log_buffs->log_err, ": ");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
        strerror_r(error_number, log_buffs->log_err, LOG_MAX_ERRNO_LENGTH - 1);
#pragma GCC diagnostic pop
    }
}

/**
 * Accordingly returns the string representation of the given message level
 * @param message_level
 * @return
 */
__always_inline char* interpret_log_level(const int message_level){
    switch (message_level){
        case LOG_FATAL:
            return LOG_FATAL_CHAR;
        case LOG_ALERT:
            return LOG_ALERT_CHAR;
        case LOG_CRITICAL:
            return LOG_CRITICAL_CHAR;
        case LOG_ERROR:
            return LOG_ERROR_CHAR;
        case LOG_WARNING:
            return LOG_WARNING_CHAR;
        case LOG_NOTICE:
            return LOG_NOTICE_CHAR;
        case LOG_INFO:
            return LOG_INFO_CHAR;
        case LOG_DEBUG:
            return LOG_DEBUG_CHAR;
        case LOG_TRACE:
            return LOG_TRACE_CHAR;
        case LOG_NOTSET:
            return LOG_NOTSET_CHAR;
        case LOG_UNKNWON:
            return LOG_UNKNOWN_CHAR;
        case LOG_OFF:
            return LOG_OFF_CHAR;
        default:
            return LOG_FATAL;

    }
}

/**
 * Assembles all sub log buffers into one string
 * @param log_buffs
 * @param message_level
 * @param message
 * @param verbosity
 */
__always_inline void log_assemble(logging_buffs *log_buffs, const int message_level, const char *message, int verbosity){
    char *message_level_ch = interpret_log_level(message_level);
    if(verbosity >= LOG_FATAL && verbosity < LOG_DEBUG) {
        snprintf(log_buffs->log_entry_buffer, LOG_MAX_LINE_LENGTH - 1, LOG_LINE_FORMAT,
                 log_buffs->log_date_buffer,
                 message_level_ch,
                 "",
                 message,
                 log_buffs->log_err,
                 "");
    } else {
        snprintf(log_buffs->log_entry_buffer, LOG_MAX_DEBUG_LINE_LENGTH - 1, LOG_LINE_FORMAT,
                 log_buffs->log_date_buffer,
                 message_level_ch,
                 log_buffs->log_debug_prefix_buffer,
                 message,
                 log_buffs->log_err,
                 log_buffs->log_debug_suffix_buffer);
    }
}

/**
 * Performs the whole logging string build-up, recording time, log level, debug info and log message.
 * @param log_buffs
 * @param message_level
 * @param message
 * @param error_number
 * @param file
 * @param function
 * @param line
 * @param verbosity
 */
__always_inline void log_build(logging_buffs *log_buffs, const int message_level, const char *message,
                               const int error_number, const char *file, const char *function, const int line, const uint8_t verbosity){
    log_reset(log_buffs);
    log_get_date_time(log_buffs);
    log_debug_get_process_thread_id(log_buffs->log_debug_prefix_buffer, message_level, verbosity);
    log_get_errno(log_buffs, error_number, message_level, verbosity);
    log_debug_get_bug_location(log_buffs->log_debug_suffix_buffer, file, function, line - 1, message_level,
                               verbosity);
    log_assemble(log_buffs, message_level, message, verbosity);
}

/**
 * Simply sends the string containing the final log line to message queue
 * @param log_buffs
 * @param log
 */
__always_inline void log_send_to_mq(logging_buffs *log_buffs, logging *log){
    mq_send(log->mq, log_buffs->log_entry_buffer, strlen(log_buffs->log_entry_buffer), 1);
}

/**
 * Wrapper, building a whole log line and sending it to message queue
 * @param log_buffs
 * @param message_level
 * @param message
 * @param error_number
 * @param file
 * @param function
 * @param line
 * @param log
 */
__always_inline void log_to_mq(logging_buffs *log_buffs, const int message_level, const char *message,
        const int error_number, const char *file, const char *function, const int line, logging *log){
    if(log->verbosity >= LOG_NOTSET){
        return;
    }
    log_build(log_buffs, message_level, message, error_number, file, function, line, log->verbosity);
    log_send_to_mq(log_buffs, log);
}

/**
 * Simple wrapper printing final log line to standard output
 * @param log
 */
__always_inline void log_to_stdout(logging_buffs *log){
    printf("%s", log->log_entry_buffer);
}

/**
 * Wrapper, writing an already built log line directly to log file. If writing fails, and verbosity asks for it,
 * error is printed to standard output
 * @param log
 * @param message
 */
__always_inline void log_write_to_file(logging *log, char *message){
    if (write(log->fd, message, strlen(message)) == -1){
        LOG_INIT;
        LOG_STDOUT(LOG_ALERT, "Call to write() to log to file failed. Cannot log.", errno, 1);
        if(log->verbosity >= LOG_NOTICE){
            printf("\tOriginal log message :\n");
            printf("\t%s", message);
        }
    }
    memset(message, 0, strlen(message));
}

/**
 * Builds a log line and writes it directly to buffer by calling log_write_to_file
 * @param log_buffs
 * @param message_level
 * @param message
 * @param error_number
 * @param file
 * @param function
 * @param line
 * @param log
 */
__always_inline void log_to_file(logging_buffs *log_buffs, const int message_level, const char *message,
                              const int error_number, const char *file, const char *function, const int line, logging *log){
    if(log->verbosity >= LOG_NOTSET){
        return;
    }
    log_build(log_buffs, message_level, message, error_number, file, function, line, log->verbosity);
    log_write_to_file(log, log_buffs->log_entry_buffer);
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
__always_inline uint8_t log_initialise_logging_s(logging *log, uint8_t verbosity, char *mq_name, char *filename){

    LOG_INIT;

    log->verbosity = verbosity;

    /* Unlink potential previous message queue if it had the same name */
    mq_unlink(mq_name);

    /* Check bounds to avoid overlow */
    if (strlen(mq_name) >= sizeof(log->mq_name)){
        LOG_STDOUT(LOG_FATAL, "Error in opening the logging messaging queue. Size is >= to maximum buffer size.", errno, 1);
        return 1;
    }

    /* Opening Message Queue */
    if( (log->mq = mq_open(mq_name, O_RDWR | O_CREAT | O_EXCL, 0600, NULL)) == (mqd_t)-1) {
        LOG_STDOUT(LOG_FATAL, "Error in opening the logging messaging queue.", errno, 1);
        return 1;
    }


    if ( strlcpy(log->mq_name, mq_name, sizeof(log->mq_name)) >= sizeof(log->mq_name) ){
        LOG_STDOUT(LOG_WARNING, "Message queue name is too long and got truncated to maximum authorised size.", errno, 1);
    }


    /* Open log file with BSD function to obtain exclusive lock on file */
    log->fd = flopen(filename, O_CREAT|O_WRONLY|O_APPEND|O_SYNC, S_IRUSR|S_IWUSR);
    if( log->fd == -1 ){
        LOG_STDOUT(LOG_FATAL, "Error in opening log file.", errno, 2);
        return 1;
    }

    /* Initialise asynchronous I/O structure */
    log->aio = malloc(sizeof(struct aiocb));
    if(!log->aio){
        LOG_FILE(LOG_ALERT, "malloc failed allocation space for the aiocb structure.", errno, 2, log);
        return 1;
    }

    log->aio->aio_fildes = log->fd;
    log->aio->aio_buf = NULL;
    log->aio->aio_nbytes = 0;

    LOG_FILE(LOG_INFO, "Initialised logging structure.", -1, 0, log);

    return 0;
}

/**
 * Wrapper of log_initialise_logging_s, returning a pointer to a malloc'ed logging structure. A call to log_free_logging()
 * should be called to free the ressources.
 * @param verbosity
 * @param mq_name
 * @param filename
 * @return Pointer to initialised logging structure, NULL when failed
 */
/*__always_inline logging* log_initialise_logging(uint8_t verbosity, char *mq_name, char *filename){

    logging *log;

    LOG_INIT;

    log = malloc(sizeof(logging));
    if ( !log ){
        LOG_STDOUT(LOG_FATAL, "malloc failed allocation space for the logging structure.", errno, 2);
        return NULL;
    }

    if ( log_initialise_logging_s(log, verbosity, mq_name, filename) ){
        free(log);
        return NULL;
    }

    return log;
}*/

void terminate_logging_thread_blocking(const pthread_t *logger, logging *log);

void* logging_thread(void *args);



/**
 * Free the allocated spaces for the logging structure components, closes and unlinks the message queue
 * @param log
 */
__always_inline void log_free_logging(logging *log){

    if (log->mq != -1){
        mq_close(log->mq);
        mq_unlink(log->mq_name);
    }

    close(log->fd);

    free(log->aio);
    log->aio = NULL;
}
#endif /* LOG_H */
