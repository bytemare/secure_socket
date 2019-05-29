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


#ifndef NAME_MAX
    #define NAME_MAX 256
#endif

#ifndef PATH_MAX
    #define PATH_MAX 256
#endif

#ifndef S_IRUSR
    #define S_IRUSR 0400
#endif


#ifndef S_IWUSR
    #define S_IWUSR 0200
#endif

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
#define LOG_OFF         0
#define LOG_FATAL       1
#define LOG_ALERT       2
#define LOG_CRITICAL    3
#define LOG_ERROR       4
#define LOG_WARNING     5
#define LOG_NOTICE      6
#define LOG_INFO        7
#define LOG_DEBUG       8
#define LOG_TRACE       9
#define LOG_NOTSET      10
#define LOG_UNKNWON     11

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
    int8_t  verbosity;
    mqd_t mq;
    char mq_name[NAME_MAX];
    int fd;
    struct aiocb *aio;
    bool quit_logging; /* Syncing with logging thread */

    struct mq_attr mq_attr;

    pthread_t thread;
    pthread_attr_t attr;
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
#define LOG_MQ_SOURCE_MAX_MESSAGE_SIZE_FILE "/proc/sys/fs/mqueue/msgsize_max"


#define LOG_MAX_LVL_LENGTH              8
/*#define LOG_DATE_LENGTH                 11*/
/*#define LOG_TIME_LENGTH                 8*/
#define LOG_MAX_TIMESTAMP_LENGTH        22
#define LOG_MAX_ERRNO_LENGTH            100
#define LOG_MAX_ERROR_MESSAGE_LENGTH    (150 + NAME_MAX)

#define LOG_DEBUG_MAX_PID_LENGTH                5 /* Maximum PID is 32768 */
#define LOG_DEBUG_MAX_THREAD_ID_LENGTH          20 /* obtained with (unsigned int) floor (log10 (UINTMAX_MAX)) + 1 */
#define LOG_DEBUG_MAX_FILE_NAME_LENGTH          NAME_MAX
#define LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH      61
#define LOG_DEBUG_MAX_LINE_NUMBER_LENGTH        5

#define LOG_DEBUG_PREFIX_MAX_LENGTH (21 + LOG_DEBUG_MAX_PID_LENGTH + LOG_DEBUG_MAX_THREAD_ID_LENGTH)
#define LOG_DEBUG_SUFFIX_MAX_LENGTH (33 + LOG_DEBUG_MAX_FILE_NAME_LENGTH + LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH + LOG_DEBUG_MAX_LINE_NUMBER_LENGTH)

#define LOG_MAX_LINE_LENGTH (LOG_MAX_TIMESTAMP_LENGTH + 4 + LOG_MAX_LVL_LENGTH + 2 + LOG_MAX_ERROR_MESSAGE_LENGTH + LOG_MAX_ERRNO_LENGTH + 3)
#define LOG_MAX_DEBUG_LINE_LENGTH (LOG_MAX_LINE_LENGTH + LOG_DEBUG_PREFIX_MAX_LENGTH + LOG_DEBUG_SUFFIX_MAX_LENGTH) /* 637 */

#if LOG_MAX_LINE_LENGTH >= LOG_MQ_MAX_MESSAGE_SIZE
#error "Maximum log line length is too long. Must be strictly inferior to LOG_MQ_MAX_MESSAGE_SIZE."
#endif

#if LOG_MAX_DEBUG_LINE_LENGTH >= LOG_MQ_MAX_MESSAGE_SIZE
#error "Maximum debug log line length is too long. Must be strictly inferior to LOG_MQ_MAX_MESSAGE_SIZE."
#endif




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
 * Function declaration
 */

uint8_t log_initialise_logging_s(logging *log, int8_t verbosity, char *mq_name, char *filename);

void set_thread_attributes(pthread_attr_t *attr, logging *log);

bool log_start_thread(logging *log, int8_t verbosity, char *mq_name, char *log_file);

bool log_start(logging *log, int8_t verbosity, char *mq_name, char *log_file);

void terminate_logging_thread_blocking(logging *log);

void log_free_logging(logging *log);

void log_close(logging *log);

void* logging_thread(void *args);


/**
 * Initialises variables and buffers for building the log line in the scope of calling function
 */
/*#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"*/
#define LOG_INIT\
    logging_buffs log_buffs;\
/*#pragma GCC diagnostic pop*/

/**
 * Logs the given message and errno according to the indicated message level and verbosity,
 * by sending it to the message queue
 */
#define LOG(message_level, message, error_number, error_delta, log)\
    log_to_mq(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ + 1 - (error_delta), log);\

/**
 * Build a log entry with runtime values
 */
#define LOG_BUILD(error_message_format, ...)\
    snprintf(log_buffer, sizeof(log_buffer), error_message_format, ##__VA_ARGS__);\


/**
 * Same as LOG, but writes directly to log file
 */
#define LOG_FILE(message_level, message, error_number, error_delta, log)\
    log_to_file(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ + 1 - (error_delta), log);\

/**
 * Same as LOG, but prints out to standard ouput
 */
#define LOG_STDOUT(message_level, message, error_number, error_delta, log)\
    log_to_stdout(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ + 1 - (error_delta), log);\



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
    snprintf(log_buffs->log_date_buffer, sizeof(log_buffs->log_date_buffer), DATE_FORMAT, log_buffs->log_timer.tm_year + 1900, log_buffs->log_timer.tm_mon + 1, log_buffs->log_timer.tm_mday, log_buffs->log_timer.tm_hour, log_buffs->log_timer.tm_min, log_buffs->log_timer.tm_sec);
}


/**
 * Builds the debug prefix containing the pid and thread id, and stores it in given buffer
 * @param log_debug_prefix_buffer
 * @param message_level
 * @param verbosity
 */
__always_inline void log_debug_get_process_thread_id(char *log_debug_prefix_buffer, const int message_level,
                                                     const int verbosity){
    memset(log_debug_prefix_buffer, '\0', LOG_DEBUG_PREFIX_MAX_LENGTH);
    if(message_level >= verbosity){
        snprintf(log_debug_prefix_buffer, LOG_DEBUG_PREFIX_MAX_LENGTH, LOG_DEBUG_PREFIX_FORMAT, (int) getpid(), (unsigned long int)pthread_self());
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
    memset(log_debug_suffix_buffer, '\0', LOG_DEBUG_SUFFIX_MAX_LENGTH);
    if(message_level >= verbosity){
    //if( message_level >= LOG_ALERT && message_level <= verbosity){
        snprintf(log_debug_suffix_buffer, LOG_DEBUG_SUFFIX_MAX_LENGTH, LOG_DEBUG_SUFFIX_FORMAT, file, function, line);
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
__always_inline void log_get_err_message(logging_buffs *log_buffs, const int error_number, const int message_level){
    if(error_number && message_level > LOG_OFF){
        strlcpy(log_buffs->log_err, ": ", 2);
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
__always_inline const char* interpret_log_level(const int message_level){
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
            return LOG_FATAL_CHAR;

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
    const char *message_level_ch = interpret_log_level(message_level);

    if(verbosity >= LOG_FATAL && verbosity < LOG_DEBUG) {
        snprintf(log_buffs->log_entry_buffer, sizeof(log_buffs->log_entry_buffer), LOG_LINE_FORMAT,
                 log_buffs->log_date_buffer,
                 message_level_ch,
                 log_buffs->log_debug_prefix_buffer,
                 message,
                 log_buffs->log_err,
                 "");
    } else {
        snprintf(log_buffs->log_entry_buffer, sizeof(log_buffs->log_entry_buffer), LOG_LINE_FORMAT,
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
                               const int error_number, const char *file, const char *function, const int line, const int8_t verbosity){
    log_reset(log_buffs);
    log_get_date_time(log_buffs);
    log_debug_get_process_thread_id(log_buffs->log_debug_prefix_buffer, message_level, verbosity);
    log_get_err_message(log_buffs, error_number, message_level);
    log_debug_get_bug_location(log_buffs->log_debug_suffix_buffer, file, function, line, message_level,
                               verbosity);
    log_assemble(log_buffs, message_level, message, verbosity);
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
    if(log->verbosity > LOG_OFF){
        log_build(log_buffs, message_level, message, error_number, file, function, line, log->verbosity);
        mq_send(log->mq, log_buffs->log_entry_buffer, strnlen(log_buffs->log_entry_buffer, sizeof(log_buffs->log_entry_buffer)), 1);
    }
}

/**
 * Simple wrapper printing final log line to standard output
 * @param log
 */
__always_inline void log_to_stdout(logging_buffs *log_buffs, const int message_level, const char *message,
        const int error_number, const char *file, const char *function, const int line, logging *log){
    int8_t verbosity = -1;

    if (log){
        if ( log->verbosity > LOG_OFF ){
            verbosity = log->verbosity;
        }
    } else{
        verbosity = LOG_INFO;
    }

    if ( verbosity != -1 ){
        log_build(log_buffs, message_level, message, error_number, file, function, line, verbosity);
        printf("%s", log_buffs->log_entry_buffer);
    }
}

/**
 * Wrapper, writing an already built log line directly to log file. If writing fails, and verbosity asks for it,
 * error is printed to standard output
 * @param log
 * @param message
 */
__always_inline void log_write_to_file(logging *log, char *message, size_t message_len){
    if (write(log->fd, message, message_len) == -1){
        LOG_INIT
        LOG_STDOUT(LOG_ALERT, "Call to write() to log to file failed. Cannot log.", errno, 1, log)
        if(log->verbosity >= LOG_NOTICE){
            printf("\tOriginal log message :\n");
            printf("\t%s", message);
        }
    }
    memset(message, 0, message_len);
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
    if(log->verbosity > LOG_OFF){
        log_build(log_buffs, message_level, message, error_number, file, function, line, log->verbosity);
        log_write_to_file(log, log_buffs->log_entry_buffer, strnlen(log_buffs->log_entry_buffer, sizeof(log_buffs->log_entry_buffer)));
    }

}


#endif /* LOG_H */
