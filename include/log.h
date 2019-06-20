/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
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
 * Fatal + Alert    : <= 1
 * Critic + Error   : <= 3
 * Warning + Notice : <= 5
 * Info + Debug     : <= 7
 * Trace            : <= 8
 */
/*#define LOG_VERBOSITY_1 1
#define LOG_VERBOSITY_2 3
#define LOG_VERBOSITY_3 5
#define LOG_VERBOSITY_4 7
#define LOG_VERBOSITY_5 8*/


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
    char mq_name[NAME_MAX];
    int fd;
    struct aiocb *aio;
    bool quit_logging; /* Syncing with logging thread */

    mqd_t mq_send;
    mqd_t mq_recv;
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
#define LOG_FORMAT_DATE "%04d-%d-%d - %02d:%02d:%02d" /* 21 chars */
#define LOG_FORMAT_DATE_BASE "%Y-%m-%d - %H:%M:%S" /* 21 chars */
#define LOG_FORMAT_DATE_MS "%s:%03ld" /* 21 + 1 + 3 */

/*
 * Log format
 * Date format - [Log level] pid - pthread id ::: Custom message > Errno message - filename, function line number.\n
 *
 * Prefix with pid and pthreadid, and suffix with filename, function and line of log call should only be used in debug mode
 *
 */
#define LOG_FORMAT_LINE "%s - [%s] %s%s%s%s.\n" /* datetime + log level + debug prefix + message + errno + debug suffix*/
#define LOG_FORMAT_ERRNO " > %s (%d)" /* Interpreted errno + number */
#define LOG_FORMAT_DEBUG_PREFIX "pid %d - pthread %lu ::: " /* 21 chars */
#define LOG_FORMAT_DEBUG_SUFFIX " - in file %s, function %s at line %d." /* Length of 33 characters without inserted strings */
/*#define LOG_FORMAT_DEFAULT "ERROR - INVALID LOG FORMAT" *//* When log format is not valid, default to this */

/*
 * To avoid potential vulnerabilities in usage of ellipsis notation by giving a malformed format string to vasprintf,
 * each LOG_FORMAT_* is to be identified, so that log_s_vsnprintf will select a valid, pre-defined format string.
 * TODO : find a better system to maintain and that has less overhead
 * TODO : Actually, this idea doesn't work since we want that freedom that the developer can use a custom string format
 */
/*#define LOG_FORMAT_DATE_ID 1
#define LOG_FORMAT_LINE_ID 2
#define LOG_FORMAT_ERRNO_ID 3
#define LOG_FORMAT_DEBUG_PREFIX_ID 4
#define LOG_FORMAT_DEBUG_SUFFIX_ID 5*/



/* Message queue system constants */
#if HARD_MSGMAX
#define LOG_MQ_MAX_NB_MESSAGES HARD_MSGMAX
#else
#define LOG_MQ_MAX_NB_MESSAGES (65536 - 1)
#endif

#ifdef HARD_MSGSIZEMAX
#define LOG_MQ_MAX_MESSAGE_SIZE HARD_MSGSIZEMAX
#else
#define LOG_MQ_MAX_MESSAGE_SIZE (16777216 - 1)
#endif

#define LOG_MQ_SOURCE_MAX_MESSAGE_SIZE_FILE "/proc/sys/fs/mqueue/msgsize_max"


#define LOG_MAX_LVL_LENGTH              8
/*#define LOG_DATE_LENGTH                 11*/
/*#define LOG_TIME_LENGTH                 8*/
#define LOG_MAX_TIMESTAMP_BASE_LENGTH      22
#define LOG_MAX_TIMESTAMP_MS_LENGTH        26
#define LOG_MAX_ERRNO_LENGTH            100
#define LOG_MAX_ERROR_MESSAGE_LENGTH    (150 + NAME_MAX)

#define LOG_DEBUG_MAX_PID_LENGTH                5 /* Maximum PID is 32768 */
#define LOG_DEBUG_MAX_THREAD_ID_LENGTH          20 /* obtained with (unsigned int) floor (log10 (UINTMAX_MAX)) + 1 */
#define LOG_DEBUG_MAX_FILE_NAME_LENGTH          NAME_MAX
#define LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH      61
#define LOG_DEBUG_MAX_LINE_NUMBER_LENGTH        5

#define LOG_DEBUG_PREFIX_MAX_LENGTH (21 + LOG_DEBUG_MAX_PID_LENGTH + LOG_DEBUG_MAX_THREAD_ID_LENGTH)
#define LOG_DEBUG_SUFFIX_MAX_LENGTH (33 + LOG_DEBUG_MAX_FILE_NAME_LENGTH + LOG_DEBUG_MAX_FUNCTION_NAME_LENGTH + LOG_DEBUG_MAX_LINE_NUMBER_LENGTH)

#define LOG_MAX_LINE_LENGTH (LOG_MAX_TIMESTAMP_MS_LENGTH + 4 + LOG_MAX_LVL_LENGTH + 2 + LOG_MAX_ERROR_MESSAGE_LENGTH + LOG_MAX_ERRNO_LENGTH + 3)
#define LOG_MAX_DEBUG_LINE_LENGTH (LOG_MAX_LINE_LENGTH + LOG_DEBUG_PREFIX_MAX_LENGTH + LOG_DEBUG_SUFFIX_MAX_LENGTH) /* 637 */

#if LOG_MAX_LINE_LENGTH >= LOG_MQ_MAX_MESSAGE_SIZE
#error "Maximum log line length is too long. Must be strictly inferior to LOG_MQ_MAX_MESSAGE_SIZE."
#endif

#if LOG_MAX_DEBUG_LINE_LENGTH >= LOG_MQ_MAX_MESSAGE_SIZE
#error "Maximum debug log line length is too long. Must be strictly inferior to LOG_MQ_MAX_MESSAGE_SIZE."
#endif

#define LOG_EMPTY_LOG_MESSAGE_FAILSAFE "ERROR : Log build was requested with empty message, but usage does not allow it."
#define LOG_BUILD_LOG_MESSAGE_WHITOUT_FLAG "ERROR : Log build was requested by pointing to log buffer, this will zero it out."

/**
 * Initialisation, date/time generation and errno catching macros
 */



/**
 * Structure to hold all buffers regarding logging in calling function
 * IMPORTANT : every line but the last one has to end with a backslash,
 * or ASAN will throw a stack overflow detection.
 */
typedef struct _logging_buffs{
    char log_date_buffer[LOG_MAX_TIMESTAMP_MS_LENGTH];\
    char log_debug_prefix_buffer[LOG_DEBUG_PREFIX_MAX_LENGTH];\
    char log_message_buffer[LOG_MAX_ERROR_MESSAGE_LENGTH];\
    char log_errno_message[LOG_MAX_ERRNO_LENGTH];\
    char log_debug_suffix_buffer[LOG_DEBUG_SUFFIX_MAX_LENGTH];\
    char log_full_line_buffer[LOG_MAX_DEBUG_LINE_LENGTH];\
    bool log_build;
} logging_buffs;

/**
 * Function declaration
 */

uint8_t log_initialise_logging_s(logging *log, char *mq_name, char *filename) __attribute__ ((warn_unused_result));

void set_thread_attributes(pthread_attr_t *attr, logging *log);

void log_init_log_params(logging *log, int8_t verbosity);

int log_start_thread(logging *log, int8_t verbosity, char *mq_name, char *log_file) __attribute__ ((warn_unused_result));

bool log_start(logging *log, int8_t verbosity, char *mq_name, char *log_file) __attribute__ ((warn_unused_result));

void terminate_logging_thread_blocking(logging *log);

void log_free_logging(logging *log);

void log_close(logging *log);

void* logging_thread(void *args);

bool log_s_vsnprintf(char *target, size_t max_buf_size, const char *format, ...) __attribute__ ((warn_unused_result));

/**
 * Initialises variables and buffers for building the log line in the scope of calling function
 */
/*#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"*/
#define LOG_INIT\
    errno = 0;\
    logging_buffs log_buffs;\
    log_buffs.log_build = false;\
/*#pragma GCC diagnostic pop*/

/**
 * Logs the given message and errno according to the indicated message level and verbosity,
 * by sending it to the message queue
 */
#define LOG(message_level, message, error_number, error_delta, log)\
    log_to_mq(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ - (error_delta), log);\

/**
 * Build a log entry with runtime values
 */
#define LOG_BUILD(error_message_format, ...)\
    if ( log_s_vsnprintf(log_buffs.log_message_buffer, sizeof(log_buffs.log_message_buffer), error_message_format, ##__VA_ARGS__) ){ log_buffs.log_build = true; };\

/**
 * Same as LOG, but writes directly to log file
 */
#define LOG_FILE(message_level, message, error_number, error_delta, log)\
    log_to_file(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ - (error_delta), log);\

/**
 * Same as LOG, but prints out to standard ouput
 */
#define LOG_STDOUT(message_level, message, error_number, error_delta, log)\
    log_to_stdout(&log_buffs, message_level, message, error_number, __FILE__, __func__, __LINE__ - (error_delta), log);\

/**
 * Zero-out memory buffers and reset timer
 * This is needed when there's more than one log call per function.
 * The prefix and suffix buffers are memset only if needed, at their
 * respective use for filling, to spare the cycles used for the expensive memset.
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline void log_reset(logging_buffs *log_buffs) {
    memset(log_buffs->log_errno_message, 0, LOG_MAX_ERRNO_LENGTH);
    memset(log_buffs->log_date_buffer, 0, LOG_MAX_TIMESTAMP_MS_LENGTH);
    if (!log_buffs->log_build) {
        memset(log_buffs->log_message_buffer, 0, LOG_MAX_ERROR_MESSAGE_LENGTH);
    }
    memset(log_buffs->log_full_line_buffer, 0, LOG_MAX_DEBUG_LINE_LENGTH);


}

/**
 * Insert in date_buffer the string in a format giving date precision to the millisecond
 * @param date_buffer
 */
__always_inline void log_gettime(char *date_buffer){
    struct tm gmtval = {0};
    struct timespec curtime = {0};
    char timestamp[LOG_MAX_TIMESTAMP_BASE_LENGTH] = {0};

    clock_gettime(CLOCK_REALTIME, &curtime);

    if (gmtime_r(&curtime.tv_sec, &gmtval) != NULL) {
        strftime(timestamp, LOG_MAX_TIMESTAMP_BASE_LENGTH, LOG_FORMAT_DATE_BASE, &gmtval);
        snprintf(date_buffer, LOG_MAX_TIMESTAMP_MS_LENGTH, LOG_FORMAT_DATE_MS, timestamp,
                 lround((double) (curtime.tv_nsec / ((long int) 1.0e6))));
    }
}

/**
 * Builds the debug prefix containing the pid and thread id, and stores it in given buffer
 * @param log_debug_prefix_buffer
 * @param message_level
 * @param verbosity
 */
__always_inline bool log_debug_get_process_thread_id(char *log_debug_prefix_buffer, int8_t message_level,
                                                     const int verbosity){
    memset(log_debug_prefix_buffer, 0, LOG_DEBUG_PREFIX_MAX_LENGTH);
    if(message_level >= verbosity){
        return log_s_vsnprintf(log_debug_prefix_buffer, LOG_DEBUG_PREFIX_MAX_LENGTH, LOG_FORMAT_DEBUG_PREFIX,
                               (int) getpid(), (unsigned long int) pthread_self());
    }
    return true;
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
__always_inline bool log_debug_get_bug_location(char *log_debug_suffix_buffer, const char *file, const char *function,
                                                const int line, int8_t message_level, const int verbosity){
    memset(log_debug_suffix_buffer, 0, LOG_DEBUG_SUFFIX_MAX_LENGTH);
    if(message_level >= verbosity){
        return log_s_vsnprintf(log_debug_suffix_buffer, LOG_DEBUG_SUFFIX_MAX_LENGTH, LOG_FORMAT_DEBUG_SUFFIX, file,
                               function, line);
    }
    return true;
}


/**
 * Interpret last encountered errno to be logged
 * @param error_number
 * @param log_err
 * @param log_entry_buffer
 * @param log_t
 * @param log_timer
 */
__always_inline bool log_get_err_message(logging_buffs *log_buffs, const int error_number, int8_t message_level){
    if(error_number && message_level > LOG_OFF){
        bool ret = log_s_vsnprintf(log_buffs->log_errno_message, LOG_MAX_ERRNO_LENGTH, LOG_FORMAT_ERRNO,
                                   strerror_r(error_number, log_buffs->log_errno_message,
                                              sizeof(log_buffs->log_errno_message) - 4), error_number);
        errno = 0;
        return ret;
    }
    return true;
}


/**
 * Accordingly returns the string representation of the given message level
 * @param message_level
 * @return
 */
__always_inline const char* interpret_log_level(int8_t message_level){
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
__always_inline bool log_assemble(logging_buffs *log_buffs, int8_t message_level, const char *message, int verbosity){
    const char *message_level_ch = interpret_log_level(message_level);

    /*TODO : print this only in log debugging mode
     * printf("\nLog assemble :\n"
           "'%s'\n"
           "'%s'\n"
           "'%s'\n"
           "'%s'\n"
           "'%s'\n"
           "'%s'\n"
           "'%s'\n"
           "=====\n",
           log_buffs->log_full_line_buffer, log_buffs->log_date_buffer, message_level_ch, log_buffs->log_debug_prefix_buffer, message, log_buffs->log_errno_message, log_buffs->log_debug_suffix_buffer);
*/
    // TODO : this logic here is broken, need rethink
    if(verbosity >= LOG_FATAL && verbosity < LOG_DEBUG) {
        return log_s_vsnprintf(log_buffs->log_full_line_buffer, sizeof(log_buffs->log_full_line_buffer),
                               LOG_FORMAT_LINE,
                               log_buffs->log_date_buffer,
                               message_level_ch,
                               log_buffs->log_debug_prefix_buffer,
                               message,
                               log_buffs->log_errno_message,
                               log_buffs->log_debug_suffix_buffer);
    } else {
        return log_s_vsnprintf(log_buffs->log_full_line_buffer, sizeof(log_buffs->log_full_line_buffer),
                               LOG_FORMAT_LINE,
                               log_buffs->log_date_buffer,
                               message_level_ch,
                               log_buffs->log_debug_prefix_buffer,
                               message,
                               "",
                               "");
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
__always_inline void log_build(logging_buffs *log_buffs, int8_t message_level, const char *message,
                               const int error_number, const char *file, const char *function, const int line, const int8_t verbosity){

    if ( message == NULL ){

        /* If the function was called with NULL message, we are supposed to find the message in log_message_buffer
         * and the log_build flag set to true. If flag was not set, LOG_BUILD was not called, and therefore there will
         * be no message, so we have to fail here. */
        if ( log_buffs->log_build ){
            message = log_buffs->log_message_buffer;
        } else {
            message_level = LOG_ERROR;
            message = LOG_EMPTY_LOG_MESSAGE_FAILSAFE;
        }
    } else {
        /* Here, the call has been made by pointing the message pointer to the buffer, therefore memset-ting it to 0,
         * and loosing the message further on */
        if ( message == log_buffs->log_message_buffer ){
            //TODO : handle this
            printf("ERROR ! You are not supposed to do this !\n");
            printf("errno : %d - Verbosity : %d - Message Level : %d - Location : file %s @fun %s at line %d\n", error_number, verbosity, message_level, file, function, line);
            message_level = LOG_ERROR;
            message = LOG_BUILD_LOG_MESSAGE_WHITOUT_FLAG;
        }
    }

    /*TODO : print this only in log debugging mode
     * printf("\033[0;31mLOGGING MESSAGE : '%s'\033[0m;\n", message);
     * printf("\t\t\033[0;31merrno : %d - Verbosity : %d - Message Level : %d - Location : file %s @fun %s at line %d\033[0m;\n", error_number, verbosity, message_level, file, function, line); */

    // TODO : handle return values relayed from vasprintf wrapper
    log_reset(log_buffs);
    log_gettime(log_buffs->log_date_buffer);
    log_debug_get_process_thread_id(log_buffs->log_debug_prefix_buffer, message_level, verbosity);
    log_get_err_message(log_buffs, error_number, message_level);
    log_debug_get_bug_location(log_buffs->log_debug_suffix_buffer, file, function, line, message_level,
                               verbosity);
    log_assemble(log_buffs, message_level, message, verbosity);
}


/**
 * Simple wrapper printing final log line to standard output
 * @param log
 */
__always_inline void log_to_stdout(logging_buffs *log_buffs, int8_t message_level, const char *message,
        const int error_number, const char *file, const char *function, const int line, logging *log){
    int8_t verbosity = -1;

    if (log){
        if ( log->verbosity > LOG_OFF ){
            verbosity = log->verbosity;
        }
    } else{
        verbosity = message_level;
    }

    /*TODO : print this only in log debugging mode
     * printf("verbosity %d - %d - %s - %d - %s - %s - %d\n", verbosity, message_level, message, error_number, file, function, line);*/

    if ( verbosity != -1 ){
        log_build(log_buffs, message_level, message, error_number, file, function, line, verbosity);
        printf("%s", log_buffs->log_full_line_buffer);
    }
}


/**
 * In case a logging request somehow fails (mq_send, write, etc.) use this fallback to print to stdout
 * @param log
 * @param original_log_message
 * @param failure_message
 * @param error_number
 * @param relative_position
 */
__always_inline void log_logging_failure_fallback(logging *log, const char *original_log_message, const char *failure_message, int error_number, int relative_position){
    LOG_INIT
    LOG_STDOUT(LOG_ALERT, failure_message, error_number, relative_position, log)
    if(log->verbosity >= LOG_NOTICE){
        printf("\tOriginal log message :\n");
        printf("\t%s", original_log_message);
    }
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
__always_inline void log_to_mq(logging_buffs *log_buffers, int8_t message_level, const char *message,
                               const int error_number, const char *file, const char *function, const int line, logging *log){
    if(log->verbosity > LOG_OFF){
        log_build(log_buffers, message_level, message, error_number, file, function, line, log->verbosity);
        if ( mq_send(log->mq_send, log_buffers->log_full_line_buffer, strnlen(log_buffers->log_full_line_buffer, sizeof(log_buffers->log_full_line_buffer)), 1) == -1 ){
            log_logging_failure_fallback(log, message, "Call to mq_send() failed. Cannot log.", errno, __LINE__ - 1);
        }
    }
}


/**
 * Wrapper, writing an already built log line directly to log file. If writing fails, and verbosity asks for it,
 * error is printed to standard output
 * @param log
 * @param message
 */
__always_inline void log_write_to_file(logging *log, const char *message, size_t message_len){
    if (write(log->fd, message, message_len) == -1){
        log_logging_failure_fallback(log, message, "Call to write() to log to file failed. Cannot log.", errno, __LINE__ - 1);
    }
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
__always_inline void log_to_file(logging_buffs *log_buffs, int8_t message_level, const char *message,
                              const int error_number, const char *file, const char *function, const int line, logging *log){
    if(log->verbosity > LOG_OFF){
        log_build(log_buffs, message_level, message, error_number, file, function, line, log->verbosity);
        log_write_to_file(log, log_buffs->log_full_line_buffer, strnlen(log_buffs->log_full_line_buffer, sizeof(log_buffs->log_full_line_buffer)));
    }

}

#endif /* LOG_H */
