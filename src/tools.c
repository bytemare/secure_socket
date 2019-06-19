/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2019 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* BSD */
#include <bsd/stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <libgen.h>
#include <limits.h>

#include <bsd/string.h>

/**
 * Fills the buffer pointed to by *rand with size - 1 random alphanumerical values, terminating with a null character.
 * The function is based on a BSD random generator, never fails, and will always return.
 * @param rand
 * @param size
 * @return
 */
void secure_random_string(char *rand, uint32_t size){

    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    if (size){
        --size;
        rand[size] = '\0';
        for (; (int) size >= 0 ; size--){
            rand[size] = charset[arc4random_uniform(sizeof(charset))];
        }

    }
}

/**
 * Attempts to open a file with given flags and mode, protecting against a symlink attack.
 * If precised, attempts to obtain an exlusive lock on file.
 * On failure, returns 0 if TOCTOU race condition was detected or if file is not a regular file, or -1 with errno set from failing function.
 *
 * @param path
 * @param flags
 * @param mode
 * @return
 */
int secure_file_open(const char *path, int flags, mode_t mode, bool lock){

    int fd;
    bool new_file = false;
    struct stat lstat_info;
    struct stat fstat_info;
    char filepath[NAME_MAX] = {0};
    strlcpy(filepath, path, NAME_MAX);

    /* Add additional security flags */
    flags |= O_CLOEXEC;
    /*flags |= (O_CREAT | O_EXCL); -- Don't follow symbolic links, but fails if file already exists */

    /* Get attributes on file and check if file is not a symbolic link */
    if ( lstat(path, &lstat_info) == -1 ){

        /* Check if file is maybe not on disk, in which case we verify if at least the path is valid */
        if ( errno != ENOENT || lstat(dirname(filepath), &lstat_info) == -1 ) {
            /* Todo : handle error */
            return -1;
        }
        new_file = true;
    }

    /* Open the file with exclusive lock to avoid race condition on operations */
    if ( lock ){
        if ( mode ){
            fd = flopen( path, flags, mode);
        } else {
            fd = flopen( path, flags);
        }
    } else {
        if ( mode ){
            fd = open( path, flags, mode);
        } else {
            fd = open( path, flags);
        }
    }

    /* Quit on error */
    if ( fd == -1 ){
        return -1;
    }

    /* Get attributes of file through the file descriptor */
    if ( fstat(fd, &fstat_info) == -1 ){
        /* todo : handle error */
        int serrno;
        serrno = errno;
        close(fd);
        errno = serrno;
        return -1;
    }

    /* Test if file is regular file */
    if (!S_ISREG(fstat_info.st_mode)) {
        /* TODO : handle error */
        close(fd);
        return 0;
    }

    /* If we created a new file, we don't check for race condition (since there was no file) */
    if ( new_file ){
        return fd;
    }

    /* Compare attributes and fail if they diverge */
    if (lstat_info.st_mode == fstat_info.st_mode &&
        lstat_info.st_ino == fstat_info.st_ino  &&
        lstat_info.st_dev == fstat_info.st_dev) {

        /* File descriptor is cleared for secure usage */
        return fd;
    } else {
        /* Todo :  handle error
         * Here, a TOCTOU race condition was detected*/
        close(fd);
        return 0;
    }
}


/**
 * Given a path to filename, reads at most max_length bytes from file, fills buffer dest_buffer with its content and
 * returns the number of bytes read.
 * @param filename
 * @param length
 * @return
 */
ssize_t read_data_from_file(const char *filename, char *dest_buffer, int max_length, bool lock){

    int file;
    ssize_t disk_file_length;
    ssize_t read_length;
    struct stat file_info;

    /*
     * Use of a BSD function here with a lock to prevent a race condition, since the function is used to open a PID file, among others
     */
    file = secure_file_open(filename, O_RDONLY, 0, lock);

    if ( file == -1 ){
        if( errno == EWOULDBLOCK){
            /* TODO : handle error */
            printf("Unable to open file '%s', the log file is locked by another process. Free the file and try again.\n", filename);
        } else {
            /* TODO : handle error */
            printf("Error in opening '%s'for reading.", filename);
        }
        return -1;
    }

    if ( file == 0 ){
        /* TODO : handle error */
        printf("Symlinks for file opening are forbidden (this is either an error or a TOCTOU race condition).\n");
        return -1;
    }

    /* Check if file size exceeds the authorised maximum length */

    fstat(file, &file_info);
    disk_file_length = file_info.st_size;

    if ( disk_file_length >= max_length ){
        /* TODO : handle error */
        printf("file length exceed authorised max limit.\n");
        return -1;
    }

    read_length = read(file, dest_buffer, sizeof(max_length) - 1);
    if ( read_length == -1 ) {
        // TODO handle error
        close(file);
        return -1;
    }

    dest_buffer[read_length] = '\0';

    close(file);

    return read_length;
}
