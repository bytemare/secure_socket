/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2019 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* BSD */
#include <bsd/stdlib.h>
#include <unistd.h>
#include <errno.h>

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
 * On failure, returns 0 if TOCTOU race condition was detected, or -1 with errno set from failing function.
 * @param path
 * @param flags
 * @param mode
 * @return
 */
int secure_file_open(const char *path, int flags, mode_t mode){

    int fd;
    int serrno;
    struct stat lstat_info;
    struct stat fstat_info;

    /* Add additional security flags */
    flags |= O_CLOEXEC;
    //flags |= (O_CREAT | O_EXCL); /* Don't follow symbolic links, but fails if file already exists */

    /* Get attributes on file and check if file is not a symbolic link */
    if ( lstat(path, &lstat_info) == -1 ){
        /* Todo : handle error */
        return -1;
    }

    /* Open the file with exclusive lock to avoid race condition on operations */
    if ( mode ){
        fd = open( path, flags, mode);
    } else {
        fd = open( path, flags);
    }

    /* Quit on error */
    if ( fd == -1 ){
        return -1;
    }

    /* Get attributes of file through the file descriptor */
    if ( fstat(fd, &fstat_info) == -1 ){
        /* todo : handle error */
        serrno = errno;
        close(fd);
        errno = serrno;
        return -1;
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
 * Same as secure_file_open but obtains an exclusive lock
 * @param path
 * @param flags
 * @param mode
 * @return
 */
int secure_file_exclusive_open(const char *path, int flags, mode_t mode){

    int fd;
    int serrno;
    struct stat lstat_info;
    struct stat fstat_info;

    /* Add additional security flags */
    flags |= O_CLOEXEC;
    //flags |= (O_CREAT | O_EXCL); /* Don't follow symbolic links, but fails if file already exists */

    /* Get attributes on file and check if file is not a symbolic link */
    if ( lstat(path, &lstat_info) == -1 ){
        /* Todo : handle error */
        return -1;
    }

    /* Open the file with exclusive lock to avoid race condition on operations */
    if ( mode ){
        fd = flopen( path, flags, mode);
    } else {
        fd = flopen( path, flags);
    }

    /* Quit on error */
    if ( fd == -1 ){
        return -1;
    }

    /* Get attributes of file through the file descriptor */
    if ( fstat(fd, &fstat_info) == -1 ){
        /* todo : handle error */
        serrno = errno;
        close(fd);
        errno = serrno;
        return -1;
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
