/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2019 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#include <string.h>
#include <stdint.h>

/* BSD */
#include <bsd/stdlib.h>

/**
 * Fills the buffer pointed to by *rand with size - 1 random alphanumerical values, terminating with a null character.
 * The function never fails and will always return, and is based on a BSD random generator.
 * @param rand
 * @param size
 * @return
 */
static void secure_random_string(char *rand, uint32_t size){

    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint32_t n, charset_length = (uint32_t) strlen(charset);

    if (size){
        --size;
        for (n = 0; n < size; n++){
            rand[n] = charset[arc4random_uniform(charset_length)];
        }
        rand[size] = '\0';
    }
}
