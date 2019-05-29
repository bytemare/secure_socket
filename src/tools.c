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
        for (; size >= 0 ; size--){
            rand[size] = charset[arc4random_uniform(sizeof(charset))];
        }

    }
}
