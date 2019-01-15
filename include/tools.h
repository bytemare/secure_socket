/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2015-2019 Bytemare <d@bytema.re>. All Rights Reserved.
 */

#ifndef SECURE_SOCKET_TOOLS_H
#define SECURE_SOCKET_TOOLS_H

#include <stdint.h>

void secure_random_string(char *rand, uint32_t size);

#endif //SECURE_SOCKET_TOOLS_H
