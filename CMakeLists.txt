# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.

cmake_minimum_required(VERSION 3.7.2)
project(secure_broker)

set(COMPILATION_WARNINGS "-W -Wall -Wextra -Werror -ansi -pedantic -Wuninitialized -Wcast-align -Wpointer-arith -Wmissing-braces -Wunused-result -Wl,-z,relro -Wl,-z,now -Wformat -Wformat-security -Wstrict-aliasing -Wunused-parameter -Wchkp")

set(LINKER_LIBRARIES "-lrt -pthread -lm")

set(CMAKE_C_FLAGS " ${COMPILATION_WARNINGS} ${LINKER_LIBRARIES} -fstack-protector -pie -fPIC  -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -O3 -std=c11 ")

# -D_XOPEN_SOURCE=700

set(SOURCE_FILES
        src/main.c
        src/ipc_socket.c
        src/context.c
        src/threaded_server.c)


include_directories(include/ src/)

add_executable(secure_broker ${SOURCE_FILES} ${HEADERS})