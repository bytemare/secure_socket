# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.

cmake_minimum_required(VERSION 3.7.2)
project(secure_socket)

set(COMPILATION_WARNINGS "-W -Wall -Wextra -Werror -ansi -pedantic -Wuninitialized -Wcast-align -Wpointer-arith -Wmissing-braces -Wunused-result -Wl,-z,relro -Wl,-z,now -Wformat -Wformat-security -Wstrict-aliasing -Wunused-parameter -Wchkp")

set(LINKER_LIBRARIES "-lbsd -lrt -pthread -lm")


set(SANITISER_FLAGS "-fsanitize=address -fsanitize=leak -fsanitize=undefined")

set(SECURITY_FLAGS "${SANITISER_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2 -fstack-check -fsplit-stack")


set(CMAKE_C_FLAGS " ${COMPILATION_WARNINGS} ${LINKER_LIBRARIES} ${SECURITY_FLAGS} -D_GNU_SOURCE -O3 -std=c11")

# -D_XOPEN_SOURCE=700
# -fpic is for shared libraries

# For libbsd, install libbsd-dev or use $(pkg-config --libs libbsd)

set(SOURCE_FILES
        src/main.c
        src/ipc_socket.c
        src/context.c
        src/threaded_server.c src/log.c include/logging.h src/tools.c include/tools.h src/secure_socket_base.c include/secure_socket_base.h)


include_directories(include/ src/)

add_executable(secure_socket ${SOURCE_FILES} ${HEADERS})