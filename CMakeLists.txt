# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2017-2018 Bytemare <d@bytema.re>. All Rights Reserved.

cmake_minimum_required(VERSION 3.7.2)
project(secure_socket)


#####################
#####################
#####################
###
### Define Flags
###

# Warning Flags
set(WARNING_FLAGS "-W -Wall -Wextra -Werror -ansi -pedantic -Wwrite-strings -Wconversion -Wuninitialized -Wcast-align -Wmissing-braces -Wunused-result -Wpointer-arith -Wchkp -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wstack-protector -Wformat -Wformat-security -Wstrict-aliasing -Wunused-parameter")

# Debug Flags
set(DEBUG_FLAGS "-g -D DEBUG -frecord-gcc-switches")

# Coverage Flags
set(COVERAGE_FLAGS "-fprofile-arcs -ftest-coverage")
#set(COVERAGE_FLAGS "--coverage") # synonym for -fprofile-arcs -ftest-coverage (when compiling)

# C version flags
set(VERSION_FLAGS "-D_GNU_SOURCE -D_XOPEN_SOURCE=700 -std=gnu11")

# Link to librairies
# For libbsd, install libbsd-dev or use $(pkg-config --libs libbsd)
set(LINKER_LIBRARIES "-pthread -lbsd -lm -lrt")


#####################
#####################
#####################
###
### Security Flags
###

# Sanitiser flags
set(SECURITY_SANITISER_FLAGS "-fsanitize=address -fsanitize=leak -fsanitize=undefined")

# -fstack-protector-all
set(SECURITY_STACK_FLAGS "-fstack-protector-strong --param ssp-buffer-size=1 -fstack-check -fsplit-stack")

# -fpic is for shared libraries
set(SECURITY_PLUS "-pie -fPIE -D_FORTIFY_SOURCE=2")

# Putting all security flags together
set(SECURITY_FLAGS "${SECURITY_SANITISER_FLAGS} ${SECURITY_STACK_FLAGS} ${SECURITY_PLUS}")

#####################
#####################
#####################
###
### Optimisation Flags
###

# -O3 may make the code to big, thus not fitting into the cache, therefore loosing performance
set(PERFORMANCE_FLAGS "-finline-functions -O2 ")

#####################
#####################
#####################
###
### Putting it together dependeing on build mode
###


message([STATUS] " Build type: " ${CMAKE_BUILD_TYPE})

if ( CMAKE_BUILD_TYPE STREQUAL "Coverage" )
    set(CMAKE_C_FLAGS "${DEBUG_FLAGS} ${WARNING_FLAGS} ${VERSION_FLAGS} ${COVERAGE_FLAGS}")
    #set(CMAKE_C_FLAGS "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")
    #target_link_libraries("-g -O0 --coverage")
    #endif ( CMAKE_BUILD_TYPE STREQUAL "Coverage" )

elseif ( CMAKE_BUILD_TYPE STREQUAL "Release" )
    set(CMAKE_C_FLAGS "${WARNING_FLAGS} ${SECURITY_FLAGS} ${PERFORMANCE_FLAGS} ${VERSION_FLAGS}")
    #endif ( CMAKE_BUILD_TYPE STREQUAL "Release" )

elseif ( CMAKE_BUILD_TYPE STREQUAL "Debug" )
    set(CMAKE_C_FLAGS "${DEBUG_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} ${PERFORMANCE_FLAGS} ${VERSION_FLAGS}")
    #endif ( CMAKE_BUILD_TYPE STREQUAL "Debug" )
endif()

#####################
#####################
#####################
###
### Index project files
###

set(SOURCE_FILES
        src/main.c
        src/ipc_socket.c
        src/context.c
        src/handler.c
        src/threaded_server.c src/log.c src/tools.c src/secure_socket_base.c include/handler.h)

include_directories(include/ src/)


#####################
#####################
#####################
###
### Build
###

SET(CMAKE_EXE_LINKER_FLAGS="-fprofile-arcs -ftest-coverage")

add_executable(secure_socket ${SOURCE_FILES} ${HEADERS})

if ( CMAKE_BUILD_TYPE STREQUAL "Coverage" )
    target_link_libraries(secure_socket -lgcov ${LINKER_LIBRARIES})
    #target_link_libraries(secure_socket --coverage ${LINKER_LIBRARIES})
else()
    target_link_libraries(secure_socket ${LINKER_LIBRARIES})
endif()
