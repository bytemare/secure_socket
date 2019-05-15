# Recent operated changes

## Done

- [x] General clean-up.
- [x] [Sockets] Adaptive Sockets : depending on the need (unix or internet based communication) uses the **_correct_** type of socket (using an union on structs) and initialises it.
- [x] Detached Threads : no synchronisation needed once a thread is launched, so no joining is needed.
- [x] [Logging] Synchronised main and logging thread : a shared variable is protected by mutex and thread is joined before shutdown.
- [x] [Sockets] Added ability to set socket access rights. set_socket_owner_and_permissions() adds given group id to socket file and applies given permissions.
- [x] [Sockets] access restriction to socket based on peer username applying [current-user]:[peer_user] access rights to socket.
- [x] [Sockets] peer validation based on criteria. Given specified criteria (by pid, uid or gid), validates or not the connection peer : ipc_validate_peer() and ipc_options.
- [x] [Logging] optimised macros : faster than functions, less overhead, cleaner code. Ability to timestamp, compared to inline functions.
- [x] [Logging] cleaned log buffers. Special characters appeared in logs when interpreting errno though no error was encountered.
- [x] [Logging] clean error macros : put errno as argument and/or don't interpret it when no error was encountered (i.e. errno = 0).
- [x] ability to manage command line arguments : parsing, validating and adapt code to handle it : ipc_options.
- [x] [Logging] resolved error mixing. Error logs are now coherently FIFO with accurate date and time.
- [x] [Compilation] hardened compilation rules
- [x] [Compilation] extreme compilation hardening
- [x] [Logging] refactoring log macros : short and concise.
- [x] corrected a buffer overflow vulnerability : macro for maximal length of script name was wrong
- [x] use of strtol instead of atoi in context.c
- [x] [Logging] corrected data disclosure : hash id was fully written to log. Now only the first n characters a are shown.
- [x] [Logging] Enhanced logging usability : Logging to stdout, directly to file, or to message queue.
- [x] [Logging] Introduced leveled verbosity of logging, set in parameters file.
- [x] [Socket] If default values are used, add a random value at end of filenames
- [x] [Logging] Added mode to completely disable logging after the command line parsing
- [x] [Compilation] Further hardened binary through compilation rules

### Priorities

1) change ctx->socket to non-pointer ?
1) Create socket under a dedicated, secured directory
2) Handle SIGPIPE signal : https://blog.erratasec.com/2018/10/tcpip-sockets-and-sigpipe.html#.XMCGx-gzaUk
4) Fallback mechanism if libbsd is not available
5) refactor code for socket to be used as component/library
6) add examples and copy/pastable code

#### Logging

1) When not cleanly shut down, the logging thread/process continues and holds the lock on the log file,
furthers attemps to open are blocked. lslocks CL helps identifying.
1) Ensure logs are syslog compliant, and add other logging formats.
2) add mode to log everything to stdout
4) separate logging macros from code for thread with mq, to enable genericity
5) Add a parameter for log file size, to keep log files at a maximum size, and then log into different file with timestamp
6) Compress old log files
7) ability to send logs to a socket or network address

### Doing

- [>] ucreds insertion in php socket : bypass php api macros and directly address underlying C socket

### Todo

- benchmark performance differences between -fstack-protector-strong and -fstack-protector-all
- check logging for snprintf return value
- Graceful stop via signal handling from outside : take care of threads etc.
- Explore necessity of always_inline'ing functions
- check which option of fsanitize is better suited : adress, thread or leak ?
- gcc options not recognised, why ? fsanitize-address-use-after-scope, fstack-clash-protection, -fcf-protection=full
- check if these are useful : -fsanitize-coverage=trace-pc-guard
- Lookup what -D_POSIX_C_SOURCE=200112L is

### Later

- get log writing non-blocking
- Check why aio writes do not work
- Signal handling. Protect against all signal and keep unavoidable for shutdown.
- Check/analyse for eventual memory leaks (valgrind)

### Notes

- compilation flag D_GNU_SOURCE (glibc manual) : "everything is included: ISO C89, ISO C99, POSIX.1, POSIX.2, BSD, SVID, X/Open, LFS, and GNU extensions."