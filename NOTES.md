# Recent operated changes

## Done

- General

  - [x] General clean-up.
  - [x] Detached Threads : no synchronisation needed once a thread is launched, so no joining is needed.
  - [x] ability to manage command line arguments : parsing, validating and adapt code to handle it : ipc_options.
  - [x] corrected a buffer overflow vulnerability : macro for maximal length of script name was wrong

- Sockets

  - [x] Adaptive Sockets : depending on the need (unix or internet based communication) uses the **_correct_** type of socket (using an union on structs) and initialises it.
  - [x] Added ability to set socket access rights. set_socket_owner_and_permissions() adds given group id to socket file and applies given permissions.
  - [x] access restriction to socket based on peer username applying [current-user]:[peer_user] access rights to socket.
  - [x] peer validation based on criteria. Given specified criteria (by pid, uid or gid), validates or not the connection peer : ipc_validate_peer() and ipc_options.
  - [x] If default values are used, add a random value at end of filenames

- Logging

  - [x] Synchronised main and logging thread : a shared variable is protected by mutex and thread is joined before shutdown.
  - [x] optimised macros : faster than functions, less overhead, cleaner code. Ability to timestamp, compared to inline functions.
  - [x] cleaned log buffers. Special characters appeared in logs when interpreting errno though no error was encountered.
  - [x] clean error macros : put errno as argument and/or don't interpret it when no error was encountered (i.e. errno = 0).
  - [x] resolved error mixing. Error logs are now coherently FIFO with accurate date and time.
  - [x] refactoring log macros : short and concise.
  - [x] corrected data disclosure : hash id was fully written to log. Now only the first n characters a are shown.
  - [x] Enhanced logging usability : Logging to stdout, directly to file, or to message queue.
  - [x] Introduced leveled verbosity of logging, set in parameters file.
  - [x] Logging: Added mode to completely disable logging after the command line parsing

- Compilation

  - [x] hardened compilation rules
  - [x] extreme compilation hardening
  - [x] Further hardened binary through compilation rules

- Security

  - [x] Automated Coding Style checks
  - [x] Automated checks with Sonar
  - [x] Automated checks with Flawfinder

### Priorities

Security Mechanisms

- check whether SO_PASSCRED credentials are verified by the kernel
- check SO_PEERSEC mechanism
- document about use of SCM_CREDENTIALS and SCM_SECURITY
- ucreds insertion in php socket : bypass php api macros and directly address underlying C socket

Socket configuratation

- See other* socket options

General

- Add a set of mandatory minimal arguments
- When creds authentication is requested, set a flag at argument parsing and checked every time things related to it are done, to avoid going through functions for nothing

1) change ctx->socket to non-pointer ?
2) Create socket under a dedicated, secured directory
3) Handle SIGPIPE signal : https://blog.erratasec.com/2018/10/tcpip-sockets-and-sigpipe.html#.XMCGx-gzaUk
4) Fallback mechanism if libbsd is not available
5) refactor code for socket to be used as component/library
6) add examples and copy/pastable code
7) Discuss use of SGX

#### Logging

1) add '-q / --quiet' argument to be completely silent on prompt : parse whole arguments first to look for that one
1) When not cleanly shut down, the logging thread/process continues and holds the lock on the log file, further attempts to open are blocked. lslocks CL helps identifying.
1) Ensure logs are syslog compliant, and add other logging formats.
1) add mode to log everything to stdout
1) separate logging macros from code for thread with mq, to enable genericity
1) Add a parameter for log file size, to keep log files at a maximum size, and then log into different file with timestamp
1) Compress old log files
1) ability to send logs to a socket or network address

### Todo

- Graceful stop via signal handling from outside : take care of threads etc.
- check logging for snprintf return value

Compilation

- benchmark performance differences between -fstack-protector-strong and -fstack-protector-all
- Explore necessity of always_inline'ing functions
- check which option of fsanitize is better suited : adress, thread or leak ?
- gcc options not recognised, why ? -fsanitize=cfi, fsanitize-address-use-after-scope, fstack-clash-protection, -fcf-protection=full
- check if these are useful : -fsanitize-coverage=trace-pc-guard
- Lookup what -D_POSIX_C_SOURCE=200112L is

### Later

- get log writing non-blocking
- Check why aio writes do not work
- Signal handling. Protect against all signal and keep unavoidable for shutdown.
- Check/analyse for eventual memory leaks (valgrind)

### Notes

- compilation flag D_GNU_SOURCE (glibc manual) : "everything is included: ISO C89, ISO C99, POSIX.1, POSIX.2, BSD, SVID, X/Open, LFS, and GNU extensions."