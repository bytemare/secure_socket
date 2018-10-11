# Recent operated changes

### Done :

- [+] General clean-up.
- [+] [Sockets] Adaptive Sockets : depending on the need (unix or internet based communication) uses the **_correct_** type of socket (using an union on structs) and initialises it.
- [+] Detached Threads : no synchronisation needed once a thread is launched, so no joining is needed.
- [+] [Logging] Synchronised main and logging thread : a shared variable is protected by mutex and thread is joined before shutdown.
- [+] [Sockets] Added ability to set socket access rights. set_socket_owner_and_permissions() adds given group id to socket file and applies given permissions.
- [+] [Sockets] access restriction to socket based on peer username applying [current-user]:[peer_user] access rights to socket.
- [+] [Sockets] peer validation based on criteria. Given specified criteria (by pid, uid or gid), validates or not the connection peer : ipc_validate_peer() and ipc_options.
- [+] [Logging] optimised macros : faster than functions, less overhead, cleaner code. Ability to timestamp, compared to inline functions.
- [+] [Logging] cleaned log buffers. Special characters appeared in logs when interpreting errno though no error was encountered.
- [+] [Logging] clean error macros : put errno as argument and/or don't interpret it when no error was encountered (i.e. errno = 0).
- [+] ability to manage command line arguments : parsing, validating and adapt code to handle it : ipc_options.
- [+] [Logging] resolved error mixing. Error logs are now coherently FIFO with accurate date and time.
- [+] hardened compilation rules
- [+] extreme compilation hardening
- [+] [Logging] refactoring log macros : short and concise.
- [+] corrected a buffer overflow vulnerability : macro for maximal length of script name was wrong
- [+] use of strtol instead of atoi in context.c
- [+] [Logging] corrected data disclosure : hash id was fully written to log. Now only the first n caracters a are shown (see in commander.c)

### Doing :

- [>] ucreds insertion in php socket : bypass php api macros and directly address underlying C socket

### Todo :

- Create socket under a dedicated directory
- look for ordinary debug code and put it under DEBUG condition ( like printf )
- Graceful stop via signal handling from outside : take care of threads etc.
- Explore necessity of always_inline'ing functions

###### Later :

- get log writing non-blocking
- Check why aio writes do not work
- Signal handling. Protect against all signal and keep unavoidable for shutdown.
- Check/analyse for eventual memory leaks (valgrind)