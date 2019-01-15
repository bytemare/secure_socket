# secure_socket

The secure_socket is a multi-threaded server daemon using a unix socket as IPC to communicate with a local client who desires to access certain protected scripts.

It can be used as an access-broker to relay information or requests, triggering things afterwards. It is build to be very fast, reliable, and tries to be as secure as possible in itself.


 
 Commands are send to the process through the socket, which are interpreted, and the result is sent back to the client.
 
 To compile the program, place yourself into the project directory and run :
 ```bash
./build.sh
```

to run the server with default parameters (found in `parameters.conf`), call the created launcher script
 ```bash
./run.sh 
```

script or launch the binary manually, with :

```bash
./build/secure_socket
```

for default parameters (found in `build.sh` script) or with whatever parameters you desire, e.g. :

```bash
./build/secure_socket socket_path=/tmp/sock_secure_socket mq_name=/secure_socket_MQ log_file=/home/secure_socket/log/secure_socket_logs domain=AF_UNIX protocol=SOCK_STREAM max_connections=200 socket_permissions=0770 authorised_peer_username=www-data
```

To automate running with your default values, insert them in the `parameters.conf` script with the others.

For more variables setting (like changing calls to scripts), you'll have to change ./include/vars.h and recompile the project.

For now, no stopping procedure has been implemented, even though graceful soft-fail is implemented.


## Security
- Creates a directory with write and search (execute) permissions to create the socket in
- Creates the socket with default read and write permissions for the caller and the peer
- The owner is by default the same as the caller, and group is set to be the destined authorised peer's real_gid
- These default values can be changed in the parameter file
- Peer commands are parsed and thoroughly checked against the predefined protocol to avoid overflows or command injections.
- The behaviour of the launched scripts is not controlled by the server, only the return code may be observed.
