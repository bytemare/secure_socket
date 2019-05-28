# secure_socket



[![Build Status](https://travis-ci.com/bytemare/secure_socket.svg?branch=master)](https://travis-ci.com/bytemare/secure_socket)  
<!---
![Badges](https://img.shields.io/badge/It%20has%20so%20many-badges-success.svg)
--->

#### Quality
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=bytemare_secure_socket&metric=ncloc)](https://sonarcloud.io/dashboard?id=bytemare_secure_socket)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=bytemare_secure_socket&metric=security_rating)](https://sonarcloud.io/dashboard?id=bytemare_secure_socket)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=bytemare_secure_socket&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=bytemare_secure_socket)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=bytemare_secure_socket&metric=bugs)](https://sonarcloud.io/dashboard?id=bytemare_secure_socket)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bytemare_secure_socket&metric=alert_status)](https://sonarcloud.io/dashboard?id=bytemare_secure_socket)

#### Coverage

<a href="https://scan.coverity.com/projects/bytemare-secure_socket">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/18404/badge.svg"/>
</a>

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bytemare_secure_socket&metric=coverage)](https://sonarcloud.io/dashboard?id=bytemare_secure_socket)



## DRAFT

secure_socket aims to provide an easy way to set up and manage a socket in C with advanced security properties.
For example, it can be used as a broker to relay information or requests, shielding other clients (but not on data layer).
It is build for reliability and speed in mind.

Integrated, you'll also find an advanced logging mecanism, that will later be extracted as an individual project.

Among functional properties, you'll find :

- Single or multi-threaded server daemon
- UNIX socket for IPC

Choice is seemless and requires minimal effort.

Among security properties, you'll have :

- Advanced access protection on the socket
  - Lock down access to a single authorised unix user
  - Lock down access to a single authorised unix group
  - Lock down access to a single authorised system process (P2P)
- Dedicated, secured and locked down directory
- Abuse detection and prevention through advanced protection mechanisms integrated at compile time
- Use of BSD functions when needed to protect against known abuse of common un-protected functions
- **add rest**

Among logging properties, you'll benefit :

- Easy integration of a logging mecanism through macros
- Reduced performance overhead due to inlining, threaded logging and asynchronous writes
- Broad logging targets : choose between stdout, a message queue, files, or remote destination.
- Leveled verbosity on a scale of 0 (Fatal) to 10 (very verbose)
- Ability to pinpoint the file, function and line in your code where you want a log line to point to
- Set your desired log file size. When full, a new one is used and the old compressed.

## Use in development stage

You may not have certain used libraries, like libbsd, and should install libbsd-dev or

```bash
$(pkg-config --libs libbsd)
```

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

For now, no stopping procedure has been implemented, even though graceful soft-fail is implemented.
