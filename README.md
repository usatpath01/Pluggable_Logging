# XPLOG : A Dynamic Observability Framework for Distributed Edge Applications

A scalable, pluggable, easily deployable, and dynamic runtime observability framework for distributed edge computing platforms that leverages the capability of extended Berkeley Packet Filters (eBPF) to intercept system-level events within the host while capturing and amalgamating relevant ap-
plication and system logs to produce globally causally-consistent log stream.

The XPLOG as 2 components: `XPLOG Agent` and `XPLOG Collector`

```
Pluggable_Logging
├── XPLOG Agent
└── XPLOG Collector
```
## System Configuration:
- Ubuntu 22.04
- Linux 6.5.0-41-generic
- x86-64
- Number of vCPU cores = 16
- RAM = 64 GB
- HDD Size = 500GB (Manager), 250GB (Workers)

## Kernel
- `CONFIG_DEBUG_INFO_BTF=y`
- Linux Kernel Version 5.8+

## Build Requirements
If you wish to build the binaries from scratch, your system must satisfy the following requirements:
- `Docker`
- `Docker-compose`
- `libbelf`
- `zlib`
- `clang`
- `docker`

To install the packages run the following commands in ```Ubuntu```.
```
sudo apt install libelf-dev
sudo apt-get install libpcap-dev
sudo apt install clang
sudo apt install binutils-dev
sudo apt install llvm
```

## Build XPLOG from source
1. Run the following command on your shell to clone this repository:
```
git clone https://github.com/usatpath01/Pluggable_Logging.git
```
Go to XPLOG_Agent Folder

2. Run the following command to clone the submodules of the `libbpf-bootstrap` repo.
```
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```

### Building the BPF Binary
1. Run the following command to build the `libbpf` library, `bpftool`, and the BPF binary.
```
cd XPLOG_Agent/libbpf-bootstrap/libbpf/src
make
cd XPLOG_Agent/libbpf-bootstrap/bpftool/src
make
```

### Building the XPLOG binary
Go to XPLOG_Agent > src folder and run
```
sudo make clean
sudo make
sudo make -f xlp.mk
```

## Running XPLOG
### Before you start
- Install Docker and Docker Compose
- Make sure the following ports are available: port 8086 for collector server.
- Configure Collector `serverIP` and `serverPort`: Go to Pluggable_Logging > XPLOG_Agent > src > xlp.c
```
const char *serverIP = "XXX.XX.XX.X";
const int serverPort = 8086;
```
### Start docker containers on single machine with ```docker-compose```
Start docker containers by running 
```
docker compose -f docker-compose.yml build 
docker compose -f docker-compose.yml up 
```

### Start docker containers with docker swarm
Before starting the containers, make sure:
1. You are on the Manager node of the docker swarm nodes.
2. You have cloned the Pluggable_Logging repository.
```
docker compose -f docker-compose-collector.yml build
docker compose -f docker-compose-collector.yml up -d
```

3. Once the collector server is up, run the XPLOG_Agent in each worker node where the microservice application containers run.
```
docker compose -f docker-compose-agent.yml build
docker compose -f docker-compose-agent.yml up
```

### To Test the logging framework with Application:
```
git clone https://github.com/usatpath01/DeathStarBench_XLP.git
sudo docker stack deploy --compose-file=docker-compose-swarm.yml dsb
```

### Running the Performance evaluation scripts
Please refer this:
[README.md](./scripts/README.md)


### Files and Directories
- `XPLOG_Agent/bin/`: Contains all the necessary library binaries, BPF object file and the userspace frontend object file compiled by the Makefile from libbpf-bootstrap.
- `XPLOG_Agent/bin/xlp.skel.h`: Skeleton eBPF header file generated from `xlp.skel.h`. Describes the structure of the ELF binary of the eBPF program. Declares wrapper functions for the `xlp` app over the libbpf functions for loading, attaching, etc. of the eBPF program
- `Logs/` : Contains the log files.
- `xlp.bpf.c`: The eBPF program logic, written in C using libbpf C CO-RE
- `xlp.c`: The frontend of the eBPF program. Contains the code for opening, loading, attaching of the eBPF program to the right hooks. Also contains the logic for handling of the various syscall log + application log events. Writes to the log file.
- `xlp.h`, `util.h`, `syscall.h`, `filesystem.h` and `buffer.h`: Useful user-defined structs and helper functions.
