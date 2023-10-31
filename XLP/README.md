# XLP : eXpress Logging for Multi-level Provenance of Distributed Applications

A collection of eBPF programs for tracing system calls, enriching them with container distinguishing information and logging them along with logging similarly enriched application logs (by keeping track of `write` calls made to write logs) into a single universal log file.

## Docker Image
The docker image of XLP is available at Docker Hub: https://hub.docker.com/repository/docker/anon98484/xlp/general. Run the following command to pull the image:
```
docker pull anon98484/xlp:latest
```
The command for running its container is given in a later section.

## Build Requirements
If you wish to build the binaries from scratch, your system must satisfy the following requirements:
### Libraries/Applications
- `libbelf`
- `zlib`
- `clang`
- `docker`

> The `bin` directory contains a pre-built BPF binary. The build configuration used was:
>- `libelf 0.176-1.1`
>- `zlib 1.2.11`
>- `clang 10.0.0`
>
>If you wish to use this pre-built binary, the first 3 libraries need not be installed in your system.

The `Dockerfile` builds the userspace frontend object file and uses the BPF binary and library files in the `bin` directory to build the final binary that is run.

### Kernel
- `CONFIG_DEBUG_INFO_BTF=y`
- Linux Kernel Version 5.8+

### Architecture
- x86-64

## How to Build from Scratch
### Cloning the repo
1. Run the following command on your shell to clone this repository:
```
git clone https://anonymous.4open.science/r/XLP-11AE
```
2. Run the following command to clone the submodules of the  `libbpf-bootstrap` repo.
```
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```
### Building the BPF Binary
1. Run the following command to build the `libbpf` library, `bpftool` and the BPF binary.
```
make
```
### Building the Docker Image
1. Make sure all the `.c` files, the `.h` files, `xlp.mk` and the `bin/` directory with the BPF binary, `libbpf` and `bpftool` libraries are present in the directory containing the Dockerfile.
2. Run the following command (as root user) on your shell to build the Docker image
```
docker build -t xlp .
```
### Running the XLP container
1. Run the following command (as root user) on your shell to run the XLP tool as a Docker container.
```
docker run --rm -it --name xlp \
--privileged --pid=host --cgroupns=host \
-v /boot/config-$(uname -r):/boot/config-$(uname -r):ro \
-v /sys/kernel/debug/:/sys/kernel/debug/ \
xlp
```
> Note: If you are using the image pulled from Docker Hub use the image name : `anon98484/xlp`
2. Run the microservices/serverless architecture to be logged.

### Running the performace evaluation scripts
1. Start the XLP container for logging.
2. Start the Cinema-Go-Microservices application from the `test/cinema` directory, by running `docker compose up`
3. Run the script `test/scripts/cinema/run.sh` for making requests to the application.
4. The execution times are stored in the `test/cinema/benchmarking` directory. Run the script `test/scripts/cinema/calc.py` to generate the resulting data.
5. The steps can be performed with Tracee as the logging architecture, and the results can be compared.

## Configurations
- `-s <syscall_1>,<syscall_2>,... or --system_call=<syscall_1>,<syscall_2>,...` : Provide the system calls to be traced as a comma separated list. By default, XLP traces all its supported system calls.
- `-c or --filter_container` : Only print logs from processes running inside containers.
> Note: All our testing and results were obtained with the `-c` flag, with tracing enabled for all system calls.
- Make sure that the application logs printed by your microservice/functions are written to `stdout` or `stderr` or a file in `/var/log/app/`.

## Files and Directories
- `bin/`: Contains all the necessary library binaries, BPF object file and the userspace frontend object file compiled by the Makefile from libbpf-bootstrap.
- `bin/xlp.skel.h`: Skeleton eBPF header file generated from `xlp.skel.h`. Describes the structure of the ELF binary of the eBPF program. Declares wrapper functions for the `xlp` app over the libbpf functions for loading, attaching, etc. of the eBPF program
- `logs/` : Contains the logs from our evaluation on both a simple Go container and full-fledged Cinema-Go-Microservices application.
- `test/cinema` : Contains the source code for the Cinema-Go-Micorservices application that was used for benchmarking.
- `test/simple-go` : Contains the source code for the simple Go containerized application that was used for correctness and log-richness evaluation.
- `test/scripts/cinema` : Contains the scripts that were used for testing and generating the results.
- `data` : Contains performance evaluation results in TSV files, were used for generating the plots with `gnuplot`.
- `xlp.bpf.c`: The eBPF program logic, written in C using libbpf C CO-RE
- `xlp.c`: The frontend of the eBPF program. Contains the code for opening, loading, attaching of the eBPF program to the right hooks. Also contains the logic for handling of the various syscall log + application log events. Writes to the log file.
- `xlp.h`, `util.h`, `syscall.h`, `filesystem.h` and `buffer.h`: Useful user-defined structs and helper functions.