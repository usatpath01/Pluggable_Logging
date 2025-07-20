#!/bin/bash

# Build script for XPLOG Agent
# This script handles vmlinux.h generation and compilation

set -e

echo "Building XPLOG Agent..."

# Get architecture
ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX_PATH="libbpf-bootstrap/vmlinux/${ARCH}/vmlinux.h"

# Check if vmlinux.h exists, generate if not
if [ ! -f "$VMLINUX_PATH" ]; then
    echo "Generating vmlinux.h for architecture: $ARCH"
    
    # Create directory if it doesn't exist
    mkdir -p "libbpf-bootstrap/vmlinux/${ARCH}"
    
    # Check if bpftool exists, build if not
    if [ ! -f "libbpf-bootstrap/bpftool/src/bpftool" ]; then
        echo "Building bpftool..."
        cd libbpf-bootstrap/bpftool/src
        make bootstrap
        cd ../../..
    fi
    
    # Generate vmlinux.h
    echo "Extracting kernel headers..."
    ./libbpf-bootstrap/bpftool/src/bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_PATH"
    echo "vmlinux.h generated successfully"
else
    echo "vmlinux.h already exists for architecture: $ARCH"
fi

# Build the project
echo "Compiling XPLOG Agent..."
cd src
sudo make clean
sudo make

echo "Build completed successfully!"
echo "Binary location: ../bin/xlp" 