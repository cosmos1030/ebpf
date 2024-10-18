# Base image
FROM ubuntu:latest

# Install essential packages
RUN apt update && apt install -y \
    clang llvm \ 
    bpfcc-tools linux-headers-$(uname -r) \ 
    libbpfcc libbpf-dev \ 
    python3-pyroute2 python3-psutil \ 
    iproute2 \ 
    && apt clean

# Set the working directory
WORKDIR /mnt/ebpf

# Set the default command (keep the container running)
CMD ["tail", "-f", "/dev/null"]
