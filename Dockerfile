# Base image
FROM ubuntu:latest

# Install essential packages, including SQLite3
RUN apt update && apt install -y \
    clang llvm \
    bpfcc-tools linux-headers-$(uname -r) \
    libbpfcc libbpf-dev \
    python3-pyroute2 python3-psutil \
    iproute2 sqlite3 \
    && apt clean

# Set the working directory
WORKDIR /mnt/ebpf

# Expose port if your application needs it (for example, 9999 in your server script)
EXPOSE 9999

# Set the default command (keep the container running)
CMD ["tail", "-f", "/dev/null"]
