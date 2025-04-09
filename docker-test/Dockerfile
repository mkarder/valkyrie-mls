FROM ubuntu:18.04

# Set noninteractive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

ARG NODE_NAME
ARG NODE_IP
ARG NODE_ID
ENV NODE_NAME=$NODE_NAME
ENV NODE_IP=$NODE_IP
ENV NODE_ID=$NODE_ID
ENV RUST_LOG=debug 

# Install Corosync 2.4.3 and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    software-properties-common \
    nano \
    sudo \ 
    iputils-ping \
    corosync \
    libcpg-dev \
    libquorum-dev \
    libvotequorum-dev \
    libcfg-dev \ 
    libcmap-dev \
    libcorosync-common-dev \
    && apt-get clean

# Expose Corosync ports
EXPOSE 5404/udp 5405/udp

# Default command if no arguments are provided
CMD ["bash"]
