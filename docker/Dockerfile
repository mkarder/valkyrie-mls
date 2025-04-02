# This Dockerfile defines the basic container needed for a swarm node.
# This includes basic network tools (ping, tc, etc.), 
# Rust and Open MLS for MLS operations,
# as well as MGEN and C++ for message generation. 

# File: Dockerfile
FROM ubuntu:latest

# Set environment variables for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive
ARG NODE_NAME
ARG NODE_IP
ENV NODE_NAME=$NODE_NAME
ENV NODE_IP=$NODE_IP


# Install required tools and dependencies
RUN apt-get update && apt-get install -y \
    iputils-ping \
    iproute2 \
    build-essential \
    git \
    wget \
    curl \
    iperf3 \
    software-properties-common \
    corosync \    
    libcpg-dev \
    libquorum-dev \
    libvotequorum-dev \
    libcfg-dev \ 
    libcmap-dev \
    libcorosync-common-dev \	
    nano \
    && apt-get clean

###   Corosync   ###
# Copy configuration files
COPY docker/corosync.conf /etc/corosync/corosync.conf.template

# Replace placeholders in 'corosync.conf'
RUN sed "s/{{NODE_IP}}/$NODE_IP/" /etc/corosync/corosync.conf.template > /etc/corosync/corosync.conf

#Expose necessary ports
EXPOSE 5404/udp 5405/udp

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Clone and build MGEN with Protolib
#RUN git clone https://github.com/USNavalResearchLaboratory/mgen.git /opt/mgen \
#    && cd /opt/mgen \
#    && git submodule update --init \
#    && cd makefiles \
#    && make -f Makefile.linux \
#    && make -f Makefile.linux install \
#    && cd / \
#    && rm -rf /opt/mgen

# Set up Rust working directory 
WORKDIR /root

### RUST APP
#Copy Rust project
COPY ../src .
COPY ../Cargo.toml .

# Cleanup
RUN apt-get remove --purge -y software-properties-common && apt-get autoremove -y

# Copy the entrypoint script into the container
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh 

#Set the entrypoint to the script
ENTRYPOINT ["/entrypoint.sh"]

#Default command if no arguments are provided
CMD ["bash"]


