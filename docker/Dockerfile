# ---------------------------------------------------------
# Stage 1: Build the Rust application
# ---------------------------------------------------------
FROM ubuntu:20.04 AS builder

# Set environment variables for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies for Rust and any additional tools needed at build-time
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \ 
    git \
    wget \
    curl \
    software-properties-common \
    corosync \    
    libcpg-dev \
    libquorum-dev \
    libvotequorum-dev \
    libcfg-dev \ 
    libcmap-dev \
    libcorosync-common-dev \
    && apt-get clean

# Install Rust (cargo and rustc)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set up a working directory for building the Rust application
WORKDIR /app

# Copy your Rust files (Cargo.toml, Cargo.lock, src/)
COPY ../Cargo.toml .
COPY ../src ./src

RUN cargo build --release
RUN cargo build --bin issue_ed25519_credential --release


# ---------------------------------------------------------
# Stage 2: Final runtime environment
# ---------------------------------------------------------
FROM ubuntu:20.04

# Set environment variables for non-interactive installations
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root


ARG NODE_NAME
ARG NODE_IP
ARG NODE_ID
ENV NODE_NAME=$NODE_NAME
ENV NODE_IP=$NODE_IP
ENV NODE_ID=$NODE_ID
ENV RUST_LOG=debug 

# Install only the packages needed at runtime
RUN apt-get update && apt-get install -y \
    iputils-ping \
    iproute2 \
    iperf \
    iperf3 \
    mgen \
    corosync \
    nano \
    sudo \ 
    && apt-get clean

# Corosync setup
COPY ./corosync.conf /etc/corosync/corosync.conf.template

# Copy config files 
COPY ./config.toml /root/valkyrie-mls/config.toml

# Copy the MGEN config file
COPY ../test-results/test.mgn /root/valkyrie-mls/test.mgn

# Replace placeholders in the Corosync config
RUN sed "s/{{NODE_IP}}/$NODE_IP/" /etc/corosync/corosync.conf.template > /etc/corosync/corosync.conf

# Expose Corosync ports
EXPOSE 5404/udp 5405/udp

# Copy the entrypoint script
COPY docker/entrypoint.sh /root/valkyrie-mls/entrypoint.sh
RUN chmod +x /root/valkyrie-mls/entrypoint.sh

# Copy the compiled Rust binary from the builder stage
# (Adjust the path and binary name if your actual target differs)
COPY --from=builder /app/target/debug/valkyrie-mls /root/valkyrie-mls/valkyrie-mls

# Set the entrypoint to the script
ENTRYPOINT ["/root/valkyrie-mls/entrypoint.sh"]

# Default command if no arguments are provided
CMD ["bash"]