# ---------- Build Stage ----------
    FROM rust:1.75 as builder

    # Create app directory
    WORKDIR /app
    
    # Copy manifests
    COPY ../Cargo.toml .
    COPY ../Cargo.lock .
    
    # Pre-build to cache dependencies
    RUN mkdir src && echo "fn main() {}" > src/main.rs
    RUN cargo build --release
    RUN rm -r src
    
    # Copy real source and rebuild
    COPY ../src ./src
    RUN cargo build --release
    
    # ---------- Runtime Stage ----------
    FROM ubuntu:22.04
    
    # Set environment variables
    ENV DEBIAN_FRONTEND=noninteractive
    ARG NODE_NAME
    ARG NODE_IP
    ENV NODE_NAME=$NODE_NAME
    ENV NODE_IP=$NODE_IP
    
    # Install only what’s needed at runtime
    RUN apt-get update && apt-get install -y \
        iputils-ping \
        iproute2 \
        corosync \
        libcpg-dev \
        libquorum-dev \
        libvotequorum-dev \
        libcfg-dev \
        libcmap-dev \
        libcorosync-common-dev \
        nano && \
        apt-get clean && rm -rf /var/lib/apt/lists/*
    
    # Set working dir
    WORKDIR /app
    
    # Copy just the compiled binary from the builder
    COPY --from=builder /app/target/release/valkyrie-mls .
    
    # Corosync config
    COPY docker/corosync.conf /etc/corosync/corosync.conf.template
    RUN sed "s/{{NODE_IP}}/$NODE_IP/" /etc/corosync/corosync.conf.template > /etc/corosync/corosync.conf
    
    # Entrypoint
    COPY docker/entrypoint.sh /entrypoint.sh
    RUN chmod +x /entrypoint.sh
    
    EXPOSE 5404/udp 5405/udp
    
    ENTRYPOINT ["/entrypoint.sh"]
    CMD ["bash"]
    