FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        iperf3 \
        iproute2 \
        iputils-ping \
        net-tools \
        wireguard-tools \
        wireguard \
        git \
        wget \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Golang since 1.20+ is not in the aptitude
ENV GO_VERSION=1.24.2
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Build wireguard-go
RUN git clone https://github.com/WireGuard/wireguard-go && \
    cd wireguard-go && \
    go build -o /usr/bin/wireguard-go

