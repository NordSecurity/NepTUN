FROM debian:bookworm-slim
RUN apt-get update && apt-get install --no-install-recommends -y \
  iperf3 \
  iproute2 \
  iputils-ping \
  net-tools \
  wireguard-go \
  wireguard-tools \
  && rm -rf /var/lib/apt/lists/*
