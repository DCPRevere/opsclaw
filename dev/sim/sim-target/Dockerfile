FROM ubuntu:22.04@sha256:c7eb020043d8fc2ae0793fb35a37bff1cf33f156d4d4b12ccc7f3ef8706c38b1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    procps \
    iproute2 \
    net-tools \
    sysstat \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /run/sshd

# Create the opsclaw user with sudo-free access
RUN useradd -m -s /bin/bash opsclaw \
    && mkdir -p /home/opsclaw/.ssh \
    && chmod 700 /home/opsclaw/.ssh \
    && chown -R opsclaw:opsclaw /home/opsclaw/.ssh

# Create the simulation directory (scenarios mounted via docker-compose)
RUN mkdir -p /sim/scenarios && chmod -R 777 /sim

# Install command wrappers (higher priority than /usr/bin via PATH)
COPY bin/ /usr/local/bin/
RUN chmod +x /usr/local/bin/free /usr/local/bin/df /usr/local/bin/uptime \
    /usr/local/bin/docker /usr/local/bin/ss /usr/local/bin/systemctl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
