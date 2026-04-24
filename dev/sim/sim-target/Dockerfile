FROM ubuntu:22.04@sha256:c7eb020043d8fc2ae0793fb35a37bff1cf33f156d4d4b12ccc7f3ef8706c38b1

ENV DEBIAN_FRONTEND=noninteractive

# stress-ng for memory/cpu pressure, iproute2 for tc netem (needs NET_ADMIN),
# coreutils for dd, util-linux for fallocate. The other packages mirror what
# a real Ubuntu host carries so the agent's tools (top, ps, ss, journalctl)
# all behave normally and report kernel-mediated state, not lies.
RUN apt-get update && apt-get install -y \
    openssh-server \
    procps \
    iproute2 \
    net-tools \
    sysstat \
    stress-ng \
    coreutils \
    util-linux \
    iptables \
    python3 \
    ncat \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /run/sshd

# Create the opsclaw user with sudo-free access.
RUN useradd -m -s /bin/bash opsclaw \
    && mkdir -p /home/opsclaw/.ssh \
    && chmod 700 /home/opsclaw/.ssh \
    && chown -R opsclaw:opsclaw /home/opsclaw/.ssh

# Scenarios are armed/disarmed via `docker exec` from sim.sh. Storage for
# disk-pressure scenarios goes under /data — backed by a tmpfs in compose
# so dd-fills disappear on container restart and never touch the host.
RUN mkdir -p /data && chmod 755 /data

# "myapp" sentinel service. Minimal HTTP server that binds 8080 and
# logs to /var/log/myapp.log, started at boot by entrypoint. Scenarios
# kill/stop/DROP this to simulate a service fault.
RUN mkdir -p /opt/myapp /var/log && chmod 755 /var/log
COPY myapp.py /opt/myapp/myapp.py
RUN chmod +x /opt/myapp/myapp.py

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
