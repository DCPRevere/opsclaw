# sim/target.Dockerfile — the "real target" that Tier 2 fault scenarios are
# injected into. Runs under gVisor (--runtime=runsc, see sim/run.sh) so it is
# a genuinely sandboxed target, not a bare container: this is what makes
# mount-scepticism (df lying over gVisor bind mounts, DESIGN.md §3 "Agent
# loop") a real, reproducible fault instead of a mocked one.
#
# Deliberately NOT multi-stage and NOT slim: this image needs a realistic
# process/service surface (sshd, a couple of fake long-running services,
# stress-ng, systemd-less service supervision) for scenarios to fault.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        stress-ng \
        openssh-server \
        procps \
        coreutils \
        util-linux \
        iproute2 \
        net-tools \
        curl \
        ca-certificates \
        supervisor \
        rsyslog \
        gawk \
        sed \
        socat \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# --- sshd -------------------------------------------------------------
# The daemon reaches the target over ssh (targets/ssh executor, DESIGN.md
# §4). Host keys generated at container start (entrypoint), not baked in.
RUN mkdir -p /var/run/sshd /root/.ssh \
    && sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
    && echo "root:$(openssl rand -base64 32 2>/dev/null || echo locked)" | chpasswd -e 2>/dev/null || true

# Authorized key is injected at container start from a path the orchestrator
# bind-mounts in (see sim/run.sh) so each run gets a fresh keypair rather
# than a key baked into the image.
RUN touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys

# --- fake services ------------------------------------------------------
# A couple of always-on services scenarios can stop/flap/starve, supervised
# by supervisord (no real systemd inside a container; this is the
# "systemd-or-a-sysvinit-shim" — supervisord fills that role portably under
# gVisor where systemd's cgroup/dbus assumptions don't hold).
RUN mkdir -p /var/log/opsclaw-sim /opt/fake-services

COPY sim/fixtures/fake-worker.sh /opt/fake-services/fake-worker.sh
COPY sim/fixtures/fake-web.sh /opt/fake-services/fake-web.sh
COPY sim/fixtures/log-emitter.sh /opt/fake-services/log-emitter.sh
COPY sim/fixtures/supervisord.conf /etc/supervisor/conf.d/opsclaw-sim.conf
COPY sim/fixtures/entrypoint.sh /entrypoint.sh
RUN chmod +x /opt/fake-services/*.sh /entrypoint.sh

# Mount point for scenarios that fill a disk (disk-fill, mount-scepticism).
# This is JUST the mount point — run.sh mounts a size-capped tmpfs over it
# (`--tmpfs /data:size=200m`) at container start. That cap is load-bearing:
# without it, `df /data` inside the overlay container reports the HOST root
# fs's free space, and disk-fill (which fills "90% of available") would
# allocate ~90% of the whole host disk. Do NOT rely on this bare mkdir to
# bound anything — the size lives in run.sh (SIM_DATA_SIZE).
RUN mkdir -p /data && chmod 777 /data

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
