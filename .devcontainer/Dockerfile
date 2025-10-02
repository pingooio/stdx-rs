FROM ubuntu:24.04

ENV TZ="UTC"
RUN echo "${TZ}" > /etc/timezone

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt upgrade -y
RUN apt-get install -y --no-install-recommends \
    # base system. psmisc for killall. openssh-client for git over SSH.
    bash curl wget psmisc ca-certificates lsb-release openssh-client \
    # dev tools. dnsutils for dig. linux-tools-generic for perf
    git vim make binutils coreutils build-essential pkg-config linux-tools-generic \
    zip htop wrk zstd gdb dnsutils jq b3sum gnupg libimage-exiftool-perl \
    # Rust toolchain
    rustup libfindbin-libs-perl lld mold gcc g++ musl musl-dev musl-tools libc6-dev cmake clang libclang-dev \
    openssl libssl-dev \
    # useful data. mailcap for mimetypes. tzdata for timezones.
    mailcap tzdata libpcre3-dev \
    sqlite3

# Setup dev user
ARG USERNAME=dev
ARG USER_UID=10001
ARG USER_GID=$USER_UID

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/home/${USERNAME}" \
    --shell "/bin/bash" \
    --uid "${USER_UID}" \
    "${USERNAME}"


USER $USERNAME

COPY --chown=$USERNAME bashrc /home/$USERNAME/.bashrc
COPY --chown=$USERNAME vimrc /home/$USERNAME/.vimrc

# setup git
RUN git config --global push.autoSetupRemote true
RUN git config --global init.defaultBranch main

WORKDIR /
