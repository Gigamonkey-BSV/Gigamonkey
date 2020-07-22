FROM ubuntu:18.04
LABEL maintainer="Katrina Knight <kat.knight@newgaea.net>"

ARG APT_MIRROR_URL
ARG BUILD_JOBS=1

COPY update_apt_sources.sh /tmp
RUN /tmp/update_apt_sources.sh

# Install build dependencies
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    autotools-dev \
    bsdmainutils \
    build-essential \
    cmake \
    curl \
    git \
    libconfig++-dev \
    libcurl4-openssl-dev \
    libgmp-dev \
    libntl-dev \
    libgoogle-glog-dev \
    libhiredis-dev \
    libmysqlclient-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    libzmq3-dev \
    libzookeeper-mt-dev \
    libevent-dev \
    libdb-dev \
    libdb++-dev \
    openssl \
    python3 \
    python3-dev \
    pkg-config \
    protobuf-compiler \
    wget \
    yasm \
    crypto++ \
    zlib1g-dev \
    libmongoc-1.0-0 \
    libbson-1.0 \
    && apt-get autoremove && apt-get clean q&& rm -rf /var/lib/apt/lists/*

# Build Boost
RUN mkdir -p /tmp/boost && cd /tmp/boost && wget https://dl.bintray.com/boostorg/release/1.72.0/source/boost_1_72_0.tar.gz  && \
    [ $(sha256sum boost_1_72_0.tar.gz | cut -d " " -f 1) = "c66e88d5786f2ca4dbebb14e06b566fb642a1a6947ad8cc9091f9f445134143f" ] && \
    tar xzf boost_1_72_0.tar.gz --strip 1 && rm boost_1_72_0.tar.gz
RUN cd /tmp/boost && ./bootstrap.sh --prefix=/usr/bsv/ --with-python-version=3.6
RUN cd /tmp/boost && ./b2 install
RUN ldconfig
ENV PKG_CONFIG_PATH=/usr/bsv/lib/pkgconfig/

# Build ctre
RUN mkdir -p /tmp/ctre && cd /tmp/ctre && wget https://github.com/hanickadot/compile-time-regular-expressions/archive/v2.8.3.tar.gz && \
    [ $(sha256sum v2.8.3.tar.gz | cut -d " " -f 1) = "5833a9d0fbce39ee39bd6e29df2f7fcafc82e41c373e8675ed0774bcf76fdc7a" ] && \
    tar xvf v2.8.3.tar.gz --strip 1 && rm v2.8.3.tar.gz
RUN mkdir -p /tmp/ctre/build && cd /tmp/ctre/build && cmake -DCMAKE_INSTALL_PREFIX=/usr/bsv/ /tmp/ctre/ && make && make install
# Build JSON
RUN mkdir -p /tmp/json && cd /tmp/json && wget https://github.com/nlohmann/json/archive/v3.8.0.tar.gz && \
    [ $(sha256sum v3.8.0.tar.gz | cut -d " " -f 1) = "7d0edf65f2ac7390af5e5a0b323b31202a6c11d744a74b588dc30f5a8c9865ba" ] && \
    tar xvf v3.8.0.tar.gz --strip 1 && rm v3.8.0.tar.gz
RUN mkdir -p /tmp/json/build && cd /tmp/json/build && cmake -DCMAKE_INSTALL_PREFIX=/usr/bsv/ /tmp/json/ && make && make install
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10
RUN update-alternatives --set python /usr/bin/python3
RUN ldconfig

COPY . /tmp/gigamonkey
RUN git clone https://github.com/bitcoin-sv/bitcoin-sv/ /tmp/bitcoin-sv
RUN mkdir -p /tmp/build && cd /tmp/build && cmake \
        -DJOBS=${BUILD_JOBS} \
        -DBOOST_ROOT=/usr/bsv/ \
        -DCHAIN_SRC_ROOT=/tmp/bitcoin-sv \
        -DCHAIN_EXTRA_FLAGS=--with-boost=/usr/bsv \
        -DCMAKE_INSTALL_PREFIX=/usr/bsv/ \
        -DCMAKE_PREFIX_PATH=/usr/bsv/ \
        /tmp/gigamonkey

RUN cd /tmp/build && make

CMD /tmp/build/test/testGigamonkey