# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

# Base image to run rust
FROM ubuntu:xenial

RUN apt-get update \
 && apt-get install -y -q --allow-downgrades \
    build-essential \
    curl \
    libssl-dev \
    gcc \
    libzmq3-dev \
    openssl \
    pkg-config \
    unzip \
    git \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN \
 if [ ! -z $HTTP_PROXY ] && [ -z $http_proxy ]; then \
  http_proxy=$HTTP_PROXY; \
 fi; \
 if [ ! -z $HTTPS_PROXY ] && [ -z $https_proxy ]; then \
  https_proxy=$HTTPS_PROXY; \
 fi; \
 if [ ! -z $http_proxy ]; then \
  http_proxy_host=$(printf $http_proxy | sed 's|http.*://\(.*\):\(.*\)$|\1|');\
  http_proxy_port=$(printf $http_proxy | sed 's|http.*://\(.*\):\(.*\)$|\2|');\
  mkdir -p $HOME/.cargo \
  && echo "[http]" >> $HOME/.cargo/config \
  && echo 'proxy = "'$http_proxy_host:$http_proxy_port'"' >> $HOME/.cargo/config \
  && cat $HOME/.cargo/config; \
 fi;

RUN curl https://sh.rustup.rs -sSf > /usr/bin/rustup-init \
 && chmod +x /usr/bin/rustup-init \
 && rustup-init -y

ENV PATH=$PATH:/root/.cargo/bin \
    CARGO_INCREMENTAL=0

RUN rustup component add rustfmt-preview

# Note: IAS Proxy makes use of IAS Client library functions
RUN mkdir -p /project/ias_client
RUN mkdir -p /project/ias_proxy

# TODO: Create a debian package of this build and install
WORKDIR /project/
COPY src/ias_client/ ./ias_client/
WORKDIR /project/ias_client/

RUN cargo build

WORKDIR /project/
COPY src/ias_proxy/ ./ias_proxy/
WORKDIR /project/ias_proxy/
RUN cargo build

ENV PATH=$PATH:/project/ias_proxy/target/debug
CMD bash -C "ias_proxy"