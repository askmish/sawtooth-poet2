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
#!/bin/bash

if [ ! -z $HTTP_PROXY ] && [ -z $http_proxy ]; then http_proxy=$HTTP_PROXY; fi
if [ ! -z $HTTPS_PROXY ] && [ -z $https_proxy ]; then https_proxy=$HTTPS_PROXY; fi

if [ ! -z $http_proxy ]
then
    http_proxy_host=$(printf $http_proxy | sed 's|http.*://\(.*\):\(.*\)$|\1|')
    http_proxy_port=$(printf $http_proxy | sed 's|http.*://\(.*\):\(.*\)$|\2|')
    echo "Setting HTTP proxy to ($http_proxy_host, $http_proxy_port)"
fi
if [ ! -z $https_proxy ]
then
    https_proxy_host=$(printf $https_proxy | sed 's|http.*://\(.*\):\(.*\)$|\1|')
    https_proxy_port=$(printf $https_proxy | sed 's|http.*://\(.*\):\(.*\)$|\2|')
    echo "Setting HTTPS proxy to ($https_proxy_host, $https_proxy_port)"
fi

############# To Run this file
#    Make a directory 
#    Clone the repository for sawtooth-poet2
#          git clone <<git repo>>
#    Go to inside sawtooth-poet2 folder and run below
#          ./build.bash
######################################################
git clone -b master --single-branch https://github.com/hyperledger/sawtooth-core.git

docker-compose -f poet-intgr.yaml up 
