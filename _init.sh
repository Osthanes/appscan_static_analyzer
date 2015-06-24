#!/bin/bash

#********************************************************************************
# Copyright 2015 IBM
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#********************************************************************************

#############
# Colors    #
#############
export green='\e[0;32m'
export red='\e[0;31m'
export label_color='\e[0;33m'
export no_color='\e[0m' # No Color

##################################################
# Simple function to only run command if DEBUG=1 # 
##################################################
debugme() {
  [[ $DEBUG = 1 ]] && "$@" || :
}
export -f debugme 

set +e
set +x 

###############################
# Configure extension PATH    #
###############################
if [ -n $EXT_DIR ]; then 
    export PATH=$EXT_DIR:$PATH
fi 

################################
# Application Name and Version #
################################
# The build number for the builder is used for the version in the image tag 
# For deployers this information is stored in the $BUILD_SELECTOR variable and can be pulled out
if [ -z "$APPLICATION_VERSION" ]; then
    export SELECTED_BUILD=$(grep -Eo '[0-9]{1,100}' <<< "${BUILD_SELECTOR}")
    if [ -z $SELECTED_BUILD ]; then 
        if [ -z $BUILD_NUMBER ]; then 
            export APPLICATION_VERSION=$(date +%s)
        else 
            export APPLICATION_VERSION=$BUILD_NUMBER    
        fi
    else
        export APPLICATION_VERSION=$SELECTED_BUILD
    fi 
fi 

# install necessary features
debugme echo "installing bc"
sudo apt-get install bc >/dev/null 2>&1
debugme echo "installing 32 bit libs"
sudo apt-get install -y libc6-i386 lib32stdc++6 >/dev/null 2>&1
debugme echo "installing unzip"
sudo apt-get install -y unzip >/dev/null 2>&1
debugme echo "done installing prereqs"

if [ -n "$BUILD_OFFSET" ]; then 
    echo "Using BUILD_OFFSET of $BUILD_OFFSET"
    export APPLICATION_VERSION=$(echo "$APPLICATION_VERSION + $BUILD_OFFSET" | bc)
    export BUILD_NUMBER=$(echo "$BUILD_NUMBER + $BUILD_OFFSET" | bc)
fi 

echo "APPLICATION_VERSION: $APPLICATION_VERSION"

################################
# Setup archive information    #
################################
if [ -z $WORKSPACE ]; then 
    echo -e "${red}Please set WORKSPACE in the environment${no_color}"
    exit 1
fi 

if [ -z $ARCHIVE_DIR ]; then 
    echo "${label_color}ARCHIVE_DIR was not set, setting to WORKSPACE/archive ${no_color}"
    export ARCHIVE_DIR="${WORKSPACE}"
fi 

if [ -d $ARCHIVE_DIR ]; then
  echo "Archiving to $ARCHIVE_DIR"
else 
  echo "Creating archive directory $ARCHIVE_DIR"
  mkdir $ARCHIVE_DIR 
fi 
export LOG_DIR=$ARCHIVE_DIR


#############################
# Install Cloud Foundry CLI #
#############################
cf help &> /dev/null
RESULT=$?
if [ $RESULT -eq 0 ]; then
    # if already have an old version installed, save a pointer to it
    export OLDCF_LOCATION=`which cf`
fi
# get the newest version
echo "Installing Cloud Foundry CLI"
pushd . >/dev/null
cd $EXT_DIR 
curl --silent -o cf-linux-amd64.tgz -v -L https://cli.run.pivotal.io/stable?release=linux64-binary &>/dev/null 
gunzip cf-linux-amd64.tgz &> /dev/null
tar -xvf cf-linux-amd64.tar  &> /dev/null
cf help &> /dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
    echo -e "${red}Could not install the cloud foundry CLI ${no_color}"
    exit 1
fi  
popd >/dev/null
echo -e "${label_color}Successfully installed Cloud Foundry CLI ${no_color}"

##########################################
# setup bluemix env
##########################################
# attempt to  target env automatically
CF_API=`cf api`
if [ $? -eq 0 ]; then
    # find the bluemix api host
    export BLUEMIX_API_HOST=`echo $CF_API  | awk '{print $3}' | sed '0,/.*\/\//s///'`
    echo $BLUEMIX_API_HOST | grep 'stage1'
    if [ $? -eq 0 ]; then
        # on staging, make sure bm target is set for staging
        export BLUEMIX_TARGET="staging"
    else
        # on prod, make sure bm target is set for prod
        export BLUEMIX_TARGET="prod"
    fi
elif [ -n "$BLUEMIX_TARGET" ]; then
    # cf not setup yet, try manual setup
    if [ "$BLUEMIX_TARGET" == "staging" ]; then 
        echo -e "Targetting staging Bluemix"
        export BLUEMIX_API_HOST="api.stage1.ng.bluemix.net"
    elif [ "$BLUEMIX_TARGET" == "prod" ]; then 
        echo -e "Targetting production Bluemix"
        export BLUEMIX_API_HOST="api.ng.bluemix.net"
    else 
        echo -e "${red}Unknown Bluemix environment specified${no_color}" | tee -a "$ERROR_LOG_FILE"
    fi 
else 
    echo -e "Targetting production Bluemix"
    export BLUEMIX_API_HOST="api.ng.bluemix.net"
fi

################################
# Login to Container Service   #
################################
if [ -n "$BLUEMIX_USER" ] || [ ! -f ~/.cf/config.json ]; then
    # need to gather information from the environment 
    # Get the Bluemix user and password information 
    if [ -z "$BLUEMIX_USER" ]; then 
        echo -e "${red} Please set BLUEMIX_USER on environment ${no_color} "
        exit 1
    fi 
    if [ -z "$BLUEMIX_PASSWORD" ]; then 
        echo -e "${red} Please set BLUEMIX_PASSWORD as an environment property environment ${no_color} "
        exit 1
    fi 
    if [ -z "$BLUEMIX_ORG" ]; then 
        export BLUEMIX_ORG=$BLUEMIX_USER
        echo -e "${label_color} Using ${BLUEMIX_ORG} for Bluemix organization, please set BLUEMIX_ORG if on the environment if you wish to change this. ${no_color} "
    fi 
    if [ -z "$BLUEMIX_SPACE" ]; then
        export BLUEMIX_SPACE="dev"
        echo -e "${label_color} Using ${BLUEMIX_SPACE} for Bluemix space, please set BLUEMIX_SPACE if on the environment if you wish to change this. ${no_color} "
    fi 
    echo -e "${label_color}Targetting information.  Can be updated by setting environment variables${no_color}"
    echo "BLUEMIX_USER: ${BLUEMIX_USER}"
    echo "BLUEMIX_SPACE: ${BLUEMIX_SPACE}"
    echo "BLUEMIX_ORG: ${BLUEMIX_ORG}"
    echo "BLUEMIX_PASSWORD: xxxxx"
    echo ""
    echo -e "${label_color}Logging in to Bluemix using environment properties${no_color}"
    debugme echo "login command: cf login -a ${BLUEMIX_API_HOST} -u ${BLUEMIX_USER} -p XXXXX -o ${BLUEMIX_ORG} -s ${BLUEMIX_SPACE}"
    cf login -a ${BLUEMIX_API_HOST} -u ${BLUEMIX_USER} -p ${BLUEMIX_PASSWORD} -o ${BLUEMIX_ORG} -s ${BLUEMIX_SPACE} 2> /dev/null
    RESULT=$?
else 
    # we are already logged in.  Simply check via cf command 
    echo -e "${label_color}Logging into IBM Container Service using credentials passed from IBM DevOps Services ${no_color}"
    cf target >/dev/null 2>/dev/null
    RESULT=$?
    if [ ! $RESULT -eq 0 ]; then
        echo "cf target did not return successfully.  Login failed."
    fi 
fi 


# check login result 
if [ $RESULT -eq 1 ]; then
    echo -e "${red}Failed to login to IBM Bluemix${no_color}"
    exit $RESULT
else 
    echo -e "${green}Successfully logged into IBM Bluemix${no_color}"
fi 

# get the extensions utilities
pushd . >/dev/null
cd $EXT_DIR 
git clone https://github.com/Osthanes/utilities.git utilities
popd >/dev/null
# enable logging to logmet
source $EXT_DIR/utilities/logging_utils.sh
setup_met_logging "${BLUEMIX_USER}" "${BLUEMIX_PASSWORD}" "${BLUEMIX_SPACE}" "${BLUEMIX_ORG}" "${BLUEMIX_TARGET}"


###############
# setup appscan
###############
# appscan has different targets as well for bluemix staging vs prod
if [ -n "$BLUEMIX_TARGET" ]; then
    if [ "$BLUEMIX_TARGET" == "staging" ]; then 
        # staging
        export APPSCAN_ENV=https://appscan-test.bluemix.net
        #export APPSCAN_DOMAIN=https://appscan-test.bluemix.net
        export APPSCAN_OPTS=-DBLUEMIX_SERVER=https://appscan-test.bluemix.net
    elif [ "$BLUEMIX_TARGET" == "prod" ]; then 
        # prod
        export APPSCAN_ENV=https://appscan.ibmcloud.com
        #export APPSCAN_DOMAIN=https://appscan.ibmcloud.com
        export APPSCAN_OPTS=-DBLUEMIX_SERVER=https://appscan.ibmcloud.com
    else 
        # unknown, setup for prod
        export APPSCAN_ENV=https://appscan.ibmcloud.com
        #export APPSCAN_DOMAIN=https://appscan.ibmcloud.com
        export APPSCAN_OPTS=-DBLUEMIX_SERVER=https://appscan.ibmcloud.com
    fi 
else 
    # none set, set for prod
    export APPSCAN_ENV=https://appscan.ibmcloud.com
    #export APPSCAN_DOMAIN=https://appscan.ibmcloud.com
    export APPSCAN_OPTS=-DBLUEMIX_SERVER=https://appscan.ibmcloud.com
fi
# fetch the current version of utils
cur_dir=`pwd`
cd ${EXT_DIR}
wget ${APPSCAN_ENV}/api/BlueMix/StaticAnalyzer/SAClientUtil?os=linux -O SAClientUtil.zip -o /dev/null
unzip -o -qq SAClientUtil.zip &>/dev/null
if [ $? -eq 9 ]; then
    debugme echo "Unable to download SAClient, using local copy"
    unzip -o -qq SAClientLocal.zip
fi
cd `ls -d SAClient*/`
export APPSCAN_INSTALL_DIR=`pwd`
cd $cur_dir
export PATH=$APPSCAN_INSTALL_DIR/bin:$PATH
export LD_LIBRARY_PATH=$APPSCAN_NSTALL_DIR/bin:$LD_LIBRARY_PATH
debugme appscan.sh version

echo -e "${label_color}Initialization complete${no_color}"
