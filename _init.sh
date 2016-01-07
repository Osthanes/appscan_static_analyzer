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

#########################################
# Configure log file to store errors  #
#########################################
if [ -z "$ERROR_LOG_FILE" ]; then
    ERROR_LOG_FILE="${EXT_DIR}/errors.log"
    export ERROR_LOG_FILE
fi

#################################
# Source git_util file          #
#################################
source ${EXT_DIR}/git_util.sh

################################
# get the extensions utilities #
################################
pushd . >/dev/null
cd $EXT_DIR 
git_retry clone https://github.com/Osthanes/utilities.git utilities
export PYTHONPATH=$EXT_DIR/utilities:$PYTHONPATH
popd >/dev/null

#################################
# Source utilities sh files     #
#################################
source ${EXT_DIR}/utilities/ice_utils.sh
source ${EXT_DIR}/utilities/logging_utils.sh


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
debugme echo "enabling i386 architechture"
sudo dpkg --add-architecture i386 
sudo apt-get update >/dev/null 2>&1
debugme echo "installing i386 java"
sudo apt-get install -y openjdk-7-jre:i386
debugme echo "installing bc"
sudo apt-get install -y bc >/dev/null 2>&1
debugme echo "installing 32 bit libs"
sudo apt-get install -y libc6-i386 lib32stdc++6 >/dev/null 2>&1
debugme echo "installing unzip"
sudo apt-get install -y unzip >/dev/null 2>&1
debugme echo "done installing prereqs"

if [ -n "$BUILD_OFFSET" ]; then 
    log_and_echo "$INFO" "Using BUILD_OFFSET of $BUILD_OFFSET"
    export APPLICATION_VERSION=$(echo "$APPLICATION_VERSION + $BUILD_OFFSET" | bc)
    export BUILD_NUMBER=$(echo "$BUILD_NUMBER + $BUILD_OFFSET" | bc)
fi 

log_and_echo "$INFO" "APPLICATION_VERSION: $APPLICATION_VERSION"

################################
# Setup archive information    #
################################
if [ -z $WORKSPACE ]; then 
    log_and_echo "$ERROR" "Please set WORKSPACE in the environment properties."
    ${EXT_DIR}/utilities/sendMessage.sh -l bad -m "Please set WORKSPACE in the environment properties."
    exit 1
fi 

if [ -z $ARCHIVE_DIR ]; then 
    log_and_echo "$LABEL" "ARCHIVE_DIR was not set, setting to WORKSPACE/archive."
    export ARCHIVE_DIR="${WORKSPACE}"
fi 

if [ -d $ARCHIVE_DIR ]; then
  log_and_echo "$INFO" "Archiving to $ARCHIVE_DIR"
else 
  log_and_echo "$INFO" "Creating archive directory $ARCHIVE_DIR"
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
log_and_echo "$INFO" "Installing Cloud Foundry CLI"
pushd . >/dev/null
cd $EXT_DIR 
curl --silent -o cf-linux-amd64.tgz -v -L https://cli.run.pivotal.io/stable?release=linux64-binary &>/dev/null 
gunzip cf-linux-amd64.tgz &> /dev/null
tar -xvf cf-linux-amd64.tar  &> /dev/null
cf help &> /dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
    log_and_echo "$ERROR" "Could not install the cloud foundry CLI"
    ${EXT_DIR}/utilities/sendMessage.sh -l bad -m "Could not install the cloud foundry CLI"
    exit 1
fi  
popd >/dev/null
log_and_echo "$SUCCESSFUL" "Successfully installed Cloud Foundry CLI"

##########################################
# setup bluemix env
##########################################
# attempt to  target env automatically
CF_API=$(${EXT_DIR}/cf api)
RESULT=$?
debugme echo "CF_API: ${CF_API}"
if [ $RESULT -eq 0 ]; then
    # find the bluemix api host
    export BLUEMIX_API_HOST=`echo $CF_API  | awk '{print $3}' | sed '0,/.*\/\//s///'`
    echo $BLUEMIX_API_HOST | grep 'stage1'
    if [ $? -eq 0 ]; then
        # on staging, make sure bm target is set for staging
        export BLUEMIX_TARGET="staging"
        export BLUEMIX_API_HOST="api.stage1.ng.bluemix.net"
    else
        # on prod, make sure bm target is set for prod
        export BLUEMIX_TARGET="prod"
        export BLUEMIX_API_HOST="api.ng.bluemix.net"
    fi
elif [ -n "$BLUEMIX_TARGET" ]; then
    # cf not setup yet, try manual setup
    if [ "$BLUEMIX_TARGET" == "staging" ]; then 
        log_and_echo "$INFO" "Targetting staging Bluemix"
        export BLUEMIX_API_HOST="api.stage1.ng.bluemix.net"
    elif [ "$BLUEMIX_TARGET" == "prod" ]; then 
        log_and_echo "$INFO" "Targetting production Bluemix"
        export BLUEMIX_API_HOST="api.ng.bluemix.net"
    else 
        log_and_echo "$INFO" "$ERROR" "Unknown Bluemix environment specified"
    fi 
else 
    log_and_echo "$INFO" "Targetting production Bluemix"
    export BLUEMIX_API_HOST="api.ng.bluemix.net"
fi

################################
# Login to Container Service   #
################################
if [ -n "$BLUEMIX_USER" ] || [ ! -f ~/.cf/config.json ]; then
    # need to gather information from the environment 
    # Get the Bluemix user and password information 
    if [ -z "$BLUEMIX_USER" ]; then 
        log_and_echo "$ERROR" "Please set BLUEMIX_USER on environment"
        ${EXT_DIR}/utilities/sendMessage.sh -l bad -m "Please set BLUEMIX_USER as an environment property"
        exit 1
    fi 
    if [ -z "$BLUEMIX_PASSWORD" ]; then 
        log_and_echo "$ERROR" "Please set BLUEMIX_PASSWORD as an environment property environment"
        ${EXT_DIR}/utilities/sendMessage.sh -l bad -m "Please set BLUEMIX_PASSWORD as an environment property"
        exit 1
    fi 
    if [ -z "$BLUEMIX_ORG" ]; then 
        export BLUEMIX_ORG=$BLUEMIX_USER
        log_and_echo "$LABEL" "Using ${BLUEMIX_ORG} for Bluemix organization, please set BLUEMIX_ORG if on the environment if you wish to change this."
    fi 
    if [ -z "$BLUEMIX_SPACE" ]; then
        export BLUEMIX_SPACE="dev"
        log_and_echo "$LABEL" "Using ${BLUEMIX_SPACE} for Bluemix space, please set BLUEMIX_SPACE if on the environment if you wish to change this."
    fi 
    log_and_echo "$LABEL" "Targetting information.  Can be updated by setting environment variables"
    log_and_echo "$INFO" "BLUEMIX_USER: ${BLUEMIX_USER}"
    log_and_echo "$INFO" "BLUEMIX_SPACE: ${BLUEMIX_SPACE}"
    log_and_echo "$INFO" "BLUEMIX_ORG: ${BLUEMIX_ORG}"
    log_and_echo "$INFO" "BLUEMIX_PASSWORD: xxxxx"
    echo ""
    log_and_echo "$LABEL" "Logging in to Bluemix using environment properties"
    debugme echo "login command: cf login -a ${BLUEMIX_API_HOST} -u ${BLUEMIX_USER} -p XXXXX -o ${BLUEMIX_ORG} -s ${BLUEMIX_SPACE}"
    cf login -a ${BLUEMIX_API_HOST} -u ${BLUEMIX_USER} -p ${BLUEMIX_PASSWORD} -o ${BLUEMIX_ORG} -s ${BLUEMIX_SPACE} 2> /dev/null
    RESULT=$?
else 
    # we are already logged in.  Simply check via cf command 
    log_and_echo "$LABEL" "Logging into IBM Container Service using credentials passed from IBM DevOps Services"
    cf target >/dev/null 2>/dev/null
    RESULT=$?
    if [ ! $RESULT -eq 0 ]; then
        log_and_echo "$INFO" "cf target did not return successfully.  Login failed."
    fi 
fi 

# check login result 
if [ $RESULT -eq 1 ]; then
    log_and_echo "$ERROR" "Failed to login to IBM Bluemix"
    ${EXT_DIR}/utilities/sendMessage.sh -l bad -m "Failed to login to IBM Bluemix"
    exit $RESULT
else 
    log_and_echo "$SUCCESSFUL" "Successfully logged into IBM Bluemix"
fi 

log_and_echo "$INFO" "BLUEMIX_API_HOST: ${BLUEMIX_API_HOST}"
log_and_echo "$INFO" "BLUEMIX_TARGET: ${BLUEMIX_TARGET}"

########################
# get BLUEMIX_USER     #
########################
if [ -z "$BLUEMIX_USER" ]; then
    # set targeting information from config.json file
    if [ -f ~/.cf/config.json ]; then
        debugme echo $(cat ~/.cf/config.json)
        get_targeting_info
    fi
fi

############################
# enable logging to logmet #
############################
setup_met_logging "${BLUEMIX_USER}" "${BLUEMIX_PASSWORD}"
RESULT=$?
if [ $RESULT -ne 0 ]; then
    log_and_echo "$WARN" "LOGMET setup failed with return code ${RESULT}"
fi

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

############################
# enable DRA               #
############################
source $EXT_DIR/utilities/dra_utils.sh
export DRA_ENABLED=1
export CRITERIAL_NAME="appscan_criterial"
setup_dra "${CRITERIAL_NAME}"
RESULT=$?
if [ $RESULT -eq 0 ]; then
    log_and_echo "Successfully Setup DRA for criterial name '${CRITERIAL_NAME}'."
elif [ $RESULT -gt 1 ]; then
    log_and_echo "$WARN" "Failed to setup DRA for criterial name '${CRITERIAL_NAME}'."
fi

log_and_echo "$LABEL" "Initialization complete"
