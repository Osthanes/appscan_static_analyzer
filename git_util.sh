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

# uncomment the next line to debug this script
#set -x

# this script is not in Osthanes/utilities because then git would be needed to access it

# use this function to help avoid pipeline problems when accessing git repositories
git_retry() {
    local GIT_CALL="git $*"
    echo $GIT_CALL
    $GIT_CALL
    local GIT_RC=$?
    local GIT_RETRY_COUNT=0
    if [ -z "$GIT_RETRY" ]; then
        local GIT_RETRY=5
    fi
    while [[  $GIT_RETRY_COUNT -lt $GIT_RETRY && $GIT_RC -ne 0 ]]; do
        ((GIT_RETRY_COUNT++))
        echo -e "${label_color}git command failed; retrying in 30 seconds${no_color} ($GIT_RETRY_COUNT of $GIT_RETRY)"
        sleep 3
        echo $GIT_CALL
        $GIT_CALL
        GIT_RC=$?
    done

    if [ $GIT_RC -ne 0 ]; then
        echo -e "${red}git command failed: $GIT_CALL${no_color}" | tee -a "$ERROR_LOG_FILE"
    fi
}

#export function
export -f git_retry