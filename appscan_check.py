#!/usr/bin/python

#***************************************************************************
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
#***************************************************************************

import json
import os
import sys
from subprocess import call, Popen, PIPE

STATIC_ANALYSIS_SERVICE='Static Analyzer'
DEFAULT_SERVICE=STATIC_ANALYSIS_SERVICE


def getCredentialsFromBoundApp (service=DEFAULT_SERVICE, binding_app=None):
    # if no binding app parm passed, try to get it from env
    if binding_app == None:
        binding_app = os.environ.get('BINDING_APP')
    # if still no parm, can't continue, fail out
    if binding_app == None:
        raise Exception("BINDING_APP is not set - this must be set to get the proper credentials.")

    # try to read the env vars off the bound app in cloud foundry, the one we
    # care about is "VCAP_SERVICES"
    verProc = Popen(["cf env \"" + binding_app + "\""], shell=True, 
                    stdout=PIPE, stderr=PIPE)
    verOut, verErr = verProc.communicate();

    if verProc.returncode != 0:
        raise Exception("Unable to read env vars off BINDING_APP - please check that it is set correctly.")

    envList = []
    envIndex = 0
    inSection = False
    # the cf env var data comes back in the form
    # blah blah blah
    # {
    #    <some json data for a var>
    # }
    # ... repeat, possibly including blah blah blah
    #
    # parse through it, and extract out just the json blocks
    for line in verOut.splitlines():
        if inSection:
            envList[envIndex] += line
            if line.startswith("}"):
                # block end
                inSection = False
                envIndex = envIndex+1
        elif line.startswith("{"): 
            # starting a block
            envList.append(line)
            inSection = True
        else:
            # just ignore this line
            pass

    # now parse that collected json data to get the actual vars
    jsonEnvList = {}
    for x in envList:
        jsonEnvList.update(json.loads(x))

    userid = ""
    password = ""

    # find the credentials for the service in question
    if jsonEnvList != None:
        serviceList = jsonEnvList['VCAP_SERVICES']
        if serviceList != None:
            analyzerService = serviceList[service]
            if analyzerService != None:
                credentials = analyzerService[0]['credentials']
                userid = credentials['bindingid']
                password = credentials['password']

    if not (userid) or not (password):
        raise Exception("Unable to get bound credentials for access to the Static Analysis service.")

    return userid, password

# given userid and password, attempt to authenticate to appscan for
# future calls
def appscanLogin (userid, password):
    proc = Popen(["appscan.sh login -u " + userid + " -P " + password + ""], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if not "Authenticated successfully." in out:
        if os.environ.get('DEBUG'):
            call(["cat $APPSCAN_INSTALL_DIR/logs/client.log"], shell=True)
        raise Exception("Unable to login to Static Analysis service")

# callout to appscan to prepare a current irx file, return a set of
# the files created by the prepare
def appscanPrepare ():
    # sadly, prepare doesn't tell us what file it created, so find
    # out by a list compare before/after
    oldIrxFiles = []
    for file in os.listdir("."):
        if file.endswith(".irx"):
            oldIrxFiles.append(file)

    proc = Popen(["appscan.sh prepare"], 
                 shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if not "IRX file generation successful" in out:
        if os.environ.get('DEBUG'):
            call(["cat $APPSCAN_INSTALL_DIR/logs/client.log"], shell=True)
        raise Exception("Unable to prepare code for analysis by Static Analysis service: " + 
                        err)

    # what files are there now?
    newIrxFiles = []
    for file in os.listdir("."):
        if file.endswith(".irx"):
            newIrxFiles.append(file)
    # which files are new?
    newIrxFiles = set(newIrxFiles).difference(oldIrxFiles)

    return newIrxFiles


# get appscan list of current jobs
def appscanList ():
    proc = Popen(["appscan.sh list"], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    print "out = " + out
    print "err = " + err

    if "Problems found" in err:
        if os.environ.get('DEBUG'):
            call(["cat $APPSCAN_INSTALL_DIR/logs/client.log"], shell=True)
        raise Exception("Unable to prepare code for analysis by Static Analysis service: " + 
                        err)

try:
    userid, password = getCredentialsFromBoundApp(service=STATIC_ANALYSIS_SERVICE)
    appscanLogin(userid,password)
    files_to_submit = appscanPrepare()
    appscanList()
except Exception, e:
    print e
    sys.exit(1)

