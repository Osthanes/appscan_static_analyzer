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
import time
from subprocess import call, Popen, PIPE

STATIC_ANALYSIS_SERVICE='Static Analyzer'
DEFAULT_SERVICE=STATIC_ANALYSIS_SERVICE
DEFAULT_SCANNAME="staticscan"


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

    print "Generated scans as file(s):"
    for file in newIrxFiles:
        print "\t" + file

    return newIrxFiles

# submit a created irx file to appscan for analysis
def appscanSubmit (filelist):
    if filelist==None:
        raise Exception("No files to analyze")

    # check the env for name of the scan, else use default
    if os.environ.get('SUBMISSION_NAME'):
        scanname=os.environ.get('SUBMISSION_NAME')
    else:
        scanname=DEFAULT_SCANNAME

    # if we have an application version, append it to the scanname
    if os.environ.get('APPLICATION_VERSION'):
        scanname.append("-" + os.environ.get('APPLICATION_VERSION'))

    scanlist = []
    index = 0
    for filename in filelist:
        submit_scanname = scanname + "-" + str(index)
        proc = Popen(["appscan.sh queue_analysis -f " + filename +
                      " -n " + submit_scanname], 
                          shell=True, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate();

        transf_found = False
        for line in out.splitlines() :
            if "100% transferred" in line:
                # done transferring
                transf_found = True
            elif not transf_found:
                # not done transferring yet
                continue
            elif line:
                # done, if line isn't empty, is an id
                scanlist.append(line)
                print "Job for file " + filename + " was submitted as scan " + submit_scanname + " and assigned id " + line
            else:
                # empty line, skip it
                continue

        index = index + 1

    return scanlist


# get appscan list of current jobs
def appscanList ():
    proc = Popen(["appscan.sh list"], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    scanlist = []
    for line in out.splitlines() :
        if "No analysis jobs" in line:
            # no jobs, return empty list
            return []
        elif line:
            # done, if line isn't empty, is an id
            scanlist.append(line)
        else:
            # empty line, skip it
            continue

    return scanlist

# translate a job state to a pretty name
def getStateName (state):
    return {
        0 : "Pending",
        1 : "Starting",
        2 : "Running",
        3 : "FinishedRunning",
        4 : "FinishedRunningWithErrors",
        5 : "PendingSupport",
        6 : "Ready",
        7 : "ReadyIncomplete",
        8 : "FailedToScan",
        9 : "ManuallyStopped",
        10 : "None",
        11 : "Initiating",
        12 : "MissingConfiguration",
        13 : "PossibleMissingConfiguration"
    }.get(state, "Unknown")

# given a state, is the job completed
def getStateCompleted (state):
    return {
        0 : False,
        1 : False,
        2 : False,
        3 : True,
        4 : True,
        5 : True,
        6 : True,
        7 : True,
        8 : True,
        9 : True,
        10 : True,
        11 : False,
        12 : True,
        13 : True
    }.get(state, True)

# given a state, was it completed successfully
def getStateSuccessful (state):
    return {
        0 : False,
        1 : False,
        2 : False,
        3 : True,
        4 : False,
        5 : False,
        6 : True,
        7 : False,
        8 : False,
        9 : False,
        10 : False,
        11 : False,
        12 : False,
        13 : False
    }.get(state, False)

# get status of a given job
def appscanStatus (jobid):
    if jobid == None:
        raise Exception("No jobid to check status")

    proc = Popen(["appscan.sh status -i " + str(jobid)], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if "request is invalid" in err:
        raise Exception("Invalid jobid")

    retval = 0
    try:
        retval = int(out)
    except ValueError:
        raise Exception("Invalid jobid")

    return retval

# cancel an appscan job
def appscanCancel (jobid):
    if jobid == None:
        return

    proc = Popen(["appscan.sh cancel -i " + str(jobid)], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

# wait for a given set of scans to complete and, if successful,
# download the results
def waitforscans (joblist):
    for jobid in joblist:
        try:
            while True:
                state = appscanStatus(jobid)
                print "Job " + str(jobid) + " in state " + getStateName(state)
                if getStateCompleted(state):
                    if getStateSuccessful(state):
                        # todo - fetch results
                        pass
                    break
                else:
                    time.sleep(5)
        except Exception:
            # bad id, skip it
            pass


try:
    print "Getting credentials for Static Analysis service"
    userid, password = getCredentialsFromBoundApp(service=STATIC_ANALYSIS_SERVICE)
    print "Connecting to Static Analysis service"
    appscanLogin(userid,password)
    print "Scanning for code submission"
    files_to_submit = appscanPrepare()
    print "Submitting scans for analysis"
    joblist = appscanSubmit(files_to_submit)
    printf "Waiting for analysis to complete"
    waitforscans(joblist)

    # cleanup the jobs we launched (since they're complete)
    for job in joblist:
        appscanCancel(job)
    # and cleanup the submitted irx files
    for file in files_to_submit:
        if os.path.isfile(file):
            os.remove(file)
        if os.path.isfile(file+".log"):
            os.remove(file+".log")
except Exception, e:
    print e
    sys.exit(1)

