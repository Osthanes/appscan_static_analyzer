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
import os.path
import sys
import time
from subprocess import call, Popen, PIPE

STATIC_ANALYSIS_SERVICE='Static Analyzer'
DEFAULT_SERVICE=STATIC_ANALYSIS_SERVICE
DEFAULT_SCANNAME="staticscan"

# check cli args, set globals appropriately
def parseArgs ():
    parsedArgs = {}
    parsedArgs['loginonly'] = False
    parsedArgs['cleanup'] = False
    for arg in sys.argv:
        if arg == "--loginonly":
            parsedArgs['loginonly'] = True
        if arg == "--cleanup":
            parsedArgs['cleanup'] = True

    return parsedArgs

# search cf, find an app in our space bound to the given service, and return
# the app name if found, or None if not
def findBoundAppForService (service=DEFAULT_SERVICE):

    proc = Popen(["cf services"], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if proc.returncode != 0:
        print "findBoundApp: couldn't run cf services"
        return None

    foundHeader = False
    serviceStart = -1
    serviceEnd = -1
    boundStart = -1
    boundEnd = -1
    boundApp = None
    for line in out.splitlines():
        if (foundHeader == False) and (line.startswith("name")):
            # this is the header bar, find out the spacing to parse later
            # header is of the format:
            #name          service      plan   bound apps    last operation
            # and the spacing is maintained for following lines
            serviceStart = line.find("service")
            serviceEnd = line.find("plan")-1
            boundStart = line.find("bound apps")
            boundEnd = line.find("last operation")
            foundHeader = True
        elif foundHeader:
            # have found the headers, looking for our service
            if service in line:
                # maybe found it, double check by making
                # sure the service is in the right place,
                # assuming we can check it
                if (serviceStart > 0) and (serviceEnd > 0) and (boundStart > 0) and (boundEnd > 0):
                    if service in line[serviceStart:serviceEnd]:
                        # this is the correct line - find the bound app(s)
                        # if there are any
                        boundApp = line[boundStart:boundEnd]
        else:
            continue

    # if we found a binding, make sure we only care about the first one
    if boundApp != None:
        if boundApp.find(",") >=0 :
            boundApp = boundApp[:boundApp.find(",")]
        boundApp = boundApp.strip()
        if boundApp=="":
            boundApp = None

    if os.environ.get('DEBUG'):
        if boundApp == None:
            print "No existing apps found bound to service \"" + service + "\""
        else:
            print "Found existing service \"" + boundApp + "\" bound to service \"" + service + "\""

    return boundApp

# look for our bridge app to bind this service to.  If it's not there,
# attempt to create it.  Then bind the service to that app.  If it 
# all works, return that app name as the bound app
def createBoundAppForService (service=DEFAULT_SERVICE):
    return None

# find given bound app, and look for the passed bound service in cf.  once
# found in VCAP_SERVICES, look for the credentials setting, and extract
# userid, password.  Raises Exception on errors
def getCredentialsFromBoundApp (service=DEFAULT_SERVICE, binding_app=None):
    # if no binding app parm passed, try to get it from env
    if binding_app == None:
        binding_app = os.environ.get('BINDING_APP')
    # if still no binding app, go looking to find a bound app for this one
    if binding_app == None:
        binding_app = findBoundAppForService(service)
    # if still no binding app... CREATE ONE!
    if binding_app == None:
        binding_app = createBoundAppForService(service)

    # if STILL no binding app, we're out of options, just fail out
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
            call(["cat $APPSCAN_INSTALL_DIR/logs/client.log | tail -n 10"], shell=True)
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

# parse a key=value line, return value
def parseKeyEqVal (line):
    if line == None:
        return None

    eqIndex = line.find("=");
    if eqIndex != -1:
        return line[eqIndex+1:]
    else:
        return None

# extended info on a current appscan job.  this comes back in a form
# similar to:
#NLowIssues=0
#ReadStatus=2
#NHighIssues=0
#Name=appscan.zip
#ScanEndTime=2014-11-20T13:56:04.497Z
#Progress=0
#RemainingFreeRescanMinutes=0
#ParentJobId=00000000-0000-0000-0000-000000000000
#EnableMailNotifications=false
#JobStatus=6
#NInfoIssues=0
#JobId=9b344fc7-bc70-e411-b922-005056924f9b
#NIssuesFound=0
#CreatedAt=2014-11-20T13:54:49.597Z
#UserMessage=Scan completed successfully. The report is ready.
#NMediumIssues=0
#Result=1
#
# parse it and return useful parts.  in particular, returns
# NInfo, NLow, NMedium, NHigh, userMessage
def appscanInfo (jobid):
    if jobid == None:
        return

    proc = Popen(["appscan.sh info -i " + str(jobid)], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    Progress = 100
    NInfo = 0
    NLow = 0
    NMed = 0
    NHigh = 0
    jobName = ""
    userMsg = ""
    for line in out.splitlines() :
        if "NLowIssues=" in line:
            # number of low severity issues found in the scan
            tmpstr = parseKeyEqVal(line)
            if tmpstr != None:
                try:
                    NLow = int(tmpstr)
                except ValueError:
                    NLow = 0

            elif "NMediumIssues=" in line:
                # number of medium severity issues found in the scan
                tmpstr = parseKeyEqVal(line)
                if tmpstr != None:
                    try:
                        NMed = int(tmpstr)
                    except ValueError:
                        NMed = 0

            elif "NHighIssues=" in line:
                # number of medium severity issues found in the scan
                tmpstr = parseKeyEqVal(line)
                if tmpstr != None:
                    try:
                        NHigh = int(tmpstr)
                    except ValueError:
                        NHigh = 0

            elif "NInfoIssues=" in line:
                # number of medium severity issues found in the scan
                tmpstr = parseKeyEqVal(line)
                if tmpstr != None:
                    try:
                        NInfo = int(tmpstr)
                    except ValueError:
                        NInfo = 0

            elif "Progress=" in line:
                # number of medium severity issues found in the scan
                tmpstr = parseKeyEqVal(line)
                if tmpstr != None:
                    try:
                        Progress = int(tmpstr)
                    except ValueError:
                        Progress = 0

            elif "Name=" in line:
                # number of medium severity issues found in the scan
                tmpstr = parseKeyEqVal(line)
                if tmpstr != None:
                    jobName = tmpstr

            elif "UserMessage=" in line:
                # number of medium severity issues found in the scan
                tmpstr = parseKeyEqVal(line)
                if tmpstr != None:
                    userMsg = tmpstr

    return NInfo, NLow, NMed, NHigh, Progress, jobName, userMsg

# get the result file for a given job
def appscanGetResult (jobid):
    if jobid == None:
        return

    proc = Popen(["appscan.sh get_result -i " + str(jobid)], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    print "Out = " + out
    print "Err = " + err

# wait for a given set of scans to complete and, if successful,
# download the results
def waitforscans (joblist):
    for jobid in joblist:
        try:
            while True:
                state = appscanStatus(jobid)
                print "Job " + str(jobid) + " in state " + getStateName(state)
                if getStateCompleted(state):
                    info,low,med,high,prog,name,msg = appscanInfo(jobid)
                    if getStateSuccessful(state):
                        print "Analysis successful (" + name + ")"
                        print "\tInfo Issues   : " + str(info)
                        print "\tLow Issues    : " + str(low)
                        print "\tMedium Issues : " + str(med)
                        print "\tHigh Issues   : " + str(high)
                        print "\tOther Message : " + msg
                        appscanGetResult(jobid)
                    else: 
                        print "Analysis unsuccessful"

                    break
                else:
                    time.sleep(10)
        except Exception:
            # bad id, skip it
            pass


# begin main execution sequence

try:
    parsedArgs = parseArgs()
    print "Getting credentials for Static Analysis service"
    sys.stdout.flush()
    userid, password = getCredentialsFromBoundApp(service=STATIC_ANALYSIS_SERVICE)
    print "Connecting to Static Analysis service"
    sys.stdout.flush()
    appscanLogin(userid,password)

    if parsedArgs['loginonly']:
        print "LoginOnly set, login complete, exiting"
        sys.exit(0)

    print "Scanning for code submission"
    sys.stdout.flush()
    files_to_submit = appscanPrepare()
    print "Submitting scans for analysis"
    sys.stdout.flush()
    joblist = appscanSubmit(files_to_submit)
    print "Waiting for analysis to complete"
    sys.stdout.flush()
    waitforscans(joblist)

    if parsedArgs['cleanup']:
        # cleanup the jobs we launched (since they're complete)
        print "Cleaning up"
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

