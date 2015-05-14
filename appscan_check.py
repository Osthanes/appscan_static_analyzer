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
import logging
import logging.handlers
import os
import os.path
import sys
import time
import timeit
from subprocess import call, Popen, PIPE

# ascii color codes for output
LABEL_GREEN='\033[0;32m'
LABEL_RED='\033[0;31m'
LABEL_COLOR='\033[0;33m'
LABEL_NO_COLOR='\033[0m'
STARS="**********************************************************************"

STATIC_ANALYSIS_SERVICE='Static Analyzer'
DEFAULT_SERVICE=STATIC_ANALYSIS_SERVICE
DEFAULT_SERVICE_PLAN="free"
DEFAULT_SERVICE_NAME=DEFAULT_SERVICE
DEFAULT_SCANNAME="staticscan"
DEFAULT_BRIDGEAPP_NAME="containerbridge"
DEFAULT_CREDENTIALS=['bindingid','password']
DEBUG=os.environ.get('DEBUG')
# time to sleep between checks when waiting on pending jobs, in seconds
SLEEP_TIME=15

SCRIPT_START_TIME = timeit.default_timer()
LOGGER = None
WAIT_TIME = 0

# check cli args, set globals appropriately
def parse_args ():
    parsed_args = {}
    parsed_args['loginonly'] = False
    parsed_args['cleanup'] = False
    parsed_args['checkstate'] = False
    parsed_args['debug'] = False
    for arg in sys.argv:
        if arg == "--loginonly":
            # only login, no scanning or submission
            parsed_args['loginonly'] = True
        if arg == "--cleanup":
            # cleanup/cancel all complete jobs, and delete irx files
            parsed_args['cleanup'] = True
        if arg == "--checkstate":
            # just check state of existing jobs, don't scan or submit
            # any new ones
            parsed_args['checkstate'] = True
        if arg == "debug":
            # enable debug mode, can also be done with DEBUG env var
            parsed_args['debug'] = True
            DEBUG = "1"

    return parsed_args

# setup logmet logging connection if it's available
def setup_logging ():
    logger = logging.getLogger('pipeline')
    if DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # if logmet is enabled, send the log through syslog as well
    if os.environ.get('LOGMET_LOGGING_ENABLED'):
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        logger.addHandler(handler)
        # don't send debug info through syslog
        handler.setLevel(logging.INFO)

    # in any case, dump logging to the screen
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    if DEBUG:
        handler.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    
    return logger

# return the remaining time to wait
# first time, will prime from env var and subtract init script time 
#
# return is the expected max time left in seconds we're allowed to wait
# for pending jobs to complete
def get_remaining_wait_time (first = False):
    if first:
        # first time through, set up the var from env
        try:
            time_to_wait = int(os.getenv('WAIT_TIME', "5")) * 60
        except ValueError:
            time_to_wait = 300

        # and (if not 0) subtract out init time
        if time_to_wait != 0:
            try:
                initTime = int(os.getenv("INT_EST_TIME", "0"))
            except ValueError:
                initTime = 0

            time_to_wait -= initTime
    else:
        # just get the initial start time
        time_to_wait = WAIT_TIME

    # if no time to wait, no point subtracting anything
    if time_to_wait != 0:
        time_so_far = int(timeit.default_timer() - SCRIPT_START_TIME)
        time_to_wait -= time_so_far

    # can't wait negative time, fix it
    if time_to_wait < 0:
        time_to_wait = 0

    return time_to_wait

# find the given service in our space, get its service name, or None
# if it's not there yet
def find_service_name_in_space (service):
    command = "cf services"
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if proc.returncode != 0:
        LOGGER.info("Unable to lookup services, error was: " + out)
        return None

    foundHeader = False
    serviceStart = -1
    serviceEnd = -1
    serviceName = None
    for line in out.splitlines():
        if (foundHeader == False) and (line.startswith("name")):
            # this is the header bar, find out the spacing to parse later
            # header is of the format:
            #name          service      plan   bound apps    last operation
            # and the spacing is maintained for following lines
            serviceStart = line.find("service")
            serviceEnd = line.find("plan")-1
            foundHeader = True
        elif foundHeader:
            # have found the headers, looking for our service
            if service in line:
                # maybe found it, double check by making
                # sure the service is in the right place,
                # assuming we can check it
                if (serviceStart > 0) and (serviceEnd > 0):
                    if service in line[serviceStart:serviceEnd]:
                        # this is the correct line - find the bound app(s)
                        # if there are any
                        serviceName = line[:serviceStart]
                        serviceName = serviceName.strip()
        else:
            continue

    return serviceName

# find a service in our space, and if it's there, get the dashboard
# url for user info on it
def find_service_dashboard (service=DEFAULT_SERVICE):

    serviceName = find_service_name_in_space(service)
    if serviceName == None:
        return None

    command = "cf service \"" + serviceName + "\""
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if proc.returncode != 0:
        return None

    serviceURL = None
    for line in out.splitlines():
        if line.startswith("Dashboard: "):
            serviceURL = line[11:]
        else:
            continue

    return serviceURL

# search cf, find an app in our space bound to the given service, and return
# the app name if found, or None if not
def find_bound_app_for_service (service=DEFAULT_SERVICE):

    proc = Popen(["cf services"], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if proc.returncode != 0:
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

    if DEBUG:
        if boundApp == None:
            LOGGER.debug("No existing apps found bound to service \"" + service + "\"")
        else:
            LOGGER.debug("Found existing service \"" + boundApp + "\" bound to service \"" + service + "\"")

    return boundApp

# look for our default bridge app.  if it's not there, create it
def check_and_create_bridge_app ():
    # first look to see if the bridge app already exists
    command = "cf apps"
    LOGGER.debug("Executing command \"" + command + "\"")
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if DEBUG:
        LOGGER.debug("command \"" + command + "\" returned with rc=" + str(proc.returncode))
        LOGGER.debug("\tstdout was " + out)
        LOGGER.debug("\tstderr was " + err)

    if proc.returncode != 0:
        return None

    for line in out.splitlines():
        if line.startswith(DEFAULT_BRIDGEAPP_NAME + " "):
            # found it!
            return True

    # our bridge app isn't around, create it
    LOGGER.info("Bridge app does not exist, attempting to create it")
    command = "cf push " + DEFAULT_BRIDGEAPP_NAME + " -i 1 -d mybluemix.net -k 1M -m 64M --no-hostname --no-manifest --no-route --no-start"
    LOGGER.debug("Executing command \"" + command + "\"")
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if DEBUG:
        LOGGER.debug("command \"" + command + "\" returned with rc=" + str(proc.returncode))
        LOGGER.debug("\tstdout was " + out)
        LOGGER.debug("\tstderr was " + err)

    if proc.returncode != 0:
        LOGGER.info("Unable to create bridge app, error was: " + out)
        return False

    return True

# look for our bridge app to bind this service to.  If it's not there,
# attempt to create it.  Then bind the service to that app under the 
# given plan.  If it all works, return that app name as the bound app
def create_bound_app_for_service (service=DEFAULT_SERVICE, plan=DEFAULT_SERVICE_PLAN):

    if not check_and_create_bridge_app():
        return None

    # look to see if we have the service in our space
    serviceName = find_service_name_in_space(service)

    # if we don't have the service name, means the tile isn't created in our space, so go
    # load it into our space if possible
    if serviceName == None:
        LOGGER.info("Service \"" + service + "\" is not loaded in this space, attempting to load it")
        serviceName = DEFAULT_SERVICE_NAME
        command = "cf create-service \"" + service + "\" \"" + plan + "\" \"" + serviceName + "\""
        LOGGER.debug("Executing command \"" + command + "\"")
        proc = Popen([command], 
                     shell=True, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate();

        if proc.returncode != 0:
            LOGGER.info("Unable to create service in this space, error was: " + out)
            return None

    # now try to bind the service to our bridge app
    LOGGER.info("Binding service \"" + serviceName + "\" to app \"" + DEFAULT_BRIDGEAPP_NAME + "\"")
    proc = Popen(["cf bind-service " + DEFAULT_BRIDGEAPP_NAME + " \"" + serviceName + "\""], 
                 shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if proc.returncode != 0:
        LOGGER.info("Unable to bind service to the bridge app, error was: " + out)
        return None

    return DEFAULT_BRIDGEAPP_NAME

# find given bound app, and look for the passed bound service in cf.  once
# found in VCAP_SERVICES, look for the credentials setting, and extract
# userid, password.  Raises Exception on errors
def get_credentials_from_bound_app (service=DEFAULT_SERVICE, binding_app=None, credentiallist=DEFAULT_CREDENTIALS):
    # if no binding app parm passed, go looking to find a bound app for this one
    if binding_app == None:
        binding_app = find_bound_app_for_service(service)
    # if still no binding app, and the user agreed, CREATE IT!
    if binding_app == None:
        setupSpace = os.environ.get('SETUP_SERVICE_SPACE')
        if (setupSpace != None) and (setupSpace.lower() == "true"):
            binding_app = create_bound_app_for_service(service=service, plan=DEFAULT_SERVICE_PLAN)
        else:
            raise Exception("Service \"" + service + "\" is not loaded and bound in this space.  Please add the service to the space and bind it to an app, or set the parameter to allow the space to be setup automatically")

    # if STILL no binding app, we're out of options, just fail out
    if binding_app == None:
        raise Exception("Unable to access an app bound to the Static Analysis service - this must be set to get the proper credentials.")

    # try to read the env vars off the bound app in cloud foundry, the one we
    # care about is "VCAP_SERVICES"
    verProc = Popen(["cf env \"" + binding_app + "\""], shell=True, 
                    stdout=PIPE, stderr=PIPE)
    verOut, verErr = verProc.communicate();

    if verProc.returncode != 0:
        raise Exception("Unable to read credential information off the app bound to the Static Analysis service - please check that it is set correctly.")

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

    return_cred_list = []
    notFound = False

    # find the credentials for the service in question
    if jsonEnvList != None:
        serviceList = jsonEnvList['VCAP_SERVICES']
        if serviceList != None:
            analyzerService = serviceList[service]
            if analyzerService != None:
                credentials = analyzerService[0]['credentials']
                for cred in credentiallist:
                    if credentials[cred] == None:
                        return_cred_list.append('')
                        notFount = True
                    else:
                        return_cred_list.append(credentials[cred])

    if notFound:
        raise Exception("Unable to get bound credentials for access to the Static Analysis service.")

    return return_cred_list

# create a template for a current scan.  this will be in the format
# "<scanname>-<version>-" where scanname comes from env var 
# 'SUBMISSION_NAME', and version comes from env var 'APPLICATION_VERSION'
def get_scanname_template ():
    # check the env for name of the scan, else use default
    if os.environ.get('SUBMISSION_NAME'):
        scanname=os.environ.get('SUBMISSION_NAME')
    else:
        scanname=DEFAULT_SCANNAME

    # if we have an application version, append it to the scanname
    if os.environ.get('APPLICATION_VERSION'):
        scanname = scanname + "-" + os.environ.get('APPLICATION_VERSION')

    return scanname

# given userid and password, attempt to authenticate to appscan for
# future calls
def appscan_login (userid, password):
    proc = Popen(["appscan.sh login -u " + userid + " -P " + password + ""], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if not "Authenticated successfully." in out:
        raise Exception("Unable to login to Static Analysis service")

# callout to appscan to prepare a current irx file, return a set of
# the files created by the prepare
def appscan_prepare ():

    # sadly, prepare doesn't tell us what file it created, so find
    # out by a list compare before/after
    oldIrxFiles = []
    for file in os.listdir("."):
        if file.endswith(".irx"):
            oldIrxFiles.append(file)

    # clean up the appscan client log so we can dump it on error if needed
    # and only see the error from this call
    logfileName = None
    appscanDir = os.environ.get('APPSCAN_INSTALL_DIR')
    if appscanDir:
        logfileName = appscanDir+"/logs/client.log"
        if os.path.isfile( logfileName ):
            os.remove( logfileName )

    proc = Popen(["appscan.sh prepare"], 
                 shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if not "IRX file generation successful" in out:
        if "An IRX file was created, but it may be incomplete" in err:
            # some jar/war/ear files were not scannable, but some were.
            # attempt the submission
            LOGGER.warning("Not all files could be scanned, but the scan has been submitted for those which were")
        else:
            if DEBUG:
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

    logMessage = "Generated scans as file(s):"
    for file in newIrxFiles:
        logMessage = logMessage + "\n\t" + file

    LOGGER.info(logMessage)

    return newIrxFiles

# submit a created irx file to appscan for analysis
def appscan_submit (filelist):
    if filelist==None:
        raise Exception("No files to analyze")

    scanlist = []
    index = 0
    for filename in filelist:
        submit_scanname = get_scanname_template() + str(index)
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
                LOGGER.info("Job for file " + filename + " was submitted as scan " + submit_scanname + " and assigned id " + line)
            else:
                # empty line, skip it
                continue

        index = index + 1

    return scanlist


# get appscan list of current jobs
def appscan_list ():
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
def get_state_name (state):
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
def get_state_completed (state):
    return {
        0 : False,
        1 : False,
        2 : False,
        3 : True,
        4 : True,
        5 : False,
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
def get_state_successful (state):
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
def appscan_status (jobid):
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
def appscan_cancel (jobid):
    if jobid == None:
        return

    proc = Popen(["appscan.sh cancel -i " + str(jobid)], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

# parse a key=value line, return value
def parse_key_eq_val (line):
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
# NInfo, NLow, NMedium, NHigh, Progress, jobName, userMessage
def appscan_info (jobid):
    if jobid == None:
        return

    command = "appscan.sh info -i " + str(jobid)
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
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
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    NLow = int(tmpstr)
                except ValueError:
                    NLow = 0

        elif "NMediumIssues=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    NMed = int(tmpstr)
                except ValueError:
                    NMed = 0

        elif "NHighIssues=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    NHigh = int(tmpstr)
                except ValueError:
                    NHigh = 0

        elif "NInfoIssues=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    NInfo = int(tmpstr)
                except ValueError:
                    NInfo = 0

        elif "Progress=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    Progress = int(tmpstr)
                except ValueError:
                    Progress = 0

        elif "Name=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                jobName = tmpstr

        elif "UserMessage=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                userMsg = tmpstr

    return NInfo, NLow, NMed, NHigh, Progress, jobName, userMsg

# get the result file for a given job
def appscan_get_result (jobid):
    if jobid == None:
        return

    proc = Popen(["appscan.sh get_result -i " + str(jobid)], 
                      shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    print "Out = " + out
    print "Err = " + err

# if the job we would run is already up (and either pending or complete),
# we just want to get state (and wait for it if needed), not create a whole
# new submission.  for the key, we use the job name, compared to the
# name template as per get_scanname_template()
def check_for_existing_job ():
    alljobs = appscan_list()
    if alljobs == None:
        # no jobs, ours can't be there
        return None

    # get the name we're looking for
    job_name = get_scanname_template()
    joblist = []
    found = False
    for jobid in alljobs:
        info,low,med,high,prog,name,msg = appscan_info(jobid)
        if (name != None) and (name.startswith(job_name)):
            joblist.append(jobid)
            found = True

    if found:
        return joblist
    else:
        return None

# wait for a given set of scans to complete and, if successful,
# download the results
def wait_for_scans (joblist):
    all_jobs_complete = True
    dash = find_service_dashboard(STATIC_ANALYSIS_SERVICE)
    for jobid in joblist:
        try:
            while True:
                state = appscan_status(jobid)
                LOGGER.info("Job " + str(jobid) + " in state " + get_state_name(state))
                if get_state_completed(state):
                    info,low,med,high,prog,name,msg = appscan_info(jobid)
                    if get_state_successful(state):
                        LOGGER.info("Analysis successful (" + name + ")")
                        #print "\tOther Message : " + msg
                        #appscan_get_result(jobid)
                        print LABEL_GREEN + STARS
                        print "Analysis successful for job \"" + name + "\""
                        print "\tHigh Severity Issues   : " + str(high)
                        print "\tMedium Severity Issues : " + str(med)
                        print "\tLow Severity Issues    : " + str(low)
                        print "\tInfo Severity Issues   : " + str(info)
                        if dash != None:
                            print "See detailed results at: " + LABEL_COLOR + " " + dash
                        print LABEL_GREEN + STARS + LABEL_NO_COLOR
                    else: 
                        LOGGER.info("Analysis unsuccessful (" + name + ") with message \"" + msg + "\"")

                    break
                else:
                    time_left = get_remaining_wait_time()
                    if (time_left > SLEEP_TIME):
                        time.sleep(SLEEP_TIME)
                    else:
                        # ran out of time, flag that at least one job didn't complete
                        all_jobs_complete = False
                        # notify the user
                        print LABEL_RED + STARS
                        print "Analysis incomplete for job \"" + name + "\""
                        print "\t" + str(prog) + "% complete"
                        if dash != None:
                            print "Track current state and results at: " + LABEL_COLOR + " " + dash
                        print LABEL_RED + "Increase the time to wait and rerun this job. The existing analysis will continue and be found and tracked."
                        print STARS + LABEL_NO_COLOR

                        # and continue to get state for other jobs
                        break
        except Exception:
            # bad id, skip it
            pass

    return all_jobs_complete


# begin main execution sequence

try:
    parsed_args = parse_args()
    LOGGER = setup_logging()
    WAIT_TIME = get_remaining_wait_time(first = True)
    LOGGER.info("Getting credentials for Static Analysis service")
    cred_list = get_credentials_from_bound_app(service=STATIC_ANALYSIS_SERVICE)
    LOGGER.info("Connecting to Static Analysis service")
    appscan_login(cred_list[0],cred_list[1])

    # allow testing connection without full job scan and submission
    if parsed_args['loginonly']:
        LOGGER.info("LoginOnly set, login complete, exiting")
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
        sys.exit(0)

    # if checkstate, don't really do a scan, just check state of current outstanding ones
    if parsed_args['checkstate']:
        # for checkstate, don't wait, just check current
        WAIT_TIME = 0
        joblist = appscan_list()
    else:
        # if the job we would run is already up (and either pending or complete),
        # we just want to get state (and wait for it if needed), not create a whole
        # new submission
        joblist = check_for_existing_job()
        if joblist == None:
            LOGGER.info("Scanning for code submission")
            files_to_submit = appscan_prepare()
            LOGGER.info("Submitting scans for analysis")
            joblist = appscan_submit(files_to_submit)
            LOGGER.info("Waiting for analysis to complete")
        else:
            LOGGER.info("Existing job found, connecting")

    # check on pending jobs, waiting if appropriate
    all_jobs_complete = wait_for_scans(joblist)

    if parsed_args['cleanup']:
        # cleanup the jobs we launched (since they're complete)
        print "Cleaning up"
        for job in joblist:
            appscan_cancel(job)
        # and cleanup the submitted irx files
        for file in files_to_submit:
            if os.path.isfile(file):
                os.remove(file)
            if os.path.isfile(file+".log"):
                os.remove(file+".log")

    # if we didn't successfully complete jobs, return that we timed out
    if not all_jobs_complete:
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
        sys.exit(2)
    else:
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
        sys.exit(0)

except Exception, e:
    LOGGER.warning("Exception received", exc_info=e)
    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
    sys.exit(1)

