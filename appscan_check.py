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
from datetime import datetime
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
DEFAULT_BRIDGEAPP_NAME="pipeline_bridge_app"
DEFAULT_OLD_SCANS_TO_KEEP="5"
DEFAULT_OLD_SCANS_TO_KEEP_INT=5
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
    parsed_args['forcecleanup'] = False
    parsed_args['checkstate'] = False
    parsed_args['debug'] = False
    parsed_args['help'] = False
    for arg in sys.argv:
        if arg == "--loginonly":
            # only login, no scanning or submission
            parsed_args['loginonly'] = True
        if arg == "--forcecleanup":
            # cleanup/cancel all complete jobs, and delete irx files
            parsed_args['forcecleanup'] = True
        if arg == "--checkstate":
            # just check state of existing jobs, don't scan or submit
            # any new ones
            parsed_args['checkstate'] = True
        if arg == "--debug":
            # enable debug mode, can also be done with DEBUG env var
            parsed_args['debug'] = True
            DEBUG = "1"
        if arg == "--help":
            # just print help and return
            parsed_args['help'] = True

    return parsed_args

# print a quick usage/help statement
def print_help ():
    print "usage: appscan_check.py [options]"
    print
    print "\toptions:"
    print "\t   --loginonly    : get credentials and login to appscan only"
    print "\t   --forcecleanup : on exit, force removal of pending jobs from this run"
    print "\t   --checkstate   : check state of existing job(s), no new submission"
    print "\t   --debug        : get additional debug output"
    print "\t   --help         : print this help message and exit"
    print


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
    if os.environ.get('OLDCF_LOCATION'):
        command = os.environ.get('OLDCF_LOCATION')
        if not os.path.isfile(command):
            command = 'cf'
    else:
        command = 'cf'
    command = command +" push " + DEFAULT_BRIDGEAPP_NAME + " -i 1 -d mybluemix.net -k 1M -m 64M --no-hostname --no-manifest --no-route --no-start"
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
        serviceName = service
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
# found in VCAP_SERVICES, look for the credentials setting, and return the
# dict.  Raises Exception on errors
def get_credentials_from_bound_app (service=DEFAULT_SERVICE, binding_app=None):
    # if no binding app parm passed, go looking to find a bound app for this one
    if binding_app == None:
        binding_app = find_bound_app_for_service(service)
    # if still no binding app, and the user agreed, CREATE IT!
    if binding_app == None:
        setupSpace = os.environ.get('SETUP_SERVICE_SPACE')
        if (setupSpace != None) and (setupSpace.lower() == "true"):
            binding_app = create_bound_app_for_service(service=service, plan=DEFAULT_SERVICE_PLAN)
        else:
            raise Exception("Service \"" + service + "\" is not loaded and bound in this space.  " + LABEL_COLOR + "Please add the service to the space and bind it to an app, or set the parameter to allow the space to be setup automatically" + LABEL_NO_COLOR)

    # if STILL no binding app, we're out of options, just fail out
    if binding_app == None:
        raise Exception("Unable to access an app bound to the " + service + " service - this must be set to get the proper credentials.")

    # try to read the env vars off the bound app in cloud foundry, the one we
    # care about is "VCAP_SERVICES"
    verProc = Popen(["cf env \"" + binding_app + "\""], shell=True, 
                    stdout=PIPE, stderr=PIPE)
    verOut, verErr = verProc.communicate();

    if verProc.returncode != 0:
        raise Exception("Unable to read credential information off the app bound to the " + service + " service - please check that it is set correctly.")

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
    found = False

    # find the credentials for the service in question
    if jsonEnvList != None:
        serviceList = jsonEnvList['VCAP_SERVICES']
        if serviceList != None:
            analyzerService = serviceList[service]
            if analyzerService != None:
                credentials = analyzerService[0]['credentials']
                if credentials != None:
                    found = True
                    return credentials

    if not found:
        raise Exception("Unable to get bound credentials for access to the " + service + " service.")

    return None

# create a template for a current scan.  this will be in the format
# "<scanname>-<version>-" where scanname comes from env var 
# 'SUBMISSION_NAME', and version comes from env var 'APPLICATION_VERSION'
def get_scanname_template (include_version=True):
    # check the env for name of the scan, else use default
    if os.environ.get('SUBMISSION_NAME'):
        scanname=os.environ.get('SUBMISSION_NAME')
    elif os.environ.get('IDS_PROJECT_NAME'):
        scanname=os.environ.get('IDS_PROJECT_NAME').replace(" | ", "-")
    else:
        scanname=DEFAULT_SCANNAME

    if include_version:
        # if we have an application version, append it to the scanname
        if os.environ.get('APPLICATION_VERSION'):
            scanname = scanname + "-" + os.environ.get('APPLICATION_VERSION')

    scanname = scanname + "-"

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
        if DEBUG:
            LOGGER.debug("error getting status: " + str(err))
        raise Exception("Invalid jobid")

    retval = 0
    try:
        retval = int(out)
    except ValueError:
        if DEBUG:
            LOGGER.debug("error getting status, converting val: " + str(out))
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
# a dict containing fields for "NLowIssues", "ReadStatus", et al
# per the list above
def appscan_info (jobid):

    # setup default (empty) return
    return_info = {}
    return_info['NLowIssues'] = 0
    return_info['ReadStatus'] = 0
    return_info['NHighIssues'] = 0
    return_info['Name'] = ""
    return_info['ScanEndTime'] = None
    return_info['Progress'] = 0
    return_info['RemainingFreeRescanMinutes'] = 0
    return_info['ParentJobId'] = ""
    return_info['EnableMailNotifications'] = False
    return_info['JobStatus'] = 0
    return_info['NInfoIssues'] = 0
    return_info['JobId'] = ""
    return_info['NIssuesFound'] = 0
    return_info['CreatedAt'] = None
    return_info['UserMessage'] = ""
    return_info['NMediumIssues'] = 0
    return_info['Result'] = 0

    if jobid == None:
        return return_info

    command = "appscan.sh info -i " + str(jobid)
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    for line in out.splitlines() :
        if "NLowIssues=" in line:
            # number of low severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['NLowIssues'] = int(tmpstr)
                except ValueError:
                    return_info['NLowIssues']= 0

        elif "NMediumIssues=" in line:
            # number of medium severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['NMediumIssues'] = int(tmpstr)
                except ValueError:
                    return_info['NMediumIssues'] = 0

        elif "NHighIssues=" in line:
            # number of high severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['NHighIssues'] = int(tmpstr)
                except ValueError:
                    return_info['NHighIssues'] = 0

        elif "NInfoIssues=" in line:
            # number of info severity issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['NInfoIssues'] = int(tmpstr)
                except ValueError:
                    return_info['NInfoIssues'] = 0

        elif "NIssuesFound=" in line:
            # total number of issues found in the scan
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['NIssuesFound'] = int(tmpstr)
                except ValueError:
                    return_info['NIssuesFound'] = 0

        elif "Progress=" in line:
            # current scan progress (0-100)
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['Progress'] = int(tmpstr)
                except ValueError:
                    return_info['Progress'] = 0

        elif "RemainingFreeRescanMinutes=" in line:
            # what the name says
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['RemainingFreeRescanMinutes'] = int(tmpstr)
                except ValueError:
                    return_info['RemainingFreeRescanMinutes'] = 0

        elif "JobStatus=" in line:
            # current job status
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['JobStatus'] = int(tmpstr)
                except ValueError:
                    return_info['JobStatus'] = 0

        elif "ReadStatus=" in line:
            # not sure what this is
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['ReadStatus'] = int(tmpstr)
                except ValueError:
                    return_info['ReadStatus'] = 0

        elif "Result=" in line:
            # final return code
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['Result'] = int(tmpstr)
                except ValueError:
                    return_info['Result'] = 0

        elif "ScanEndTime=" in line:
            # timestamp when this scan completed
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['ScanEndTime'] = datetime.strptime(tmpstr, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    return_info['ScanEndTime'] = None

        elif "CreatedAt=" in line:
            # timestamp when this job was created
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                try:
                    return_info['CreatedAt'] = datetime.strptime(tmpstr, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    return_info['CreatedAt'] = None

        elif "Name=" in line:
            # job name
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                return_info['Name'] = tmpstr

        elif "JobId=" in line:
            # job ID
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                return_info['JobId'] = tmpstr

        elif "ParentJobId=" in line:
            # parent job ID
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                return_info['ParentJobId'] = tmpstr

        elif "UserMessage=" in line:
            # user displayable message, current job state
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                return_info['UserMessage'] = tmpstr

        elif "EnableMailNotifications=" in line:
            # are email notifications setup (doesn't matter, we don't use it)
            tmpstr = parse_key_eq_val(line)
            if tmpstr != None:
                if tmpstr.lower() in ("yes", "true"):
                    return_info['EnableMailNotifications'] = True
                else:
                    return_info['EnableMailNotifications'] = False

    return return_info

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
def check_for_existing_job ( ignore_older_jobs = True):
    alljobs = appscan_list()
    if alljobs == None:
        # no jobs, ours can't be there
        return None

    # get the name we're looking for
    job_name = get_scanname_template( include_version = ignore_older_jobs )
    joblist = []
    found = False
    for jobid in alljobs:
        results = appscan_info(jobid)
        if results["Name"].startswith(job_name):
            joblist.append(jobid)
            found = True

    if found:
        return joblist
    else:
        return None

# don't want to have too many old copies of the job hanging out, it
# makes a mess and is hard to read.  prune old copies here
def cleanup_old_jobs ():
    # see how many copies we're going to keep
    try:
        count_to_keep = int(os.getenv('OLD_SCANS_TO_KEEP', DEFAULT_OLD_SCANS_TO_KEEP))
    except ValueError:
        count_to_keep = DEFAULT_OLD_SCANS_TO_KEEP_INT

    # if the count to keep is 0 or negative, keep all copies
    if count_to_keep < 1:
        return

    joblist = check_for_existing_job( ignore_older_jobs = False )
    if joblist == None or len(joblist) <= count_to_keep:
        # related job count < number of jobs too keep, do nothing
        return

    # too many jobs!  remove the oldest ones (cancel if necessary)
    if DEBUG:
        LOGGER.debug("Found " + str(len(joblist)) + " jobs pending with limit " + str(count_to_keep))

    # make a sorted list of these jobs (yes, this is O(n**2) algorithm, but
    # this should always be a fairly short list of scans)
    s_jobs = []
    for job in joblist:
        results = appscan_info(job)
        # if no results or time, this is not a valid job, skip it
        if (results['CreatedAt'] == None):
            continue
        # put it in the right spot in the list
        i = 0
        while i < len(s_jobs):
            if results['CreatedAt'] > s_jobs[i]['CreatedAt']:
                # found right place
                if DEBUG:
                    LOGGER.debug("Insert job " + str(results['Name']) + " at index " + str(i) + " for timestamp " + str(results['CreatedAt']))
                s_jobs[i:i] = results
                break
            i += 1
        if i==len(s_jobs):
            # right place is the end
            if DEBUG:
                LOGGER.debug("Append job " + str(results['Name']) + " at index " + str(i) + " for timestamp " + str(results['CreatedAt']))
            s_jobs.append(results)

    # now cleanup all jobs after the 'n' we're supposed to keep
    for index, res in enumerate(s_jobs):
        if index<count_to_keep:
            if DEBUG:
                LOGGER.debug("keeping: " + str(index) + " \"" + res['Name'] + "\" : " + str(res['JobId']))
        else:
            if DEBUG:
                LOGGER.debug("cleaning: " + str(index) + " \"" + res['Name'] + "\" : " + str(res['JobId']))
            appscan_cancel(res['JobId'])
    # and we're done

# wait for a given set of scans to complete and, if successful,
# download the results
def wait_for_scans (joblist):
    # were all jobs completed on return
    all_jobs_complete = True
    # number of high sev issues in completed jobs
    high_issue_count = 0
    dash = find_service_dashboard(STATIC_ANALYSIS_SERVICE)
    for jobid in joblist:
        try:
            while True:
                state = appscan_status(jobid)
                LOGGER.info("Job " + str(jobid) + " in state " + get_state_name(state))
                if get_state_completed(state):
                    results = appscan_info(jobid)
                    if get_state_successful(state):
                        high_issue_count += results["NHighIssues"]
                        LOGGER.info("Analysis successful (" + results["Name"] + ")")
                        #print "\tOther Message : " + msg
                        #appscan_get_result(jobid)
                        print LABEL_GREEN + STARS
                        print "Analysis successful for job \"" + results["Name"] + "\""
                        print "\tHigh Severity Issues   : " + str(results["NHighIssues"])
                        print "\tMedium Severity Issues : " + str(results["NMediumIssues"])
                        print "\tLow Severity Issues    : " + str(results["NLowIssues"])
                        print "\tInfo Severity Issues   : " + str(results["NInfoIssues"])
                        if dash != None:
                            print "See detailed results at: " + LABEL_COLOR + " " + dash
                        print LABEL_GREEN + STARS + LABEL_NO_COLOR
                    else: 
                        LOGGER.info("Analysis unsuccessful (" + results["Name"] + ") with message \"" + results["UserMessage"] + "\"")

                    break
                else:
                    time_left = get_remaining_wait_time()
                    if (time_left > SLEEP_TIME):
                        time.sleep(SLEEP_TIME)
                    else:
                        # ran out of time, flag that at least one job didn't complete
                        all_jobs_complete = False
                        # get what info we can on this job
                        results = appscan_info(jobid)
                        # notify the user
                        print LABEL_RED + STARS
                        print "Analysis incomplete for job \"" + results["Name"] + "\""
                        print "\t" + str(prog) + "% complete"
                        if dash != None:
                            print "Track current state and results at: " + LABEL_COLOR + " " + dash
                        print LABEL_RED + "Increase the time to wait and rerun this job. The existing analysis will continue and be found and tracked."
                        print STARS + LABEL_NO_COLOR

                        # and continue to get state for other jobs
                        break
        except Exception, e:
            # bad id, skip it
            if DEBUG:
                LOGGER.debug("exception in wait_for_scans: " + str(e))

    return all_jobs_complete, high_issue_count


# begin main execution sequence

try:
    parsed_args = parse_args()
    if parsed_args['help']:
        print_help()
        sys.exit(0)

    LOGGER = setup_logging()
    WAIT_TIME = get_remaining_wait_time(first = True)
    LOGGER.info("Getting credentials for Static Analysis service")
    creds = get_credentials_from_bound_app(service=STATIC_ANALYSIS_SERVICE)
    LOGGER.info("Connecting to Static Analysis service")
    appscan_login(creds['bindingid'],creds['password'])

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
        # see if we have related jobs
        joblist = check_for_existing_job()
        if joblist == None:
            # no related jobs, get whole list
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
    all_jobs_complete, high_issue_count = wait_for_scans(joblist)

    # force cleanup of all?
    if parsed_args['forcecleanup']:
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
    else:
        # cleanup old copies of this job
        cleanup_old_jobs()

    # if we didn't successfully complete jobs, return that we timed out
    if not all_jobs_complete:
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
        
        # send slack notification 
        dash = find_service_dashboard(STATIC_ANALYSIS_SERVICE)
        command='${EXT_DIR}/utilities/sendMessage.sh -l bad -m <{url}|Static security scan> did not complete within {wait}'.format(url=dash,state=WAIT_TIME)
        proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate();
        LOGGER.debug(out)

        sys.exit(2)
    else:
        print "Sending notifications"
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
        if high_issue_count > 0:
            # send slack notification 
            dash = find_service_dashboard(STATIC_ANALYSIS_SERVICE)
            command='${EXT_DIR}/utilities/sendMessage.sh -l good -m <{url}|Static security scan> completed with no major issues'.format(url=dash)
            proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate();
            LOGGER.debug(out)
            sys.exit(1)

        # send slack notification 
        dash = find_service_dashboard(STATIC_ANALYSIS_SERVICE)
        command='${EXT_DIR}/utilities/sendMessage.sh -l good -m <{url}|Static security scan> completed with no major issues'.format(url=dash)
        proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate();
        LOGGER.debug(out)

        sys.exit(0)

except Exception, e:
    LOGGER.warning("Exception received", exc_info=e)
    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
    sys.exit(1)
