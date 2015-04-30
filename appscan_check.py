#!/usr/bin/python
import json
import os
import sys
from subprocess import Popen, PIPE

app = os.environ.get('BINDING_APP')
if app == None:
    print "BINDING_APP is not set - this must be set to get the proper credentials."
    sys.exit(1)

verProc = Popen(["cf env \"" + app + "\""], shell=True, stdout=PIPE, stderr=PIPE)
verOut, verErr = verProc.communicate();

if verProc.returncode != 0:
    print "Unable to read env vars off BINDING_APP - please check that it is set correctly."
    sys.exit(2)

envList = []
envIndex = 0
inSection = False
# do parsing to break down the vars
for line in verOut.splitlines():
    if inSection:
        envList[envIndex] += line
        if line.startswith("}"):
            inSection = False
            envIndex = envIndex+1
    elif line.startswith("{"): 
        envList.append(line)
	inSection = True

jsonEnvList = {}
for x in envList:
    jsonEnvList.update(json.loads(x))

userid = ""
password = ""

if jsonEnvList != None:
    serviceList = jsonEnvList['VCAP_SERVICES']
    if serviceList != None:
        analyzerService = serviceList['Static Analyzer']
        if analyzerService != None:
            credentials = analyzerService[0]['credentials']
            userid = credentials['bindingid']
            password = credentials['password']

if not (userid) or not (password):
    print "Unable to get bound credentials for access to the Static Analysis service."
    sys.exit(3)

loginProc = Popen(["appscan.sh login -u " + userid + " -P " + password + ""], shell=True, stdout=PIPE, stderr=PIPE)
loginOut, loginErr = loginProc.communicate();

print "out = " + loginOut
print "err = " + loginErr

listProc = Popen(["appscan.sh list"], shell=True, stdout=PIPE, stderr=PIPE)
listOut, listErr = loginProc.communicate();

print "out = " + listOut
print "err = " + listErr

