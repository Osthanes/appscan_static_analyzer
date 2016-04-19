#!/bin/bash

# ----------------------------------------------------------------------------
#  AppScan Static Analyzer script for Linux/Cygwin/OSX
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# THIS PRODUCT CONTAINS RESTRICTED MATERIALS OF IBM
# IBM Security AppScan Source (C) COPYRIGHT International Business Machines Corp., 2014
# All Rights Reserved * Licensed Materials - Property of IBM
# US Government Users Restricted Rights - Use, duplication or disclosure
# restricted by GSA ADP Schedule Contract with IBM Corp. 
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# ENVIRONMENT VARIABLES
#
# Optional:
# 	APPSCAN_OPTS - Parameters passed to the Java JVM when running AppScan
# 		e.g. To enable FIPS for IBM SDK use:
#			set APPSCAN_OPTS=-Dcom.ibm.jsse2.usefipsprovider=true property
# ----------------------------------------------------------------------------

if [ -n "$APPSCAN_INTERNAL" ] ; then
	APPSCAN_OPTS="-DINTERNAL_SERVER=$APPSCAN_INTERNAL $APPSCAN_OPTS"
	echo .
	echo WARNING: The APPSCAN_INTERNAL environment variable has been replaced with the Java property -DINTERNAL_SERVER.
	echo e.g. export APPSCAN_OPTS=-DINTERNAL_SERVER=\<server\>
	echo .
fi
if [ -n "$APPSCAN_DOMAIN" ] ; then
	APPSCAN_OPTS="-DBLUEMIX_SERVER=$APPSCAN_DOMAIN $APPSCAN_OPTS"
	echo .
	echo WARNING: The APPSCAN_DOMAIN environment variable has been replaced with the Java property -DBLUEMIX_SERVER.
	echo e.g. export APPSCAN_OPTS=-DBLUEMIX_SERVER=\<server\>
	echo .
fi

export APPSCAN_INSTALL_DIR=`dirname "${BASH_SOURCE[0]}"`/../
APPSCAN_INSTALL_DIR=`readlink -f $APPSCAN_INSTALL_DIR`
die ( ) {
    echo
    echo "$*"
    echo
    exit 1
}

# For Cygwin, ensure paths are in UNIX format before anything is touched.
if [[ `uname` == CYGWIN* ]] ; then
    [ -n "$JAVA_HOME" ] && JAVA_HOME=`cygpath --unix "$JAVA_HOME"`
fi

# Set JAVA_HOME if it doesn't exist
if [ ! -n "$JAVA_HOME" ] ; then
	export JAVA_HOME=$APPSCAN_INSTALL_DIR/jre
fi

if [ "x$APPSCAN_INSTALL_DIR" == x ] ; then
	die "ERROR: APPSCAN_INSTALL_DIR is not set"
fi

# Process additional configuration
if [ -f "$APPSCAN_INSTALL_DIR/config/cli.config" ] ; then
	CLI_CONFIG_OPTS="$(paste -s $APPSCAN_INSTALL_DIR/config/cli.config)"
fi

export LD_LIBRARY_PATH=$APPSCAN_INSTALL_DIR/bin:$LD_LIBRARY_PATH

JAVACMD="$APPSCAN_INSTALL_DIR/jre/bin/java"

if [ $# -eq 0 ] ; then
	"$JAVACMD" $CLI_CONFIG_OPTS $APPSCAN_OPTS -cp "$APPSCAN_INSTALL_DIR/lib/*" com.ibm.appscan.cli.common.Launcher "$APPSCAN_INSTALL_DIR" help
else
	"$JAVACMD" $CLI_CONFIG_OPTS $APPSCAN_OPTS -cp "$APPSCAN_INSTALL_DIR/lib/*" com.ibm.appscan.cli.common.Launcher "$APPSCAN_INSTALL_DIR" "$@"
fi
echo
