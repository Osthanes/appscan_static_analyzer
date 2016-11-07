#!/bin/bash

function dra_commands {
    echo -e "${no_color}"
    node_modules_dir=`npm root`

    dra_grunt_command="grunt --gruntfile=$node_modules_dir/grunt-idra3/idra.js"
    dra_grunt_command="$dra_grunt_command -testResult=\"$1\""
    dra_grunt_command="$dra_grunt_command -stage=\"$3\""

    debugme echo -e "dra_grunt_command with log & stage: \n\t$dra_grunt_command"

    if [ -n "$2" ] && [ "$2" != " " ]; then

        debugme echo -e "\tartifact: '$2' is defined and not empty"
        dra_grunt_command="$dra_grunt_command -artifact=\"$2\""
        debugme echo -e "\tdra_grunt_command: \n\t\t$dra_grunt_command"

    else
        debugme echo -e "\tartifact: '$2' is not defined or is empty"
        debugme echo -e "${no_color}"
    fi


    debugme echo -e "FINAL dra_grunt_command: $dra_grunt_command"
    debugme echo -e "${no_color}"


    eval "$dra_grunt_command -f --no-color"
    GRUNT_RESULT=$?

    debugme echo "GRUNT_RESULT: $GRUNT_RESULT"

    if [ $GRUNT_RESULT -ne 0 ]; then
        exit 1
    fi

    echo -e "${no_color}"
}







installDRADependencies

echo ""

for zipFile in appscan-*.zip;
do
    # unzip the appscan results
    resultDirectory="appscanResultDir"
    unzip $zipFile -d $resultDirectory

    # full report location
    export DRA_LOG_FILE="$EXT_DIR/$resultDirectory/Report-final.xml"
    # summary report location. Replace appscan-app.zip with appscan-app.json.
    export DRA_SUMMARY_FILE="$EXT_DIR/${zipFile%.zip}.json"

    # Upload to DRA

    # upload the full appscan report
    dra_commands "${DRA_LOG_FILE}" "${zipFile}" "codescan"
    # upload the summary appscan report
    dra_commands "${DRA_SUMMARY_FILE}" "${DRA_SUMMARY_FILE}" "codescansummary"



    # Clean up directory
    rm -r $resultDirectory
done
