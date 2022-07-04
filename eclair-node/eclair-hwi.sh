#!/bin/bash

echo $* >> cmd.log
ECLAIR="eclair-cli -a localhost:8080 -p foobar"
COMMAND=""

parse() {
	while [ -n "$1" ]; do # while loop starts
		case "$1" in
			enumerate) COMMAND="enumerate $COMMAND" ;; 
			getmasterxpub) COMMAND="getmasterxpub $COMMAND" ;;
			getdescriptors) COMMAND="getdescriptors $COMMAND" ;;
			signtx) COMMAND="signtx --psbt=$2 $COMMAND"; shift ;;
			--fingerprint) COMMAND="$COMMAND --fingerprint=$2"; shift ;;
			--chain) COMMAND="$COMMAND --chain=$2"; shift ;;
			--account) COMMAND="$COMMAND --account=$2"; shift ;;
			--stdin)
				read -r cmdline
				echo cmdline is $cmdline >> cmd.log
				;;
			*) echo "Option $1 not recognized" ;;
		esac
		shift
	done
}

parse $*
set -- $cmdline
parse $*

echo "echo \`$ECLAIR $COMMAND\`" >> cmd.log
RESULT=`$ECLAIR $COMMAND`
echo $RESULT >> cmd.log
echo $RESULT
