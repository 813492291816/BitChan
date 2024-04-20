# Update remote bitchan system (no docker) and restart frontend/backend
#
# Dependencies:
# sudo apt install coreutils torsocks sshpass
#
NOW=$(date '+%Y-%m-%d_%H-%M-%S')

set -e

provide_path() {
    printf "Must provide local bitchan path, user, IP address, remote bitchan path, and to restart (1) or not restart (0) frontend/backend services..\nExample: ./VPS_update_no_docker.sh /local/path/to/BitChan/ root 123.4.5.6 /user/local/bitchan/BitChan 1\n"
    exit
}

if [ -z $1 ]; then
  echo "Missing first argument: Path to local BitChan directory to transfer."
  provide_path
fi

if [ -z $2 ]; then
  echo "Missing second argument: User to log in with."
  provide_path
fi

if [ -z $3 ]; then
  echo "Missing third argument: IP address to transfer to."
  provide_path
fi

if [ -z $4 ]; then
  echo "Missing fourth argument: Path to remote BitChan directory."
  provide_path
fi

if [ -z $5 ]; then
  echo "Missing sixth argument: restart services (1) (default) or don't restart services (0)."
  provide_path
fi

if [ ! -d "$1" ]; then
   echo "Invalid directory"
   provide_path
fi

DIR_BITCHAN=$(realpath "$1")

if [ ! -f "${DIR_BITCHAN}/config.py" ]; then
   echo "Invalid bitchan directory"
   provide_path
fi

printf "Beginning transfer to remote bitchan system and restart frontend/backend at ${NOW}\n"

printf "\n"

CMD1="rsync -e ssh -r -a --progress --partial \
	${DIR_BITCHAN}/database \
	${DIR_BITCHAN}/docker \
	${DIR_BITCHAN}/flask_routes \
	${DIR_BITCHAN}/forms \
	${DIR_BITCHAN}/install_files \
	${DIR_BITCHAN}/scripts_dev \
	${DIR_BITCHAN}/static \
	${DIR_BITCHAN}/templates \
	${DIR_BITCHAN}/utils \
	${DIR_BITCHAN}/bitchan_client.py \
	${DIR_BITCHAN}/bitchan_daemon.py \
	${DIR_BITCHAN}/bitchan_flask.py \
	${DIR_BITCHAN}/config.py \
	${DIR_BITCHAN}/requirements.txt \
	${DIR_BITCHAN}/requirements_bitmessage.txt \
	${2}@${3}:${4}"

printf "Transferring files with torsocks...\n"
torsocks ${CMD1}

printf "Finished transferring files.\n"

if [ "$5" -eq "1" ]; then
    printf "Restarting services.\n"
    CMD2="service bitchan_frontend restart && service bitchan_backend restart"

    printf "Restarting services with torsocks...\n"
    torsocks ssh "${2}@${3}" ${CMD2}

else
    printf "Not restarting services.\n"
fi
