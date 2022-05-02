#
# Dependencies:
# sudo apt install realpath torsocks sshpass
#
NOW=$(date '+%Y-%m-%d_%H-%M-%S')

set -e

provide_path() {
    printf "Must provide local bitchan path, user, IP address, remote destination path, and to build (1) or not to build (0). If you don't instruct this script to build, everything except building will be done and you must log in and build yourself.\nExample: /script.sh /path/to/bitchan user 123.4.5.6 /user 1\n"
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
  echo "Missing fourth argument: Path to transfer archive."
  provide_path
fi

if [ -z $5 ]; then
  echo "Missing fifth argument: Build (1) or don't build (0)."
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
   exit
fi

printf "Beginning transfer to remote system and rebuild at ${NOW}\n"

DIR_BITCHAN_PARENT="$(dirname "${DIR_BITCHAN}")"

DIR_BITCHAN_TAR=$(realpath ~)

# archive local dev folder to kiosk and build
TAR_DIR="${DIR_BITCHAN_TAR}/bitchan-${NOW}.tar.gz"
TAR="bitchan-${NOW}.tar.gz"

if ! tar --exclude='.idea' --exclude='.git' --exclude='env' -zcf "${TAR_DIR}" -C "${DIR_BITCHAN_PARENT}" ./bitchan ; then
   echo "Could not archive BitChan directory"
   exit
fi

read -s -p "Password: " password
sshpass -p ${password} torsocks scp "${TAR_DIR}" "${2}@${3}:${4}"

printf "\n"

rm -rf "${TAR}"

CMD1="mv ~/bitchan ~/bitchan-${NOW} &&
tar zxf ${TAR} &&
cp ~/bitchan-${NOW}/credentials.py ~/bitchan/ &&
cp ~/bitchan-${NOW}/docker/docker-compose.yml ~/bitchan/docker/ &&
cp ~/bitchan-${NOW}/docker/tor/torrc ~/bitchan/docker/tor/"

RESULTS1=$(sshpass -p ${password} torsocks ssh "${2}@${3}" ${CMD1} 2>&1)
echo $RESULTS1

printf "Finished transferring and moving directories.\n"

if [ "$5" -eq "1" ]; then
    printf "Building. This can take a while.\n"
    CMD2="
    cd ~/bitchan/docker &&
    make daemon &&
    printf 'SUCCESS'"

    RESULTS2=$(sshpass -p ${password} torsocks ssh "${2}@${3}" ${CMD2} 2>&1)
    echo $RESULTS2
else
    printf "Not Building. You will need to log in and build yourself.\n"
fi
