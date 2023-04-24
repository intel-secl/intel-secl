#!/bin/bash

COMPONENT_NAME=authservice
# Upgrade if component is already installed
if command -v $COMPONENT_NAME &>/dev/null; then
  echo "$COMPONENT_NAME is installed, proceeding with the upgrade"
  ./${COMPONENT_NAME}_upgrade.sh
  exit $?
fi

# Check OS
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)
temp="${OS%\"}"
temp="${temp#\"}"
OS="$temp"

# READ .env file 
echo PWD IS $(pwd)
if [ -f ~/authservice.env ]; then 
    echo Reading Installation options from `realpath ~/authservice.env`
    env_file=~/authservice.env
elif [ -f ../authservice.env ]; then
    echo Reading Installation options from `realpath ../authservice.env`
    env_file=../authservice.env
fi

if [ -z $env_file ]; then
    echo "No .env file found"
    AAS_NOSETUP="true"
else
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

SERVICE_USERNAME=aas

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up Auth Service Linux User..."
# useradd -M -> this user has no home directory
id -u $SERVICE_USERNAME 2> /dev/null || useradd -M --system --shell /sbin/nologin $SERVICE_USERNAME

echo "Installing Auth Service..."

COMPONENT_NAME=authservice
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
DB_SCRIPT_PATH=$PRODUCT_HOME/dbscripts
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/
CERTS_PATH=$CONFIG_PATH/certs
CERTDIR_TOKENSIGN=$CERTS_PATH/tokensign
CERTDIR_TRUSTEDJWTCAS=$CERTS_PATH/trustedca

for directory in $BIN_PATH $DB_SCRIPT_PATH $LOG_PATH $CONFIG_PATH $CERTS_PATH $CERTDIR_TOKENSIGN $CERTDIR_TRUSTEDJWTCAS; do
  # mkdir -p will return 0 if directory exists or is a symlink to an existing directory or directory and parents can be created
  mkdir -p $directory
  if [ $? -ne 0 ]; then
    echo "Cannot create directory: $directory"
    exit 1
  fi
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $directory
  chmod 700 $directory
done

cp $COMPONENT_NAME $BIN_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $BIN_PATH/*
chmod 700 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

cp db_rotation.sql $DB_SCRIPT_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $DB_SCRIPT_PATH/*

# log file permission change
chmod 740 $LOG_PATH

# Install systemd script
cp authservice.service $PRODUCT_HOME && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME/authservice.service && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME

# Enable systemd service
#systemctl disable authservice.service > /dev/null 2>&1
#systemctl enable $PRODUCT_HOME/authservice.service
#systemctl daemon-reload
/usr/bin/authservice run &

auto_install() {
  local component=${1}
  local cprefix=${2}
  local packages=$(eval "echo \$${cprefix}_PACKAGES")
  # detect available package management tools. start with the less likely ones to differentiate.
if [ "$OS" == "rhel" ]
then
  yum -y install $packages
elif [ "$OS" == "ubuntu" ]
then
  apt -y install $packages
fi
}

# SCRIPT EXECUTION
logRotate_clear() {
  logrotate=""
}

logRotate_detect() {
  local logrotaterc=`ls -1 /etc/logrotate.conf 2>/dev/null | tail -n 1`
  logrotate=`which logrotate 2>/dev/null`
  if [ -z "$logrotate" ] && [ -f "/usr/sbin/logrotate" ]; then
    logrotate="/usr/sbin/logrotate"
  fi
}

logRotate_install() {
  LOGROTATE_PACKAGES="logrotate"
  if [ "$(whoami)" == "root" ]; then
    auto_install "Log Rotate" "LOGROTATE"
    if [ $? -ne 0 ]; then echo "Failed to install logrotate"; exit -1; fi
  fi
  logRotate_clear; logRotate_detect;
    if [ -z "$logrotate" ]; then
      echo "logrotate is not installed"
    else
      echo  "logrotate installed in $logrotate"
    fi
}

logRotate_install

export LOG_ROTATION_PERIOD=${LOG_ROTATION_PERIOD:-weekly}
export LOG_COMPRESS=${LOG_COMPRESS:-compress}
export LOG_DELAYCOMPRESS=${LOG_DELAYCOMPRESS:-delaycompress}
export LOG_COPYTRUNCATE=${LOG_COPYTRUNCATE:-copytruncate}
export LOG_SIZE=${LOG_SIZE:-100M}
export LOG_OLD=${LOG_OLD:-12}

mkdir -p /etc/logrotate.d

if [ ! -a /etc/logrotate.d/aas ]; then
 echo "/var/log/authservice/*.log {
    missingok
    notifempty
    rotate $LOG_OLD
    maxsize $LOG_SIZE
    nodateext
    $LOG_ROTATION_PERIOD
    $LOG_COMPRESS
    $LOG_DELAYCOMPRESS
    $LOG_COPYTRUNCATE
}" > /etc/logrotate.d/aas
fi


# check if AAS_NOSETUP is defined
if [ "${AAS_NOSETUP,,}" == "true" ]; then
    echo "AAS_NOSETUP is true, skipping setup"
    echo "Run \"authservice setup all\" for manual setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup all --force
    SETUPRESULT=$?
    chown -R aas:aas /etc/authservice/
    if [ ${SETUPRESULT} == 0 ]; then 
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi
