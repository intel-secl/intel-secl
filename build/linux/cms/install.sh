#!/bin/bash

COMPONENT_NAME=cms
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
if [ -f ~/cms.env ]; then
    echo Reading Installation options from `realpath ~/cms.env`
    env_file=~/cms.env
elif [ -f ../cms.env ]; then
    echo Reading Installation options from `realpath ../cms.env`
    env_file=../cms.env
fi

if [ -z $env_file ]; then
    echo "No .env file found"
    CMS_NOSETUP="true"
else
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Installing Certificate Management Service..."

COMPONENT_NAME=cms
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME

echo "Setting up Certificate Management Service Linux User..."
id -u cms 2> /dev/null || useradd --comment "Certificate Management Service" --home $PRODUCT_HOME  --shell /bin/false cms

mkdir -p $BIN_PATH && chown cms:cms $BIN_PATH/
cp $COMPONENT_NAME $BIN_PATH/ && chown cms:cms $BIN_PATH/*
chmod 750 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

# Create configuration directory in /etc
mkdir -p $CONFIG_PATH && chown cms:cms $CONFIG_PATH
chmod 700 $CONFIG_PATH

# Create jwt certs directory in config
mkdir -p $CONFIG_PATH/jwt && chown cms:cms $CONFIG_PATH/jwt
chmod 700 $CONFIG_PATH/jwt

mkdir -p $CONFIG_PATH/root-ca && chown cms:cms $CONFIG_PATH/root-ca
chmod 700 $CONFIG_PATH/root-ca

mkdir -p $CONFIG_PATH/intermediate-ca && chown cms:cms $CONFIG_PATH/intermediate-ca
chmod 700 $CONFIG_PATH/intermediate-ca

# Create logging dir in /var/log
mkdir -p $LOG_PATH && chown cms:cms $LOG_PATH
chmod 740 $LOG_PATH

# Install systemd script
cp cms.service $PRODUCT_HOME && chown cms:cms $PRODUCT_HOME/cms.service && chown cms:cms $PRODUCT_HOME

# Enable systemd service
#systemctl disable cms.service > /dev/null 2>&1
#systemctl enable $PRODUCT_HOME/cms.service
#systemctl daemon-reload

#Install log rotation
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

if [ ! -a /etc/logrotate.d/cms ]; then
 echo "/var/log/cms/*.log {
    missingok
    notifempty
    rotate $LOG_OLD
    maxsize $LOG_SIZE
    nodateext
    $LOG_ROTATION_PERIOD
    $LOG_COMPRESS
    $LOG_DELAYCOMPRESS
    $LOG_COPYTRUNCATE
}" > /etc/logrotate.d/cms
fi

# check if CMS_NOSETUP is defined
if [ "${CMS_NOSETUP,,}" == "true" ]; then
    echo "CMS_NOSETUP is true, skipping setup"
    echo "Run command \"cms setup all\" and start server"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup all -f $env_file --force
    SETUPRESULT=$?
    chown -R cms:cms /etc/cms/
    if [ ${SETUPRESULT} == 0 ]; then 
        #systemctl start $COMPONENT_NAME
        #echo "Waiting for daemon to settle down before checking status"
        #sleep 3
        #systemctl status $COMPONENT_NAME 2>&1 > /dev/null
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
