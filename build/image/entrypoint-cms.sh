#!/bin/bash

USER_ID=$(id -u)
LOG_PATH=/var/log/cms
CONFIG_PATH=/etc/cms
ROOT_CA_DIR=${CONFIG_PATH}/root-ca
INTERMEDIATE_CA_DIR=${CONFIG_PATH}/intermediate-ca
CERTDIR_TRUSTEDJWTCERTS=${CONFIG_PATH}/jwt

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTDIR_TRUSTEDJWTCERTS $ROOT_CA_DIR $INTERMEDIATE_CA_DIR; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  cms setup all --force
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

if [ ! -z $SETUP_TASK ]; then
  cp $CONFIG_PATH/config.yml /tmp/config.yml
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    cms setup $task --force
    if [ $? -ne 0 ]; then
      cp /tmp/config.yml $CONFIG_PATH/config.yml
      exit 1
    fi
  done
  rm -rf /tmp/config.yml
fi

cms run
