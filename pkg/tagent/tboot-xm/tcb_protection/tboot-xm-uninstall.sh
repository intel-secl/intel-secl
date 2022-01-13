#!/bin/bash

#This scripts uninstall the tboot-xm components on compute node
TBOOTXM_ENV_FILE="/opt/tbootxm/env/tbootxm-layout"
source $TBOOTXM_ENV_FILE

. $TBOOTXM_BIN/functions.sh
KERNEL_VERSION=`uname -r`
GRUB_UPDATE="grub2-mkconfig -o $GRUB_FILE"
REMOVE_GRUB_ENTRY_SCRIPT="${TBOOTXM_LIB}/remove_menuentry.pl"
GRUB_ENTRY_FILE=""
MENUENTRY_PREFIX="TCB-Protection"
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
TBOOTXM_CONF_FILE="/tbootxm.conf"

# check the flavour of OS
function which_flavour()
{
    flavour=""
    grep -c -i ubuntu /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="ubuntu"
    fi
    grep -c -i "red hat" /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="rhel"
    fi
    grep -c -i fedora /etc/*-release > /dev/null
    if [ $? -eq 0 ] && [ $flavour == "" ]; then
            flavour="fedora"
    fi
    grep -c -i "SuSE" /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="suse"
    fi
    grep -c -i centos /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="centos"
    fi
    if [ "$flavour" == "" ]; then
            echo "Unsupported linux flavor, Supported versions are ubuntu, rhel, fedora, centos and suse"
            exit 1
    else
            echo $flavour
    fi
}

#find out the grub version
function which_grub() {

        os_version=`which_flavour`
        GRUB_VERSION=""

        if [ $os_version == "fedora" ] ; then
                grub2-install --version | grep " 2."
                GRUB_VERSION=2
                return
        elif [ $os_version == "suse" ] ; then
                zypper info grub | grep -i version | grep " 0."
                if [ $? -eq 0 ] ; then
                        GRUB_VERSION=0
                        return
                fi
        elif [ $os_version == "rhel" ] && [ -n "`which grub2-install 2>/dev/null`" ] ; then
                grub2-install --version | grep " 2."
                GRUB_VERSION=2
                return
        fi

        grub-install --version | grep " 2."
        if [ $? -eq 0 ]
        then
                GRUB_VERSION=2
                return
        fi
        grub-install --version | grep " 0."
        if [ $? -eq 0 ]
        then
                GRUB_VERSION=0
                return
        fi
        grub-install --version | grep " 1."
        if [ $? -eq 0 ]
        then
                GRUB_VERSION=1
                return
        fi
}


function isRhel8WithoutTboot()
{
    uname -r | grep "\.el8" > /dev/null 2>&1
	local isRhel8=$?

	which txt-stat > /dev/null 2>&1
	local tbootInstalled=$?

    if [[ $isRhel8 -eq 0 ]]
	then
		if [[ $tbootInstalled -ne 0 ]] 
		then
			return 0
		fi
	fi

	return 1
}

#Remove the TCB-Protection grub entry
function remove_grub_entry()
{
	if isRhel8WithoutTboot
	then
		ENTRY=`grep -l "${MENUENTRY_PREFIX}" /boot/loader/entries/*conf | tail -1`
		if [ ! -z "$ENTRY" ]
		then
			rm "$ENTRY"
		else
			echo_failure "Could not locate $MENUENTRY_PREFIX entry in /boot/loader/entries"
		fi
	elif [ `grep -c "$MENUENTRY_PREFIX" $GRUB_ENTRY_FILE` -gt 0 ]
	then
		echo "$MENUENTRY_PREFIX grub entry found"
		echo "proceeding to remove the grub entry from file $GRUB_ENTRY_FILE"
		perl $REMOVE_GRUB_ENTRY_SCRIPT "$GRUB_VERSION" "$GRUB_ENTRY_FILE" "$MENUENTRY_PREFIX"
		if [ $? -ne 0 ]
		then
			echo_failure "Uninstaller failed to remove $MENUENTRY_PREFIX grub entry"
			echo "Please remove entry manually"
		else
			echo_success "Successfully removed the $MENUENTRY_PREFIX grub entry from file $GURB_ENTRY_FILE"
		fi
	else
		echo_warning "$MENUENTRY_PREFIX entry not found in file $GRUB_ENTRY_FILE"
	fi
}

#update the grub file after removing TCB-Protection entry
function update_grub_entry()
{
	if [ $GRUB_VERSION -eq 1 ] || [ $GRUB_VERSION -eq 2 ]
	then
		echo "updating the grub file"
		if [ $os_version == "fedora" ] || [ $os_version == "rhel" ]; then
			ERROR_LOG_FILE=/tmp/grubupdate.err
			$GRUB_UPDATE 2>$ERROR_LOG_FILE
			if [ $? -ne 0 ]
			then
			  echo_warning "Error updating grub file, check $ERROR_LOG_FILE file for details"
			fi
		else
			update-grub
		fi
	fi
}

#remove the ISecL initrd
function remove_initrd()
{
	rm /boot/${INITRD_NAME}
	if [ $? -eq 0 ]
	then
		echo "successfully removed ISecL initrd"
	else
		echo_warning "seems like ISecL initrd is not present for current kernel version"
	fi
}

#Remove tbootxm files
function remove_tbootxm_files()
{
	rm -rf $TBOOTXM_HOME
	if [ $? -eq 0 ]
	then
		echo "Successfully removed tbootxm files"
	else
		echo_warning "seems like tbootxm is not installed on the machine"
	fi
	rm $TBOOTXM_CONF_FILE 2>/dev/null
}

#Remove library path
function remove_library_path()
{
    if [ -e "/etc/ld.so.conf.d/wml.conf" ]; then
        rm /etc/ld.so.conf.d/wml.conf
    fi
	if [ $? -eq 0 ]
	then
		echo "Successfully removed WML path"
	else
		echo_warning "seems like WML path is not set on the machine"
	fi
}

function main()
{
	which_grub
	if [ $GRUB_VERSION -eq 0 ]
	then
		GRUB_ENTRY_FILE="$GRUB_FILE"
		GRUB_DEFAULT_FILE="$GRUB_FILE"
	elif [ $GRUB_VERSION -eq 1 ] || [ $GRUB_VERSION -eq 2 ]
	then
		GRUB_ENTRY_FILE="/etc/grub.d/40_custom"
		GRUB_DEFAULT_FILE="/etc/default/grub"
	fi
	echo "removing grub entry from $GRUB_ENTRY_FILE"
	remove_grub_entry
	echo_warning "default grub entry will be changed to first entry in GRUB file"
	if [ $GRUB_VERSION -eq 0 ]
	then
		sed -i s/default=[0-9]*/default=0/ $GRUB_DEFAULT_FILE
	elif [ $GRUB_VERSION -eq 1 ] || [ $GRUB_VERSION -eq 2 ]
	then
		sed -i s/^GRUB_DEFAULT=.*/GRUB_DEFAULT=0/ $GRUB_DEFAULT_FILE
	fi
	update_grub_entry
	remove_initrd
	remove_tbootxm_files
	remove_library_path
	echo_success "tboot-xm uninstall complete"
}

function help()
{
        echo "		tboot-xm uninstall script"
        echo "Usage:"
        echo "          $0				- uninstal the tbootxm"
        echo "          $0 -h or --help			- print this help"
}

if [ $# -eq 1 ] && [ "$1" == "--help" -o "$1" == "-h" ]
then
	help
elif [ $# -ge 1 ]
then
	echo "invalid options"
	help
	exit 1
else
	main
fi
