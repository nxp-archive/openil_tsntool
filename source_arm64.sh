#!/bin/bash
if [ ! -n "$1" ]
then
	echo "How to use:"
	echo "source source_arm64.sh <dir_to_kernel>"
fi

if [ ! -f $1/.config ]
then
	echo "Not right kernel folder"
fi

if [ ! -f $1/include/uapi/linux/tsn.h ]
then
	echo "Not right kernel folder"
fi

export KERNELDIR=$1
export PKG_CONFIG_SYSROOT_DIR=
export PKG_CONFIG_PATH=$SDKTARGETSYSROOT/lib/pkgconfig

if [ ! -f ./include/linux/tsn.h ]; then
	sudo mkdir include/linux/
fi

sudo cp ${KERNELDIR}/include/uapi/linux/tsn.h include/linux/
