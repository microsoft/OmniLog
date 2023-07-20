#!/bin/bash

boards_list=(
	mx6dhmbedge \
	mx6dlsabreauto \
	mx6dlsabresd \
	mx6dlhmbedge \
	mx6qsabrelite \
	mx6qsabresd \
	mx6qsabreauto
	mx6qhmbedge \
	mx6qpsabresd \
	mx6qpsabreauto \
	mx6shmbedge \
	mx6slevk \
	mx6sllevk \
	mx6solosabresd \
	mx6solosabreauto \
	mx6sxsabreauto \
	mx6sxsabresd \
	mx6sxudooneofull \
	mx6ulevk \
	mx6ul9x9evk \
	mx6ulccimx6ulsbcpro\
	mx6ullevk \
	mx7dsabresd \
	mx7dpico_mbl \
	mx7swarp7 \
	mx7swarp7_mbl \
	mx7dclsom \
	mx7ulpevk \
	mx8dxmek \
	mx8mqevk \
	mx8mmevk \
	mx8mnevk \
	mx8mpevk \
	mx8qxpmek \
	mx8qmmek \
	mx8dxlevk \
	ls1021atwr \
	ls1021aqds \
	ls1012ardb \
	ls1012afrwy \
	ls1043ardb \
	ls1046ardb \
	ls1088ardb \
	ls2088ardb \
	lx2160ardb \
)

CROSS_COMPILE="${CROSS_COMPILE:-arm-linux-gnueabihf-}"
CROSS_COMPILE64="${CROSS_COMPILE64:-aarch64-linux-gnu-}"
MKIMAGE="${MKIMAGE:-mkimage}"
O="${O:-.}"
NB_CORES="${NB_CORES:-1}"
CFG_TEE_CORE_LOG_LEVEL="${CFG_TEE_CORE_LOG_LEVEL:-1}"
CFG_TEE_TA_LOG_LEVEL="${CFG_TEE_TA_LOG_LEVEL:-0}"

mx67build()
{
	platform=$1 && \
	make -j$NB_CORES CROSS_COMPILE=${CROSS_COMPILE} CROSS_COMPILE64=${CROSS_COMPILE64} \
		CFG_TEE_CORE_LOG_LEVEL=${CFG_TEE_CORE_LOG_LEVEL} \
		CFG_TEE_TA_LOG_LEVEL=${CFG_TEE_TA_LOG_LEVEL} \
		CFG_WERROR=y \
		PLATFORM=imx PLATFORM_FLAVOR=$platform O=${O}/build.$platform && \
	${CROSS_COMPILE}objcopy -O binary ${O}/build.$platform/core/tee.elf ${O}/build.$platform/tee.bin && \
	ln -s -rf ${O}/build.$platform/tee.bin ${O}/build.$platform/tee-$platform.bin && \
	imx_load_addr=`${CROSS_COMPILE}readelf -h ${O}/build.$platform/core/tee.elf | grep "Entry point address" | awk '{print $4}'` && \
	${MKIMAGE} -A arm -O linux -C none -a $imx_load_addr -e $imx_load_addr \
			-d ${O}/build.$platform/tee.bin ${O}/build.$platform/uTee && \
	ln -s -rf ${O}/build.$platform/uTee ${O}/build.$platform/uTee-$platform && \
	return 0
}

mx8build()
{
	platform=$1 && \
	make -j$NB_CORES CROSS_COMPILE=${CROSS_COMPILE} CROSS_COMPILE64=${CROSS_COMPILE64} \
		PLATFORM=imx PLATFORM_FLAVOR=$platform O=${O}/build.$platform && \
	${CROSS_COMPILE64}objcopy -O binary ${O}/build.$platform/core/tee.elf ${O}/build.$platform/tee.bin && \
	ln -s -rf ${O}/build.$platform/tee.bin ${O}/build.$platform/tee-$platform.bin && \
	return 0
}

lsbuild()
{
	platform=$1 && \
	make -j$NB_CORES CROSS_COMPILE=${CROSS_COMPILE} CROSS_COMPILE64=${CROSS_COMPILE64} \
		PLATFORM=ls PLATFORM_FLAVOR=$platform O=${O}/build.$platform && \
	${CROSS_COMPILE64}objcopy -O binary ${O}/build.$platform/core/tee.elf ${O}/build.$platform/tee.bin && \
	ln -s -rf ${O}/build.$platform/tee.bin ${O}/build.$platform/tee-$platform.bin && \
	return 0
}

build()
{
	case $1 in
		mx[6-7]*) mx67build $1 ;;
		mx8*) mx8build $1 ;;
		l[s-x]*) lsbuild $1 ;;
		*) echo "No function to build $1"; return 0;;
	esac

}

list_board()
{

	i=0

	while ((i<=${#boards_list[@]}))
	do
		echo ${boards_list[i]}
		let ++i
	done
}

help()
{
	echo "Make sure you have you cross compile toolchain ready"
	echo "./build.sh help"
	echo "Build all boards"
	echo "./build.sh all"
	echo "Build all boards with only building error output"
	echo "./build.sh all-silence"
	echo "Build specfic board"
	echo "./build.sh 'boardname'"
	echo "supported boards:"
	list_board
}

arg_num=$#
if [ ${arg_num} -eq 0 ]
then
	help
	exit 0
fi

if [ "$1" == "help" ]
then
	help
	exit 0
fi

if [ "$1" == "all" ]
then
	i=0

	while ((i<${#boards_list[@]}))
	do
		echo "=============Building ${boards_list[i]}================"
		build ${boards_list[i]}
		if [ $? -ne 0 ]; then
			echo "=============Fail building ${boards_list[i]}================"
			exit 1
		fi
		let ++i
	done
	exit 0
fi

if [ "$1" == "all-silence" ]
then
	i=0

	while ((i<${#boards_list[@]}))
	do
		echo "=============Building ${boards_list[i]}================"
		build ${boards_list[i]} > /dev/null
		if [ $? -ne 0 ]; then
			echo "=============Fail building ${boards_list[i]}================"
			exit 1
		fi
		let ++i
	done
	exit 0
fi

build $1

