#! /bin/bash

pwd="$(cd $(dirname $0) && pwd)"
THIR_PATH=${pwd}/../thirparty
LIBPCAP_PATH=${pwd}/../lib/libpcap
SRC_PATH=${pwd}/../src
SEND_PATH=${pwd}/..
LIB_PATH=${pwd}/../lib

export LIB_PATH
export SEND_PATH

MAKE="make"

CLEAN="n"

if [ $# -gt 0 ];then
	case $1 in 
	clean)
		CLEAN="y";;
	esac
fi

if [ ${CLEAN} == "y" ];then
	cd ${SRC_PATH}
	${MAKE} clean LIB_PATH=${LIBPCAP_PATH} SEND_PATH=${SEND_PATH}
	echo "pcap_send target file clean!"
	exit 1
fi

LIBPCAP_RELEASE=libpcap-1.1.1
LIBPCAP_TAR=${THIR_PATH}/${LIBPCAP_RELEASE}.tar.gz

echo "############################################   build libpcap   #########################################"
if [ ! -e ${LIBPCAP_PATH}/lib/libpcap.a ]
then
	if [ ! -d ${THIR_PATH}/libpcap ]
	then
		if [ ! -e ${LIBPCAP_TAR} ]
		then
			echo "Error: src libpcap not exists!"
			exit 1
		fi
		
		cd ${THIR_PATH}
		tar zxvf ${LIBPCAP_TAR}
		mv ${LIBPCAP_RELEASE} libpcap
	fi
	
	cd ${THIR_PATH}/libpcap
	rm -rf ${LIBPCAP_PATH}
	#chmod -R 755 ${LIBPCAP_SRC_PATH}
	./configure --prefix=${LIBPCAP_PATH} --build=i686-pc-linux
	make
	make install
fi

if [ ! -e ${LIBPCAP_PATH}/lib/libpcap.a ]
then
	echo "##########################################  Error: build libpcap error! #####################################"
	exit 1
else
	cd ${LIBPCAP_PATH}/lib
	rm -rf *so*
fi

if [ -d ${LIBPCAP_SRC_PATH} ];then
	rm -rf ${LIBPCAP_SRC_PATH}
fi

cd ${SRC_PATH}

if [ ${CLEAN} == "y" ];then
	${MAKE} clean LIB_PATH=${LIBPCAP_PATH} SEND_PATH=${SEND_PATH}
fi

${MAKE} LIB_PATH=${LIBPCAP_PATH} SEND_PATH=${SEND_PATH}

${MAKE} link LIB_PATH=${LIBPCAP_PATH} SEND_PATH=${SEND_PATH} 
