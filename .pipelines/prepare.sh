#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

sudo apt update
sudo apt install -y \
	build-essential \
	libncurses-dev \
	bison \
	flex \
	libssl-dev \
	libelf-dev \
	gcc-aarch64-linux-gnu \
	gcc-arm-linux-gnueabihf \
	binutils-aarch64-linux-gnu

sudo apt install -y \
	adb \
	acpica-tools \
	autoconf \
	automake \
	bc \
	ccache \
	cscope \
	curl \
	device-tree-compiler \
	e2tools \
	expect \
	fastboot \
	ftp-upload \
	gdisk \
	libattr1-dev \
	libcap-dev \
	libfdt-dev \
	libftdi-dev \
	libglib2.0-dev \
	libgmp3-dev \
	libhidapi-dev \
	libmpc-dev \
	libncurses5-dev \
	libpixman-1-dev \
	libslirp-dev \
	libtool \
	libusb-1.0-0-dev \
	make \
	mtools \
	netcat \
	ninja-build \
	python3-cryptography \
	python3-pip \
	python3-pyelftools \
	python3-serial \
	python-is-python3 \
	rsync \
	swig \
	unzip \
	uuid-dev \
	xdg-utils \
	xterm \
	xz-utils \
	zlib1g-dev
