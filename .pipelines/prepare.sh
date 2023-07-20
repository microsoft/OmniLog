#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

sudo apt update
sudo apt install -y \
	wget \
	build-essential \
	libncurses-dev \
	bison \
	flex \
	libssl-dev \
	libelf-dev \
	gcc-aarch64-linux-gnu \
	gcc-arm-linux-gnueabihf \
	binutils-aarch64-linux-gnu

pip3 install pycryptodomex
