#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

set -x
set -e

pushd arm
pushd imx-optee-os

CROSS_COMPILE=arm-linux-gnueabihf- LDFLAGS= NB_CORES=$(nproc) ./scripts/nxp_build.sh mx8mqevk

popd
popd
