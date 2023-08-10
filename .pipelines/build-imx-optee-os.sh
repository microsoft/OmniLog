#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

set -x
set -e

pushd imx-optee-os
CROSS_COMPILE=arm-linux-gnueabihf- CFG_TEE_CORE_LOG_LEVEL=4 CFG_TEE_TA_LOG_LEVEL=4 LDFLAGS= NB_CORES=$(nproc) ./scripts/nxp_build.sh mx8mqevk

popd
