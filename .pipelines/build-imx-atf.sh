#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

set -x
set -e

pushd imx-atf ${BASE_KERNEL}

CROSS_COMPILE=aarch64-linux-gnu- make -j$(nproc) PLAT=imx8mq LOG_LEVEL=40 SPD=opteed bl31

popd
