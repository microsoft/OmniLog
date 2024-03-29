#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

set -x
set -e

pushd arm
pushd imx-atf

CROSS_COMPILE=aarch64-linux-gnu- make -j$(nproc) PLAT=imx8mq SPD=opteed bl31

popd
popd
