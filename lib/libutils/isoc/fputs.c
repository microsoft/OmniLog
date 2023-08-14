// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <trace.h>

int fputs(const char *s __maybe_unused, FILE *stream)
{
	if (stream != stdout && stream != stderr)
		abort();
#if TRACE_LEVEL > 0
	trace_ext_puts(s);
#endif
	return 0;
}
