/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fu-input-stream.h"

typedef GMemoryInputStream FuMemoryInputStream;		  /* nocheck:blocked */
typedef GMemoryInputStreamClass FuMemoryInputStreamClass; /* nocheck:blocked */

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FuMemoryInputStream, g_object_unref) /* nocheck:blocked */
#define FU_MEMORY_INPUT_STREAM(o)    G_MEMORY_INPUT_STREAM(o)	   /* nocheck:blocked */
#define FU_TYPE_MEMORY_INPUT_STREAM  G_TYPE_MEMORY_INPUT_STREAM	   /* nocheck:blocked */
#define FU_IS_MEMORY_INPUT_STREAM(o) G_IS_MEMORY_INPUT_STREAM(o)   /* nocheck:blocked */

FuInputStream *
fu_memory_input_stream_new(void); /* nocheck:blocked */
FuInputStream *
fu_memory_input_stream_new_from_bytes(GBytes *bytes) G_GNUC_NON_NULL(1); /* nocheck:blocked */
FuInputStream *
fu_memory_input_stream_new_from_data(const void *data,
				     gssize len,
				     GDestroyNotify destroy); /* nocheck:blocked */
