// SPDX-License-Identifier: Apache-2.0
#include <ntddk.h>

#include "../include/tachyon_wfp_abi.h"

#if defined(_VCRUNTIME_H) || defined(_INC_STDINT) || defined(_STDINT)
#error "kernel ABI contract must not include the user-mode CRT"
#endif

TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_UINT8) == 1, "uint8 width");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_UINT16) == 2, "uint16 width");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_UINT32) == 4, "uint32 width");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_UINT64) == 8, "uint64 width");
TACHYON_WFP_STATIC_ASSERT(TACHYON_WFP_ALIGNOF(TACHYON_WFP_UINT64) >= 8, "uint64 alignment");
TACHYON_WFP_STATIC_ASSERT(
    TACHYON_WFP_OFFSET_OF(TACHYON_WFP_CAPTURE_RECORD, payload) == TACHYON_WFP_CAPTURE_HEADER_SIZE,
    "capture payload offset");
