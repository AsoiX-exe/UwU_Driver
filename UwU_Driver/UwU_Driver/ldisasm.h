#pragma once
#include <ntddk.h>

int ldisasm(const UINT8 *p);

int ldisasm_aligned(const UINT8 *p, int min_bytes);
