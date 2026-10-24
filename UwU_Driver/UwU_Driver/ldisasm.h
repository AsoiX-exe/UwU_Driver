#pragma once
#include <ntddk.h>

// Returns length of x64 instruction at p, 0 if unrecognized.
int ldisasm(const UINT8 *p);

// Returns minimum N >= min_bytes such that N is an instruction boundary.
// Returns 0 on failure (unrecognized instruction).
int ldisasm_aligned(const UINT8 *p, int min_bytes);
