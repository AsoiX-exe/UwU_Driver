

#include <ntddk.h>
#include <wdm.h>
#include "ldisasm.h"


#define CI_TESTSIGN_BITS        (0x00000002UL | 0x00000008UL)
#define SystemCodeIntegrityInfo 103
#define HOOK_SIZE               14
#define MAX_COPY                64

typedef struct _CI_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} CI_INFO;

typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);


static PUCHAR  g_ntqsi_fn   = NULL;
static PUCHAR  g_trampoline = NULL;
static UINT8   g_orig[MAX_COPY];
static int     g_copy_len   = 0;
static BOOLEAN g_hooked     = FALSE;


typedef struct _PATCH_CTX {
    PVOID Dst;
    const VOID* Src;
    SIZE_T Len;
} PATCH_CTX;


static ULONG_PTR PatchCodeIpi(ULONG_PTR ctx) {
    PATCH_CTX* p = (PATCH_CTX*)ctx;
    RtlCopyMemory(p->Dst, p->Src, p->Len);
    return 0;
}


static NTSTATUS WriteBytes(PVOID dst, const VOID* src, SIZE_T len) {
    PMDL mdl = IoAllocateMdl(dst, (ULONG)len, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return GetExceptionCode();
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS st = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(st)) {
        PATCH_CTX ctx = { mapped, src, len };
        KeIpiGenericCall(PatchCodeIpi, (ULONG_PTR)&ctx);
    }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return st;
}



static void FixRipRelative(PUCHAR tramp, PUCHAR orig, int copy_len) {
    for (int off = 0; off < copy_len; ) {
        const UINT8 *p = orig + off;
        int instr_len = ldisasm(p);
        if (instr_len <= 0) break;

        int idx = 0;
        while (idx < instr_len) {
            UINT8 b = p[idx];
            if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65)
                idx++;
            else if ((b & 0xF0) == 0x40) idx++;
            else break;
        }

        UINT8 op = p[idx];
        int modrm_off = idx + 1;
        if (op == 0x0F) modrm_off = idx + 2;

        if (modrm_off < instr_len) {
            UINT8 modrm = p[modrm_off];
            int mod = (modrm >> 6) & 3;
            int rm  = modrm & 7;
            if (mod == 0 && rm == 5) {
                int disp_off = modrm_off + 1;
                if (disp_off + 4 <= instr_len) {
                    LONG old_disp = *(LONG*)(p + disp_off);
                    LONG64 abs_target = (LONG64)(orig + off + instr_len) + old_disp;
                    LONG64 new_rip    = (LONG64)(tramp + off + instr_len);
                    LONG   new_disp   = (LONG)(abs_target - new_rip);
                    *(LONG*)(tramp + off + disp_off) = new_disp;
                    KdPrint(("[UwU] RIP-rel fixup at tramp+%d: %d -> %d\n",
                             off, old_disp, new_disp));
                }
            }
        }

        off += instr_len;
    }
}



static NTSTATUS NTAPI NtqsiHook(
    ULONG  cls,
    PVOID  buf,
    ULONG  len,
    PULONG retlen)
{
    PFN_NTQSI orig = (PFN_NTQSI)g_trampoline;
    NTSTATUS st = orig(cls, buf, len, retlen);

    if (NT_SUCCESS(st) && cls == SystemCodeIntegrityInfo && buf && len >= 8)
        ((PULONG)buf)[1] &= ~CI_TESTSIGN_BITS;

    return st;
}


NTSTATUS InstallHook() {

    CI_INFO ci = { sizeof(CI_INFO), 0 };
    {
        UNICODE_STRING fn;
        RtlInitUnicodeString(&fn, L"NtQuerySystemInformation");
        PFN_NTQSI ntqsi = (PFN_NTQSI)MmGetSystemRoutineAddress(&fn);
        if (ntqsi) ntqsi(SystemCodeIntegrityInfo, &ci, sizeof(ci), NULL);
    }
    KdPrint(("[UwU] CI options before hook: 0x%08X\n", ci.CodeIntegrityOptions));

    if (!(ci.CodeIntegrityOptions & CI_TESTSIGN_BITS)) {
        KdPrint(("[UwU] TESTSIGN bits not set - not in test mode? skipping\n"));
    }

    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"NtQuerySystemInformation");
    g_ntqsi_fn = (PUCHAR)MmGetSystemRoutineAddress(&fn);
    if (!g_ntqsi_fn) {
        KdPrint(("[UwU] NtQuerySystemInformation not found\n"));
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    KdPrint(("[UwU] NtQuerySystemInformation @ %p\n", g_ntqsi_fn));

    g_copy_len = ldisasm_aligned(g_ntqsi_fn, HOOK_SIZE);
    if (g_copy_len <= 0 || g_copy_len > MAX_COPY) {
        KdPrint(("[UwU] ldisasm_aligned failed (%d), using fallback 32\n", g_copy_len));
        g_copy_len = 32;
    }
    KdPrint(("[UwU] Prologue copy: %d bytes\n", g_copy_len));

    RtlCopyMemory(g_orig, g_ntqsi_fn, g_copy_len);

    g_trampoline = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE,
        (SIZE_T)g_copy_len + HOOK_SIZE,
        'uwu1'
    );
    if (!g_trampoline) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(g_trampoline, g_orig, g_copy_len);
    FixRipRelative(g_trampoline, g_ntqsi_fn, g_copy_len);

    PUCHAR jb = g_trampoline + g_copy_len;
    jb[0] = 0xFF; jb[1] = 0x25;
    *(ULONG*)(jb + 2)  = 0;
    *(UINT64*)(jb + 6) = (UINT64)(g_ntqsi_fn + g_copy_len);

    KdPrint(("[UwU] Trampoline @ %p\n", g_trampoline));

    UINT8 patch[HOOK_SIZE];
    patch[0] = 0xFF; patch[1] = 0x25;
    *(ULONG*)(patch + 2)  = 0;
    *(UINT64*)(patch + 6) = (UINT64)NtqsiHook;

    NTSTATUS st = WriteBytes(g_ntqsi_fn, patch, HOOK_SIZE);
    if (!NT_SUCCESS(st)) {
        KdPrint(("[UwU] Hook write failed: 0x%X\n", st));
        ExFreePoolWithTag(g_trampoline, 'uwu1');
        g_trampoline = NULL;
        return st;
    }
    g_hooked = TRUE;

    CI_INFO ci2 = { sizeof(CI_INFO), 0 };
    {
        UNICODE_STRING fn2;
        RtlInitUnicodeString(&fn2, L"NtQuerySystemInformation");
        PFN_NTQSI ntqsi2 = (PFN_NTQSI)MmGetSystemRoutineAddress(&fn2);
        if (ntqsi2) ntqsi2(SystemCodeIntegrityInfo, &ci2, sizeof(ci2), NULL);
    }
    KdPrint(("[UwU] Hook installed! CI 0x%X -> 0x%X  %s\n",
             ci.CodeIntegrityOptions, ci2.CodeIntegrityOptions,
             (ci2.CodeIntegrityOptions & CI_TESTSIGN_BITS) ? "BITS STILL SET!" : "TESTSIGN cleared OK"));

    return STATUS_SUCCESS;
}

VOID RemoveHook() {
    if (!g_hooked || !g_ntqsi_fn || !g_trampoline) return;
    WriteBytes(g_ntqsi_fn, g_orig, HOOK_SIZE);
    g_hooked = FALSE;
    ExFreePoolWithTag(g_trampoline, 'uwu1');
    g_trampoline = NULL;
    g_ntqsi_fn   = NULL;
    KdPrint(("[UwU] Hook removed\n"));
}



VOID PatchRegistry() {
    UNICODE_STRING keyPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
    );
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    if (!NT_SUCCESS(ZwOpenKey(&hKey, KEY_SET_VALUE, &oa))) return;

    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"TestSigning");
    ULONG zero = 0;
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &zero, sizeof(zero));
    ZwClose(hKey);

    KdPrint(("[UwU] Registry: TestSigning -> 0\n"));
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    RemoveHook();
    KdPrint(("[UwU] Driver unloaded\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    KdPrint(("[UwU] Driver loaded!\n"));

    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS status = InstallHook();
    if (!NT_SUCCESS(status))
        KdPrint(("[UwU] Hook failed: 0x%X\n", status));

    PatchRegistry();

    return STATUS_SUCCESS;
}
