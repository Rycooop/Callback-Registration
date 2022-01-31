//This project is a proof of concept that will allow you to register a
//callback from a manually mapped driver. By taking advantage of a function in
//a valid module, we can use that to jump to our actual callback routine.

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntdef.h>
#include "undoc.h"


//Some util function definitions
PVOID GetSystemRoutineAddress(LPCSTR modName, LPCSTR routineName);
PVOID GetSystemModuleBase(LPCSTR modName);
VOID WriteToReadOnly(PVOID dst, PVOID src, SIZE_T size);
BOOL Hook(PVOID dst, PVOID RoutineAddr);


//Our actual callback that will be executed upon image load:
PLOAD_IMAGE_NOTIFY_ROUTINE ImageLoadCallback(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	//Create an exe named hello and test for yourself!
	if (wcsstr(ImageName->Buffer, L"hello.exe"))
	{
		DbgPrintEx(0, 0, "Callback from a Manually Mapped Driver! %p", ImageInfo->ImageBase);
	}

	return STATUS_SUCCESS;
}


//Driver Entry
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	//First we must "hook" a function to jump to our Callback code, Im going to be using 
	//NtSetCompositionSurfaceStatistics inside dxgkrnl.sys to jump to our callback

	//Obtain the address of the function we are hooking
	PVOID routineAddr = GetSystemRoutineAddress("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtSetCompositionSurfaceStatistics");

	//Heres the magic, pass the address of the function we are hooking, and direct it to our callback function
	if (Hook(&ImageLoadCallback, routineAddr))
	{
		DbgPrintEx(0, 0, "Hooked");

		//the callback will appear to be registered to an address inside a valid module!
		PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)routineAddr);
	}
	
	return STATUS_SUCCESS;
}

//Get function address
PVOID GetSystemRoutineAddress(LPCSTR modName, LPCSTR routineName)
{
	PVOID pMod = GetSystemModuleBase(modName);

	return RtlFindExportedRoutineByName(pMod, routineName);
}

//Get module base of a kernel module, credit to some other github
PVOID GetSystemModuleBase(LPCSTR modName)
{
	ULONG Bytes = 0;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, Bytes, &Bytes);

	if (!Bytes)
		return NULL;

	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, Bytes);

	Status = ZwQuerySystemInformation(SystemModuleInformation, Modules, Bytes, &Bytes);

	if (!NT_SUCCESS(Status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION modInfo = Modules->Modules;
	PVOID ModBase = 0;

	for (ULONG i = 0; i < Modules->NumberOfModules; i++)
	{
		if (strcmp(modInfo[i].FullPathName, modName) == 0)
		{
			ModBase = modInfo[i].ImageBase;
			break;
		}
	}

	if (Modules)
		ExFreePool(Modules);

	return ModBase;
}

//Allocate an MDL so we can write to .text section of system driver
VOID WriteToReadOnly(PVOID dst, PVOID src, SIZE_T size)
{
	PMDL mdl = IoAllocateMdl(dst, (ULONG)size, FALSE, FALSE, NULL);

	if (!mdl)
		return;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

	memcpy(Mapping, src, size);

	MmUnmapLockedPages(Mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
}

//Deal with our hook
BOOL Hook(PVOID dst, PVOID RoutineAddr)
{
	if (!dst || !RoutineAddr)
		return FALSE;

	UINT_PTR hookAddr = (UINT_PTR)dst;

	BYTE baseInstr[12] = { 0x00 };
	BYTE movInstr[2] = { 0x48, 0xBA };
	BYTE jmpInstr[2] = { 0xFF, 0xE2 };

	RtlSecureZeroMemory(&baseInstr, sizeof(baseInstr));

	memcpy((PVOID)((UINT_PTR)baseInstr), &movInstr, sizeof(movInstr));
	memcpy((PVOID)((UINT_PTR)baseInstr + sizeof(movInstr)), &hookAddr, sizeof(UINT_PTR));
	memcpy((PVOID)((UINT_PTR)baseInstr + sizeof(movInstr) + sizeof(UINT_PTR)), &jmpInstr, sizeof(jmpInstr));

	WriteToReadOnly(RoutineAddr, &baseInstr, sizeof(baseInstr));

	return TRUE;
}