#pragma once
#include "Definitions.h"

namespace Memory {

    void* GetSystemInformation(const SYSTEM_INFORMATION_CLASS information_class)
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation(information_class, buffer, size, &size);

        const auto info = ExAllocatePool(NonPagedPool, size);

        if (!info)
        {
            return nullptr;
        }

        if (ZwQuerySystemInformation(information_class, info, size, &size) != STATUS_SUCCESS)
        {
            ExFreePool(info);
            return nullptr;
        }

        return info;
    }

    uintptr_t GetKernelModule(const char* name) {
        const auto to_lower = [](char* string) -> const char* {
            for (char* pointer = string; *pointer != '\0'; ++pointer)
            {
                *pointer = (char)(short)tolower(*pointer);
            }

            return string;
            };

        const auto info = (PRTL_PROCESS_MODULES)GetSystemInformation(SystemModuleInformation);

        if (!info)
        {
            return 0;
        }

        for (auto i = 0ull; i < info->NumberOfModules; ++i)
        {
            const auto& module = info->Modules[i];

            if (strcmp(to_lower((char*)module.FullPathName + module.OffsetToFileName), name) == 0)
            {
                const auto address = module.ImageBase;

                ExFreePool(info);

                return reinterpret_cast<uintptr_t> (address);
            }
        }

        ExFreePool(info);

        return 0;
    }

    uintptr_t PatternScan(uintptr_t base, size_t range, const char* pattern, const char* mask)
    {
        const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool {
            for (; *mask; ++base, ++pattern, ++mask) {
                if (*mask == 'x' && *base != *pattern)
                    return false;
            }

            return true;
            };

        range = range - strlen(mask);

        for (size_t i = 0; i < range; ++i) {
            if (check_mask((const char*)base + i, pattern, mask))
                return base + i;
        }

        return NULL;
    }

    uintptr_t PatternScan(uintptr_t base, const char* pattern, const char* mask) {
        const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++) {
            const PIMAGE_SECTION_HEADER section = &sections[i];

            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                const uintptr_t match = PatternScan(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (match)
                    return match;
            }
        }

        return 0;
    }

    PVOID GetSystemModuleBase(const char* module_name) {
        if (!module_name)
            return NULL;

        ULONG bytes = 0;
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
        if (!bytes || !NT_SUCCESS(status))
            return NULL;

        // Allocate memory for the modules list
        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'MODL');
        if (!modules)
            return NULL;

        // Query system module information
        status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(modules, 'MODL');
            return NULL;
        }

        PVOID module_base = NULL;

        // Iterate through the modules to find the specified module
        for (ULONG i = 0; i < modules->NumberOfModules; i++) {
            const char* fullPathName = (const char*)modules->Modules[i].FullPathName;
            const char* baseName = strrchr(fullPathName, '\\');
            baseName = baseName ? baseName + 1 : fullPathName;

            if (_stricmp(baseName, module_name) == 0) {
                module_base = modules->Modules[i].ImageBase;
                break;
            }
        }

        // Free the allocated memory for modules list
        ExFreePoolWithTag(modules, 'MODL');

        return module_base;
    }
    PVOID GetSystemModuleExport(const char* module_name, LPCSTR routing_name)
    {
        PVOID lpModule = GetSystemModuleBase(module_name);

        if (!lpModule)
            return NULL;
        return RtlFindExportedRoutineByName(lpModule, routing_name);


    }



    BOOL WriteMemory(void* address, void* buffer, size_t size)
    {
        if (!RtlCopyMemory(address, buffer, size))
        {
            return FALSE;
        }
        else
        {
            return TRUE;
        }
    }

    BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size)
    {
        PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
        if (!Mdl)
            return false;
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
        PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
        MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
        WriteMemory(Mapping, buffer, size);
        MmUnmapLockedPages(Mapping, Mdl);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return TRUE;

    }

    void EnumerateProcesses(ProcessEntry* buffer, ULONG maxProcessCount) {
        if (buffer == NULL || maxProcessCount == 0) {
            Debug::Log("Invalid buffer or maxProcessCount.");
            return;
        }

        if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
            Debug::Log("Function called at incorrect IRQL.");
            return;
        }

        ULONG processCount = 0;

        PEPROCESS currentProcess = PsInitialSystemProcess;
        if (currentProcess == NULL) {
            Debug::Log("PsInitialSystemProcess is NULL.");
            return;
        }

        PLIST_ENTRY startLink = (PLIST_ENTRY)((PUCHAR)currentProcess + 0x448); // Verify this offset for your OS version
        if (startLink == NULL) {
            Debug::Log("ActiveProcessLinks is NULL.");
            return;
        }

        PLIST_ENTRY currentLink = startLink->Flink;

        while (currentLink != startLink) {
            if (processCount >= maxProcessCount) {
                Debug::Log("Reached maximum buffer size. Stopping enumeration.");
                break;
            }

            PEPROCESS process = (PEPROCESS)((PUCHAR)currentLink - 0x448); // Verify this offset for your OS version
            if (process == NULL) {
                Debug::Log("EPROCESS is NULL. Skipping.");
                currentLink = currentLink->Flink;
                continue;
            }

            ULONG processId = HandleToUlong(PsGetProcessId(process));
            if (processId == 0) {
                currentLink = currentLink->Flink;
                continue;
            }

            PPEB Peb = PsGetProcessPeb(process);
            if (Peb == NULL) {
                Debug::Log("PEB is NULL for ProcessId: %lu.", processId);
                currentLink = currentLink->Flink;
                continue;
            }

            KAPC_STATE apcState;
            KeStackAttachProcess(process, &apcState);

            __try {
                PRTL_USER_PROCESS_PARAMETERS ProcessParameters = Peb->ProcessParameters;
                if (ProcessParameters == NULL || ProcessParameters->ImagePathName.Buffer == NULL) {
                    Debug::Log("ProcessParameters or ImagePathName.Buffer is NULL for ProcessId: %lu.", processId);
                    KeUnstackDetachProcess(&apcState);
                    currentLink = currentLink->Flink;
                    continue;
                }

                // Extract only the process name
                UNICODE_STRING ImagePathName = ProcessParameters->ImagePathName;
                PWCHAR lastSlash = wcsrchr(ImagePathName.Buffer, L'\\');
                PWCHAR processName = (lastSlash != NULL) ? lastSlash + 1 : ImagePathName.Buffer;

                // Ensure it fits in the buffer
                USHORT processNameLength = (USHORT)wcslen(processName) * sizeof(WCHAR);
                if (processNameLength >= sizeof(buffer[processCount].ProcessName)) {
                    Debug::Log("Process name too long for ProcessId: %lu. Truncating.", processId);
                    processNameLength = sizeof(buffer[processCount].ProcessName) - sizeof(WCHAR);
                }

                RtlZeroMemory(&buffer[processCount], sizeof(ProcessEntry));
                buffer[processCount].ProcessId = processId;
                RtlCopyMemory(&buffer[processCount].ProcessName, processName, processNameLength);
               

                processCount++;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                Debug::Log("Exception occurred for ProcessId: %lu.", processId);
            }

            KeUnstackDetachProcess(&apcState);

            currentLink = currentLink->Flink;
        }

        Debug::Log("Total processes enumerated: %lu", processCount);
    }

    void EnumerateModules(HANDLE processId, ModuleEntry* buffer, ULONG maxModules) {
        ULONG moduleCount = 0;

        // Validate input
        if (processId == 0 || buffer == NULL || maxModules == 0) {
            Debug::Log("Invalid arguments to EnumerateModules.");
            return;
        }

        // Lookup the target process
        PEPROCESS targetProcess;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess))) {
            Debug::Log("Failed to lookup process by ID: %lu", processId);
            return;
        }

        // Retrieve PEB
        PPEB Peb = PsGetProcessPeb(targetProcess);
        if (Peb == NULL) {
            Debug::Log("Failed to retrieve PEB for process.");
            ObDereferenceObject(targetProcess);
            return;
        }

        KAPC_STATE apcState;
        KeStackAttachProcess(targetProcess, &apcState);

        // Access LDR data
        _PEB_LDR_DATA* LDRData = Peb->Ldr;
        if (LDRData == NULL) {
            Debug::Log("Failed to retrieve LDR data.");
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(targetProcess);
            return;
        }

        LIST_ENTRY* moduleList = &LDRData->InLoadOrderModuleList;
        LIST_ENTRY* current = moduleList->Flink; // Start traversing

        size_t counter = 0;

        // Traverse the module list
        while (current != moduleList && counter < maxModules) {
            LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (!MmIsAddressValid(entry)) {
                Debug::Log("Invalid LDR entry encountered.");
                break;
            }

            if (entry == nullptr) {
                continue;
            }

            if (entry->SizeOfImage == 0) {
                continue; 
            }

            if (entry->BaseDllName.Buffer == nullptr || entry->BaseDllName.Length == 0) {
                continue;
            }

         
            if (entry->BaseDllName.Length % sizeof(wchar_t) != 0) {
                continue; 
            }


            RtlZeroMemory(&buffer[counter], sizeof(ModuleEntry));
            
            RtlCopyMemory(&buffer[counter].ModuleName, entry->BaseDllName.Buffer, entry->BaseDllName.Length);
            buffer[counter].BaseAddress = entry->DllBase;
            buffer[counter].Size = entry->SizeOfImage;

           
            

            //Debug::Log("Module Name: %wZ, Base Address: 0x%p, Size: 0x%X", buffer[counter].ModuleName, buffer[counter].BaseAddress, buffer[counter].Size);

            counter++;
            current = current->Flink; 
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(targetProcess);
    }


    NTSTATUS DumpProcessMemoryKernel(HANDLE processId, UNICODE_STRING* fileName) {
        PEPROCESS targetProcess = NULL;
        HANDLE fileHandle = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;

        // Lookup the target process
        status = PsLookupProcessByProcessId(processId, &targetProcess);
        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to find process with ID %d. Status: 0x%X", processId, status);
            return status;
        }

        Debug::Log("Target process found.");

        // Get the base address of the process (ImageBase)
        PVOID baseAddress = PsGetProcessSectionBaseAddress(targetProcess);
        if (!baseAddress) {
            Debug::Log("Failed to retrieve process base address.");
            ObDereferenceObject(targetProcess);
            return STATUS_INVALID_PARAMETER;
        }

        Debug::Log("Base address of the process: 0x%p", baseAddress);

        // Initialize object attributes for the output file
        InitializeObjectAttributes(&objAttr, fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Create the output file
        status = ZwCreateFile(
            &fileHandle,
            GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to create file. Status: 0x%X", status);
            ObDereferenceObject(targetProcess);
            return status;
        }

        Debug::Log("Output file created successfully.");

        // Allocate memory for the buffer
        SIZE_T chunkSize = 4096;
        PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, chunkSize, 'DUMP');
        if (!buffer) {
            Debug::Log("Failed to allocate buffer memory.");
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Step 1: Read the PE headers
        status = MmCopyVirtualMemory(
            targetProcess,
            baseAddress,
            PsGetCurrentProcess(),
            buffer,
            chunkSize,
            KernelMode,
            &chunkSize
        );

        if (!NT_SUCCESS(status) || chunkSize < sizeof(IMAGE_DOS_HEADER)) {
            Debug::Log("Failed to read PE headers. Status: 0x%X", status);
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return status;
        }

        // Validate the PE headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            Debug::Log("Invalid DOS header signature.");
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            Debug::Log("Invalid NT header signature.");
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Debug::Log("PE headers validated successfully.");

        // Write the headers to the output file
        ULONG headersSize = ntHeaders->OptionalHeader.SizeOfHeaders;
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, headersSize, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to write PE headers to file. Status: 0x%X", status);
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return status;
        }

        // Step 2: Dump all sections
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)ntHeaders + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

            PVOID sectionBase = (PVOID)((uintptr_t)baseAddress + sectionHeader->VirtualAddress);
            ULONG sectionSize = sectionHeader->SizeOfRawData;

            Debug::Log("Dumping section: %s (Size: 0x%X)", sectionHeader->Name, sectionSize);

            // Allocate memory for the section
            PVOID sectionBuffer = ExAllocatePoolWithTag(NonPagedPool, sectionSize, 'SECT');
            if (!sectionBuffer) {
                Debug::Log("Failed to allocate memory for section: %s", sectionHeader->Name);
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            // Read the section from memory
            SIZE_T bytesRead = 0;
            status = MmCopyVirtualMemory(
                targetProcess,
                sectionBase,
                PsGetCurrentProcess(),
                sectionBuffer,
                sectionSize,
                KernelMode,
                &bytesRead
            );

            if (!NT_SUCCESS(status) || bytesRead != sectionSize) {
                Debug::Log("Failed to read section: %s. Status: 0x%X", sectionHeader->Name, status);
                ExFreePoolWithTag(sectionBuffer, 'SECT');
                break;
            }

            // Write the section to the file
            status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, sectionBuffer, sectionSize, NULL, NULL);
            ExFreePoolWithTag(sectionBuffer, 'SECT');

            if (!NT_SUCCESS(status)) {
                Debug::Log("Failed to write section: %s to file. Status: 0x%X", sectionHeader->Name, status);
                break;
            }

            Debug::Log("Section %s dumped successfully.", sectionHeader->Name);
        }

        // Cleanup
        ExFreePoolWithTag(buffer, 'DUMP');
        ZwClose(fileHandle);
        ObDereferenceObject(targetProcess);

        return status;
    }

    NTSTATUS GetModuleBaseAndSize(PEPROCESS targetProcess, PCWSTR moduleName, PVOID* baseAddress, ULONG* moduleSize) {
        NTSTATUS status = STATUS_SUCCESS;
        KAPC_STATE apcState;
        PPEB peb = NULL;
        PLDR_DATA_TABLE_ENTRY moduleEntry = NULL;

        // Attach to the target process to access its PEB
        KeStackAttachProcess(targetProcess, &apcState);

        __try {
            peb = PsGetProcessPeb(targetProcess);
            if (!peb || !peb->Ldr || !peb->Ldr->InLoadOrderModuleList.Flink) {
                status = STATUS_NOT_FOUND;
                __leave;
            }

            PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
            PLIST_ENTRY currentEntry = listHead->Flink;

            while (currentEntry != listHead) {
                moduleEntry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (_wcsicmp(moduleEntry->BaseDllName.Buffer, moduleName) == 0) {
                    *baseAddress = moduleEntry->DllBase;
                    *moduleSize = moduleEntry->SizeOfImage;
                    status = STATUS_SUCCESS;
                    break;
                }

                currentEntry = currentEntry->Flink;
            }

            if (!NT_SUCCESS(status)) {
                status = STATUS_NOT_FOUND;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

        KeUnstackDetachProcess(&apcState);

        return status;
    }

    ULONG_PTR AdjustRVA(ULONG_PTR rva, PVOID moduleBaseAddress, PIMAGE_NT_HEADERS ntHeaders) {
        if (rva == 0) {
            return 0; // No adjustment needed for null RVAs
        }

        // Locate the section containing the RVA
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
            ULONG sectionStartRVA = sectionHeader->VirtualAddress;
            ULONG sectionEndRVA = sectionStartRVA + sectionHeader->SizeOfRawData;

            if (rva >= sectionStartRVA && rva < sectionEndRVA) {
                // Calculate the file offset
                ULONG_PTR offset = rva - sectionStartRVA + sectionHeader->PointerToRawData;
                return offset;
            }
        }

        Debug::Log("RVA 0x%p is not within any section!", rva);
        return 0; // Return 0 for invalid RVAs
    }

    void FixExportTable(
        PEPROCESS targetProcess,
        PVOID moduleBaseAddress,
        PIMAGE_NT_HEADERS ntHeaders,
        HANDLE fileHandle
    ) {
        PIMAGE_DATA_DIRECTORY exportDirEntry = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirEntry->VirtualAddress == 0 || exportDirEntry->Size == 0) {
            Debug::Log("No export table found.");
            return;
        }

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)moduleBaseAddress + exportDirEntry->VirtualAddress);

        // Allocate memory for export directory
        ULONG exportSize = exportDirEntry->Size;
        PVOID exportBuffer = ExAllocatePoolWithTag(NonPagedPool, exportSize, 'EXPT');
        if (!exportBuffer) {
            Debug::Log("Failed to allocate memory for export table.");
            return;
        }

        // Copy export directory from the target process
        SIZE_T bytesRead = 0;
        NTSTATUS status = MmCopyVirtualMemory(
            targetProcess,
            exportDir,
            PsGetCurrentProcess(),
            exportBuffer,
            exportSize,
            KernelMode,
            &bytesRead
        );

        if (!NT_SUCCESS(status) || bytesRead != exportSize) {
            Debug::Log("Failed to read export table. Status: 0x%X", status);
            ExFreePoolWithTag(exportBuffer, 'EXPT');
            return;
        }

        // Adjust RVAs in the export directory
        PIMAGE_EXPORT_DIRECTORY localExportDir = (PIMAGE_EXPORT_DIRECTORY)exportBuffer;
        localExportDir->Name = AdjustRVA(localExportDir->Name, moduleBaseAddress, ntHeaders);
        localExportDir->AddressOfFunctions = AdjustRVA(localExportDir->AddressOfFunctions, moduleBaseAddress, ntHeaders);
        localExportDir->AddressOfNames = AdjustRVA(localExportDir->AddressOfNames, moduleBaseAddress, ntHeaders);
        localExportDir->AddressOfNameOrdinals = AdjustRVA(localExportDir->AddressOfNameOrdinals, moduleBaseAddress, ntHeaders);

        // Write the adjusted export directory to the file
        IO_STATUS_BLOCK ioStatusBlock;
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, exportBuffer, exportSize, NULL, NULL);
        ExFreePoolWithTag(exportBuffer, 'EXPT');

        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to write export table to file. Status: 0x%X", status);
            return;
        }

        Debug::Log("Export table fixed and written successfully.");
    }

    void DumpModuleFromKernel(HANDLE processId, PCWSTR moduleName, UNICODE_STRING* fileName) {
        PEPROCESS targetProcess = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;

        // Lookup the target process
        status = PsLookupProcessByProcessId(processId, &targetProcess);
        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to find process with ID %d. Status: 0x%X", processId, status);
            return;
        }

        Debug::Log("Target process found.");

        // Get the base address of the specified module
        PVOID moduleBaseAddress = NULL;
        ULONG moduleSize = 0;

        status = GetModuleBaseAndSize(targetProcess, moduleName, &moduleBaseAddress, &moduleSize);
        if (!NT_SUCCESS(status) || !moduleBaseAddress || moduleSize == 0) {
            Debug::Log("Failed to retrieve module base address or size for %ws. Status: 0x%X", moduleName, status);
            ObDereferenceObject(targetProcess);
            return;
        }

        Debug::Log("Module base address: 0x%p, Size: 0x%X", moduleBaseAddress, moduleSize);

        // Initialize object attributes for the output file
        InitializeObjectAttributes(&objAttr, fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Create the output file
        status = ZwCreateFile(
            &fileHandle,
            GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to create file. Status: 0x%X", status);
            ObDereferenceObject(targetProcess);
            return;
        }

        Debug::Log("Output file created successfully.");

        // Allocate buffer for headers
        SIZE_T chunkSize = PAGE_SIZE;
        PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, chunkSize, 'DUMP');
        if (!buffer) {
            Debug::Log("Failed to allocate buffer memory.");
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return;
        }

        // Read and write PE headers
        SIZE_T bytesRead = 0;
        status = MmCopyVirtualMemory(
            targetProcess,
            moduleBaseAddress,
            PsGetCurrentProcess(),
            buffer,
            chunkSize,
            KernelMode,
            &bytesRead
        );

        if (!NT_SUCCESS(status) || bytesRead == 0) {
            Debug::Log("Failed to read PE headers. Status: 0x%X", status);
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            Debug::Log("Invalid DOS header signature.");
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            Debug::Log("Invalid NT header signature.");
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return;
        }

        // Write headers to file
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, (ULONG)bytesRead, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            Debug::Log("Failed to write PE headers to file. Status: 0x%X", status);
            ExFreePoolWithTag(buffer, 'DUMP');
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            return;
        }

        Debug::Log("PE headers dumped successfully.");

        // Dump each section
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)ntHeaders + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
            PVOID sectionBase = (PVOID)((uintptr_t)moduleBaseAddress + sectionHeader->VirtualAddress);
            ULONG sectionSize = sectionHeader->SizeOfRawData;

            Debug::Log("Dumping section: %s (Raw Size: 0x%X)", sectionHeader->Name, sectionSize);

            PVOID sectionBuffer = ExAllocatePoolWithTag(NonPagedPool, sectionSize, 'SECT');
            if (!sectionBuffer) {
                Debug::Log("Failed to allocate memory for section: %s", sectionHeader->Name);
                break;
            }

            // Read section data
            status = MmCopyVirtualMemory(
                targetProcess,
                sectionBase,
                PsGetCurrentProcess(),
                sectionBuffer,
                sectionSize,
                KernelMode,
                &bytesRead
            );

            if (!NT_SUCCESS(status) || bytesRead != sectionSize) {
                Debug::Log("Failed to read section: %s. Status: 0x%X", sectionHeader->Name, status);
                ExFreePoolWithTag(sectionBuffer, 'SECT');
                break;
            }

            // Write section to file
            status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, sectionBuffer, sectionSize, NULL, NULL);
            ExFreePoolWithTag(sectionBuffer, 'SECT');

            if (!NT_SUCCESS(status)) {
                Debug::Log("Failed to write section: %s to file. Status: 0x%X", sectionHeader->Name, status);
                break;
            }

            Debug::Log("Section %s dumped successfully.", sectionHeader->Name);
        }

        FixExportTable(targetProcess, moduleBaseAddress, ntHeaders, fileHandle);

        // Cleanup
        ExFreePoolWithTag(buffer, 'DUMP');
        ZwClose(fileHandle);
        ObDereferenceObject(targetProcess);

        Debug::Log("Module dump completed for %ws.", moduleName);
    }

    void UnregisterCallbacksForType(POBJECT_TYPE ObjectType) {
        if (!ObjectType) {
            Debug::Log("Invalid ObjectType pointer.");
            return;
        }

        // Get the head of the CallbackList
        PLIST_ENTRY callbackListHead = &ObjectType->CallbackList;
        if (!callbackListHead) {
            Debug::Log("Invalid CallbackListHead pointer.");
            return;
        }

        PLIST_ENTRY currentEntry = callbackListHead->Flink;

        int counter = 0;

        // Traverse the CallbackList
        while (currentEntry != callbackListHead) {
            PCALLBACK_ENTRY_ITEM entryItem = CONTAINING_RECORD(currentEntry, CALLBACK_ENTRY_ITEM, EntryItemList);
            if (!entryItem) {
                Debug::Log("Invalid entryItem encountered.");
                break;
            }

            // Check if ObjectType is valid
            if (entryItem->ObjectType) {
                if (entryItem->ObjectType->Name.Buffer) {
                    if (counter < 15) {

                        wchar_t Name[128];

                        RtlCopyMemory(&Name, entryItem->ObjectType->Name.Buffer, entryItem->ObjectType->Name.Length);

                        Debug::Log("Object Type Name: %wZ", Name);
                    }
                }
                else {
                    Debug::Log("ObjectType->Name.Buffer is NULL.");
                }
            }
            else {
                Debug::Log("entryItem->ObjectType is NULL.");
            }

            counter++;

            // Move to the next entry
            currentEntry = currentEntry->Flink;
        }
    }

    void UnregisterCallbacks() {
        POBJECT_TYPE ProcessType = *PsProcessType;
        POBJECT_TYPE ThreadType = *PsThreadType;

        if (!ProcessType || !ThreadType) {
            Debug::Log("Failed to locate PsProcessType or PsThreadType.");
            return;
        }

        Debug::Log("Unregistering callbacks for processes...");
        UnregisterCallbacksForType(ProcessType);

        Debug::Log("Unregistering callbacks for threads...");
        UnregisterCallbacksForType(ThreadType);

        Debug::Log("Callback unregistration complete.");
        
    }

    void RemoveHandleProtection(HANDLE processId) {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(processId, &process);

        if (!NT_SUCCESS(status)) {
            Debug::Log("[-] Failed to find process with ID %d. Status: 0x%X\n", processId, status);
            return;
        }

        // Safely access the handle table
        uintptr_t handleTableOffset = 0x570; // Adjust based on verified symbols for your OS version
        _PHANDLE_TABLE handleTable = *(_PHANDLE_TABLE*)((uintptr_t)process + handleTableOffset);
        if (!handleTable) {
            Debug::Log("[-] Handle table not found.\n");
            ObDereferenceObject(process);
            return;
        }

        Debug::Log("[+] Handle table located: %p\n", handleTable);

        // Decode TableCode
        PHANDLE_TABLE_ENTRY handleEntries = (PHANDLE_TABLE_ENTRY)(handleTable->TableCode & ~0x07);
        if (!handleEntries) {
            Debug::Log("[-] Handle entries not found.\n");
            ObDereferenceObject(process);
            return;
        }

        Debug::Log("[+] Handle entries decoded.\n");

        // Safely iterate through the handle table
        for (ULONG i = 0; i < handleTable->NextHandleNeedingPool; i++) {
            PHANDLE_TABLE_ENTRY entry = &handleEntries[i];

            // Validate the entry
            if (!entry || !entry->ObjectPointerBits) {
                continue;
            }

            Debug::Log("[+] Handle: %u", i);
            Debug::Log("Object: %p", entry->ObjectPointerBits);

            // Check GrantedAccess
#define PROCESS_ALL_ACCESS 0x1FFFFF
            if (entry->GrantedAccessBits & PROCESS_ALL_ACCESS) {
                Debug::Log("GrantedAccess: PROCESS_ALL_ACCESS");
            }
            else {
                Debug::Log("GrantedAccess: OTHER");
            }
        }

        // Cleanup
        ObDereferenceObject(process);
        Debug::Log("[+] Handle protection removal complete.\n");
    }
    NTSTATUS SuspendProcessKernel(HANDLE processId) {
        PEPROCESS targetProcess = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(processId, &targetProcess);

        if (!NT_SUCCESS(status)) {
            Debug::Log("[-] Failed to find process with ID %d. Status: 0x%X\n", processId, status);
            return status;
        }

        Debug::Log("[+] Target process found for suspension: %p\n", targetProcess);


        PsSuspendProcess(targetProcess);

        ObDereferenceObject(targetProcess);
        return STATUS_SUCCESS;
    }

    NTSTATUS ResumeProcessKernel(HANDLE processId) {
        PEPROCESS targetProcess = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(processId, &targetProcess);

        if (!NT_SUCCESS(status)) {
            Debug::Log("[-] Failed to find process with ID %d. Status: 0x%X\n", processId, status);
            return status;
        }

        Debug::Log("[+] Target process found for suspension: %p\n", targetProcess);


        PsResumeProcess(targetProcess);

        ObDereferenceObject(targetProcess);
        return STATUS_SUCCESS;
    }


    PVOID g_KernelBase = NULL;
    ULONG g_KernelSize = 0;

    PVOID get_kernel_base(OUT PULONG pSize)
    {
        NTSTATUS status = STATUS_SUCCESS;
        ULONG bytes = 0;
        PRTL_PROCESS_MODULES pMods = NULL;
        PVOID checkPtr = NULL;
        UNICODE_STRING routineName;

        // Already found
        if (g_KernelBase != NULL)
        {
            if (pSize)
                *pSize = g_KernelSize;
            return g_KernelBase;
        }

        RtlUnicodeStringInit(&routineName, L"NtOpenFile");

        checkPtr = MmGetSystemRoutineAddress(&routineName);
        if (checkPtr == NULL)
            return NULL;


        status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

        if (bytes == 0)
            return NULL;

        pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x454E4F45); // 'ENON'
        RtlZeroMemory(pMods, bytes);

        status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

        if (NT_SUCCESS(status))
        {
            PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

            for (ULONG i = 0; i < pMods->NumberOfModules; i++)
            {
                // System routine is inside module
                if (checkPtr >= pMod[i].ImageBase &&
                    checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
                {
                    g_KernelBase = pMod[i].ImageBase;
                    g_KernelSize = pMod[i].ImageSize;
                    if (pSize)
                        *pSize = g_KernelSize;
                    break;
                }
            }
        }

        if (pMods)
            ExFreePoolWithTag(pMods, 0x454E4F45); // 'ENON'

        return g_KernelBase;
    }

    NTSTATUS pattern_scan(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
    {
        ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
        if (ppFound == NULL || pattern == NULL || base == NULL)
            return STATUS_INVALID_PARAMETER;

        for (ULONG_PTR i = 0; i < size - len; i++)
        {
            BOOLEAN found = TRUE;
            for (ULONG_PTR j = 0; j < len; j++)
            {
                if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
                {
                    found = FALSE;
                    break;
                }
            }

            if (found != FALSE)
            {
                *ppFound = (PUCHAR)base + i;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    NTSTATUS scan_section(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
    {
        ASSERT(ppFound != NULL);
        if (ppFound == NULL)
            return STATUS_INVALID_PARAMETER;

        PVOID base = get_kernel_base(NULL);
        if (!base)
            return STATUS_NOT_FOUND;


        PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
        if (!pHdr)
            return STATUS_INVALID_IMAGE_FORMAT;

        PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
        for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
        {
            ANSI_STRING s1, s2;
            RtlInitAnsiString(&s1, section);
            RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
            if (RtlCompareString(&s1, &s2, TRUE) == 0)
            {
                PVOID ptr = NULL;
                NTSTATUS status = pattern_scan(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
                if (NT_SUCCESS(status))
                    *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);

                return status;
            }
        }

        return STATUS_NOT_FOUND;
    }

    PVOID resolve_relative_address(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
    {
        ULONG_PTR Instr = (ULONG_PTR)Instruction;
        LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
        PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

        return ResolvedAddr;
    }

    BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
    {
        UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
        UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

        PVOID PiDDBLockPtr = NULL;
        if (!NT_SUCCESS(scan_section("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (&PiDDBLockPtr)))) {
            return FALSE;
        }

        RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

        PVOID PiDTablePtr = NULL;
        if (!NT_SUCCESS(scan_section("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (&PiDTablePtr)))) {
            return FALSE;
        }

        RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);


        UINT64 RealPtrPIDLock = NULL;

        RealPtrPIDLock = (UINT64)g_KernelBase + (UINT64)PiDDBLockPtr;


        *lock = (PERESOURCE)resolve_relative_address((PVOID)RealPtrPIDLock, 3, 7);


        UINT64 RealPtrPIDTable = NULL;

        RealPtrPIDTable = (UINT64)g_KernelBase + (UINT64)PiDTablePtr;


        *table = (PRTL_AVL_TABLE)(resolve_relative_address((PVOID)RealPtrPIDTable, 3, 7));

        return TRUE;
    }


    BOOLEAN clean_piddbcachetalbe() {
        PERESOURCE PiDDBLock = NULL;
        PRTL_AVL_TABLE PiDDBCacheTable = NULL;
        if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) {
            return FALSE;
        }

        // build a lookup entry

        PIDCacheobj lookupEntry;

        // this should work :D
        UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
        // removed *DriverName no need for it
        lookupEntry.DriverName = DriverName;
        lookupEntry.TimeDateStamp = 0x5284EAC3; // intel_driver TimeStamp.

        // aquire the ddb lock
        ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

        // search our entry in the table

        // maybe something will bsod here.
        PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
        if (pFoundEntry == NULL)
        {
            // release the ddb resource lock
            ExReleaseResourceLite(PiDDBLock);
            return FALSE;
        }
        else
        {
            // first, unlink from the list
            RemoveEntryList(&pFoundEntry->List);
            // then delete the element from the avl table
            RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);

            // release the ddb resource lock
            ExReleaseResourceLite(PiDDBLock);
        }
        DbgPrintEx(0, 0, "Cleaned piddb\n");
        return TRUE;
    }


    

}