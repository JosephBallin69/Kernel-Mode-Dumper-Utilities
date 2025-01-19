#include "Memory.h"
#include <stdlib.h>

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS HandleRequest(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Information = sizeof(Request);
	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto request = (Request*)irp->AssociatedIrp.SystemBuffer;

	if (stack) {
		if (request && sizeof(*request) >= sizeof(Request)) {
			const auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

			if (ctl_code == IOCTL_SEND_REQUEST) {

				if (request->RequestKey == DRIVER_PING) {
					request->Ping = true; 
					Debug::Log("Ping request handled successfully!");
					irp->IoStatus.Status = STATUS_SUCCESS; 
					
				}
				else if (request->RequestKey == DRIVER_DUMP_PROCESS) {
					UNICODE_STRING fileName;
					RtlInitUnicodeString(&fileName, request->FilePath);

					NTSTATUS status = Memory::DumpProcessMemoryKernel((HANDLE)request->ProcessID, &fileName);

					if (NT_SUCCESS(status)) {
						Debug::Log("Process memory dumped successfully!");
						irp->IoStatus.Status = STATUS_SUCCESS;
					}
					else {
						Debug::Log("Failed to dump process memory. Status: 0x%X", status);
						irp->IoStatus.Status = status;
					}

				}
				else if (request->RequestKey == DRIVER_SUSPEND_PROCESS) {
					Memory::SuspendProcessKernel((HANDLE)request->ProcessID);

					irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else if (request->RequestKey == DRIVER_REMOVE_HANDLE_PROTECTION) {
					Memory::UnregisterCallbacks();

					irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else if (request->RequestKey == DRIVER_FETCH_PROCESS_LIST) {
					
					/*
					RtlZeroMemory(request->ProcessList, sizeof(request->ProcessList));
					Memory::EnumerateProcesses(request->ProcessList, ARRAYSIZE(request->ProcessList));
					*/

					irp->IoStatus.Status = STATUS_SUCCESS;

				}
				else if (request->RequestKey == DRIVER_FETCH_MODULE_LIST) {
					size_t bytesWritten = 0;
					RtlZeroMemory(request->ModuleList, sizeof(request->ModuleList));
					Memory::EnumerateModules((HANDLE)request->ProcessID, request->ModuleList, ARRAYSIZE(request->ModuleList));
					irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else if (request->RequestKey == DRIVER_RESUME_PROCESS) {
					Memory::ResumeProcessKernel((HANDLE)request->ProcessID);
					irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else if (request->RequestKey == DRIVER_DUMP_MODULE) {
					UNICODE_STRING fileName;
					RtlInitUnicodeString(&fileName, request->FilePath);
					Memory::DumpModuleFromKernel((HANDLE)request->ProcessID, request->DumpModuleName, &fileName);
					irp->IoStatus.Status = STATUS_SUCCESS;
				}

			}
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

NTSTATUS CustomDriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	UNREFERENCED_PARAMETER(driver_obj);
	UNREFERENCED_PARAMETER(registery_path);

	Memory::clean_piddbcachetalbe();

	Debug::Log("Startup!");

	
	UNICODE_STRING dev_name, sym_link;
	PDEVICE_OBJECT dev_obj;

	RtlInitUnicodeString(&dev_name, L"\\Device\\KMDU"); 
	auto status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
	if (status != STATUS_SUCCESS) return status;

	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\KMDU");
	status = IoCreateSymbolicLink(&sym_link, &dev_name);
	if (status != STATUS_SUCCESS) return status;

	SetFlag(dev_obj->Flags, DO_BUFFERED_IO); 

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++) 
		driver_obj->MajorFunction[t] = unsupported_io;

	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io; 
	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io; 
	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleRequest; 
	driver_obj->DriverUnload = NULL; 

	ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING); 

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	UNREFERENCED_PARAMETER(driver_obj);
	UNREFERENCED_PARAMETER(registery_path);

	UNICODE_STRING  drv_name;
	RtlInitUnicodeString(&drv_name, L"\\Driver\\KMDU");
	IoCreateDriver(&drv_name, &CustomDriverEntry);

	return STATUS_SUCCESS;
}