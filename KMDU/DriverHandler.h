#pragma once
#include <Windows.h>
#include "ProcessInformation.h"
#include "ModuleInformation.h"
#include <locale>
#include <codecvt>


namespace Driver {

#define DRIVER_PING				            0x80000001
#define DRIVER_DUMP_PROCESS                 0x80000002
#define DRIVER_SUSPEND_PROCESS              0x80000003
#define DRIVER_REMOVE_HANDLE_PROTECTION     0x80000004

#define DRIVER_FETCH_PROCESS_LIST           0x80000005
#define DRIVER_FETCH_MODULE_LIST            0x80000006

#define DRIVER_RESUME_PROCESS            0x80000007
#define DRIVER_DUMP_MODULE           0x80000008

#define IOCTL_SEND_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

    struct Request {

        int ProcessID;
        int RequestKey;
        //ProcessInformation::ProcessEntry ProcessList[300];
        ModuleInformation::ModuleEntry ModuleList[300];
        bool Ping;
        wchar_t DumpModuleName[256];
        wchar_t FilePath[260];
    };

    HANDLE DriverHandle;

    bool ConnectToDriver(std::wstring drivername) {
        DriverHandle = CreateFileW(drivername.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (DriverHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "[-] Failed to connect to driver: " << GetLastError() << std::endl;
            return false;
        }

        return true;

    }

    void DisconnectFromDriver() {
        CloseHandle(DriverHandle);
    }

    bool DoesDriverRespond() {
        Request req{};
        req.RequestKey = DRIVER_PING;

        DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(Request), &req, sizeof(Request), nullptr, nullptr);
        return req.Ping;

    }

    void DumpProcess(int ProcessID, const std::wstring& filePath) {
        std::wstring kernelFilePath = L"\\??\\" + filePath;

        Request req{};
        req.RequestKey = DRIVER_DUMP_PROCESS;
        req.ProcessID = ProcessID;
        wcscpy_s(req.FilePath, kernelFilePath.c_str());

        
        NTSTATUS Status = DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(Request), &req, sizeof(Request), nullptr, nullptr);
        return;

    }

    void SuspendProcess(int ProcessID) {
        Request req{};
        req.RequestKey = DRIVER_SUSPEND_PROCESS;
        req.ProcessID = ProcessID;

        NTSTATUS Status = DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(Request), &req, sizeof(Request), nullptr, nullptr);
        return;
    }

    void ResumeProcess(int ProcessID) {
        Request req{};
        req.RequestKey = DRIVER_RESUME_PROCESS;
        req.ProcessID = ProcessID;

        NTSTATUS Status = DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(Request), &req, sizeof(Request), nullptr, nullptr);
        return;
    }

    void RemoveHandleProtection(int ProcessID) {
        Request req{};
        req.RequestKey = DRIVER_REMOVE_HANDLE_PROTECTION;
        req.ProcessID = ProcessID;

        NTSTATUS Status = DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(Request), &req, sizeof(Request), nullptr, nullptr);
        return;
    }

    void DumpModule(int ProcessID, const std::wstring& moduleName, const std::wstring& filePath) {
        std::wstring kernelFilePath = L"\\??\\" + filePath;
        Request req{};
        req.RequestKey = DRIVER_DUMP_MODULE;
        req.ProcessID = ProcessID;
        wcscpy_s(req.FilePath, kernelFilePath.c_str());
        wcscpy_s(req.DumpModuleName, moduleName.c_str());

        NTSTATUS Status = DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(Request), &req, sizeof(Request), nullptr, nullptr);
        return;
    }

    void GetModuleList(int ProcessID) {
        Request req{};
        req.RequestKey = DRIVER_FETCH_MODULE_LIST;
        req.ProcessID = ProcessID;

        DWORD bytesReturned = 0;
        if (DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(req), &req, sizeof(req), &bytesReturned, nullptr)) {
            ModuleInformation::moduleList.clear();
            for (size_t i = 0; i < ARRAYSIZE(req.ModuleList); ++i) {
                const auto& module = req.ModuleList[i];
                ModuleInformation::moduleList.push_back(req.ModuleList[i]);

            }
        }
        
    }

    /*
void GetProcessList() {

    Request req{};
    req.RequestKey = DRIVER_FETCH_PROCESS_LIST;


    DWORD bytesReturned = 0;
    if (DeviceIoControl(DriverHandle, IOCTL_SEND_REQUEST, &req, sizeof(req), &req, sizeof(req), &bytesReturned, nullptr)) {
        ProcessInformation::processList.clear();
        for (size_t i = 0; i < ARRAYSIZE(req.ProcessList); ++i) {

            ProcessInformation::processList.push_back(req.ProcessList[i]);

        }
    }
    else {
        std::cerr << "Failed to fetch processes. Error: " << GetLastError() << std::endl;
    }

}
*/

}