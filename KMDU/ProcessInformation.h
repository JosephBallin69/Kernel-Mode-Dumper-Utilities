#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <TlHelp32.h>

namespace ProcessInformation {
    /*
    struct ProcessEntry {
        DWORD ProcessId;
        wchar_t ProcessName[1024]; // Standard char array (15 characters + null terminator)
    };
    */

    struct ProcessEntry{
        DWORD ProcessId;
        std::string ProcessName; // Standard string for easier handling
    };

    std::vector<ProcessEntry> processList;

    void GetAllProcesses() {
        processList.clear(); // Clear the current list

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return; // Handle error if needed
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                // Convert wchar_t to std::string
                std::wstring processNameW(pe32.szExeFile);
                std::string processName(processNameW.begin(), processNameW.end());

                // Add to the process list
                if (pe32.th32ProcessID != 0) {
                    processList.push_back({ pe32.th32ProcessID, processName });
                }

                
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    std::vector<ProcessEntry> SearchProcessByNameOrId(const std::vector<ProcessEntry>& filteredList, const std::string& query) {
        std::vector<ProcessEntry> results;
        std::string lowerQuery = query;
        std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

        for (const auto& process : filteredList) {
            // Convert process name to lowercase for comparison
            std::string processNameLower = process.ProcessName;
            std::transform(processNameLower.begin(), processNameLower.end(), processNameLower.begin(), ::tolower);

            // Check if the ProcessId matches the query or if the name contains the query
            if (std::to_string(process.ProcessId) == query || processNameLower.find(lowerQuery) != std::string::npos) {
                results.push_back(process);
            }
        }
        return results;
    }
}