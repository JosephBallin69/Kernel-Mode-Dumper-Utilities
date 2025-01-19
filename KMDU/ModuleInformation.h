#pragma once
#include <string>
#include <Windows.h>
#include <vector>
#include <unordered_set>
#include <string.h>

namespace ModuleInformation {
    
        struct ModuleEntry {
            PVOID BaseAddress;
            ULONG Size;
            wchar_t ModuleName[256];
        };

        struct ModuleEntryString {
            PVOID BaseAddress;
            ULONG Size;
            std::string ModuleName; // Standard string for easier handling
        };

        std::vector<ModuleEntry> moduleList;

        std::vector<ModuleEntryString> FilteredModuleList(const std::vector<ModuleEntry>& moduleList) {
            std::vector<ModuleEntryString> filteredList;
            std::unordered_set<std::string> seenModuleNames;

            for (const auto& CurrentModule : moduleList) {
                // Convert ModuleName to a standard string for comparison
                if (CurrentModule.BaseAddress == 0) continue;

                std::wstring moduleNameW(CurrentModule.ModuleName);
                std::string moduleName(moduleNameW.begin(), moduleNameW.end());

                // Check if the ModuleName has already been seen
                if (seenModuleNames.count(moduleName) == 0) {
                    filteredList.push_back({ CurrentModule.BaseAddress, CurrentModule.Size, moduleName });
                    seenModuleNames.insert(moduleName);
                }
            }

            return filteredList;
        }

        std::vector<ModuleEntryString> SearchModuleByName(const std::vector<ModuleEntryString>& filteredList, const std::string& query) {
            std::vector<ModuleEntryString> results;
            std::string lowerQuery = query;
            std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

            for (const auto& module : filteredList) {
                std::string moduleNameLower = module.ModuleName;
                std::transform(moduleNameLower.begin(), moduleNameLower.end(), moduleNameLower.begin(), ::tolower);

                if (moduleNameLower.find(lowerQuery) != std::string::npos) {
                    results.push_back(module);
                }
            }
            return results;
        }
    

}
