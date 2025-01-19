#pragma once
#include "include/imgui/imgui.h"
#include "include/imgui/imgui_impl_win32.h"
#include "include/imgui/imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <dwmapi.h>
#include <chrono>

#include "RobotFont.h"
#include "ProcessInformation.h"
#include <unordered_set>
#include <format>

#pragma comment(lib, "d3d11.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
namespace Interface {

    ID3D11Device* g_pd3dDevice = NULL;
    ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
    IDXGISwapChain* g_pSwapChain = NULL;
    ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

    bool Exit = false;

    void CreateRenderTarget() {
        ID3D11Texture2D* pBackBuffer;
        g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }

    void CleanupRenderTarget() {
        if (g_mainRenderTargetView) {
            g_mainRenderTargetView->Release();
            g_mainRenderTargetView = NULL;
        }
    }

    void CleanupDeviceD3D() {
        CleanupRenderTarget();
        if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
        if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
        if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
    }

    void SetupStyle() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Alpha = 1.0f;
        style.DisabledAlpha = 1.0f;
        style.WindowPadding = ImVec2(12.0f, 12.0f);
        style.WindowRounding = 1.0f;
        style.WindowBorderSize = 0.0f;
        style.WindowMinSize = ImVec2(20.0f, 20.0f);
        style.WindowTitleAlign = ImVec2(0.5f, 0.5f);
        style.WindowMenuButtonPosition = ImGuiDir_None;
        style.ChildRounding = 0.0f;
        style.ChildBorderSize = 1.0f;
        style.PopupRounding = 0.0f;
        style.PopupBorderSize = 1.0f;
        style.FramePadding = ImVec2(20.0f, 5.0f);
        style.FrameRounding = 11.89999961853027f;
        style.FrameBorderSize = 0.0f;
        style.ItemSpacing = ImVec2(4.300000190734863f, 5.5f);
        style.ItemInnerSpacing = ImVec2(7.099999904632568f, 1.799999952316284f);
        style.CellPadding = ImVec2(12.10000038146973f, 9.199999809265137f);
        style.IndentSpacing = 0.0f;
        style.ColumnsMinSpacing = 4.900000095367432f;
        style.ScrollbarSize = 11.60000038146973f;
        style.ScrollbarRounding = 15.89999961853027f;
        style.GrabMinSize = 3.700000047683716f;
        style.GrabRounding = 20.0f;
        style.TabRounding = 7.0f;
        style.TabBorderSize = 0.0f;
        style.TabMinWidthForCloseButton = 0.0f;
        style.ColorButtonPosition = ImGuiDir_Right;
        style.ButtonTextAlign = ImVec2(0.5f, 0.5f);
        style.SelectableTextAlign = ImVec2(0.0f, 0.0f);


        ImVec4* colors = ImGui::GetStyle().Colors;
        colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        colors[ImGuiCol_TextDisabled] = ImVec4(0.27f, 0.32f, 0.45f, 1.00f);
        colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_ChildBg] = ImVec4(0.09f, 0.10f, 0.12f, 1.00f);
        colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_Border] = ImVec4(0.16f, 0.17f, 0.19f, 1.00f);
        colors[ImGuiCol_BorderShadow] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_FrameBg] = ImVec4(0.11f, 0.13f, 0.15f, 1.00f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(0.16f, 0.17f, 0.19f, 1.00f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(0.16f, 0.17f, 0.19f, 1.00f);
        colors[ImGuiCol_TitleBg] = ImVec4(0.05f, 0.05f, 0.07f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(0.05f, 0.05f, 0.07f, 1.00f);
        colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_MenuBarBg] = ImVec4(0.10f, 0.11f, 0.12f, 1.00f);
        colors[ImGuiCol_ScrollbarBg] = ImVec4(0.05f, 0.05f, 0.07f, 1.00f);
        colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.12f, 0.13f, 0.15f, 1.00f);
        colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.16f, 0.17f, 0.19f, 1.00f);
        colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.12f, 0.13f, 0.15f, 1.00f);
        colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 1.00f, 1.00f, 0.91f);
        colors[ImGuiCol_SliderGrab] = ImVec4(1.00f, 1.00f, 1.00f, 0.82f);
        colors[ImGuiCol_SliderGrabActive] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        colors[ImGuiCol_Button] = ImVec4(0.15f, 0.18f, 0.21f, 1.00f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.28f, 0.29f, 1.00f);
        colors[ImGuiCol_ButtonActive] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.14f, 0.16f, 0.21f, 1.00f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_Separator] = ImVec4(0.13f, 0.15f, 0.19f, 1.00f);
        colors[ImGuiCol_SeparatorHovered] = ImVec4(0.16f, 0.18f, 0.25f, 1.00f);
        colors[ImGuiCol_SeparatorActive] = ImVec4(0.16f, 0.18f, 0.25f, 1.00f);
        colors[ImGuiCol_ResizeGrip] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
        colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.97f, 1.00f, 0.50f, 1.00f);
        colors[ImGuiCol_ResizeGripActive] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        colors[ImGuiCol_Tab] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_TabHovered] = ImVec4(0.12f, 0.13f, 0.15f, 1.00f);
        colors[ImGuiCol_TabActive] = ImVec4(0.12f, 0.13f, 0.15f, 1.00f);
        colors[ImGuiCol_TabUnfocused] = ImVec4(0.08f, 0.09f, 0.10f, 1.00f);
        colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.13f, 0.27f, 0.57f, 1.00f);
        colors[ImGuiCol_PlotLines] = ImVec4(0.52f, 0.60f, 0.70f, 1.00f);
        colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.04f, 0.98f, 0.98f, 1.00f);
        colors[ImGuiCol_PlotHistogram] = ImVec4(0.88f, 0.80f, 0.56f, 1.00f);
        colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.96f, 0.96f, 0.96f, 1.00f);
        colors[ImGuiCol_TableHeaderBg] = ImVec4(0.05f, 0.05f, 0.07f, 1.00f);
        colors[ImGuiCol_TableBorderStrong] = ImVec4(0.05f, 0.05f, 0.07f, 1.00f);
        colors[ImGuiCol_TableBorderLight] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
        colors[ImGuiCol_TableRowBg] = ImVec4(0.12f, 0.13f, 0.15f, 1.00f);
        colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.10f, 0.11f, 0.12f, 1.00f);
        colors[ImGuiCol_TextSelectedBg] = ImVec4(0.94f, 0.94f, 0.94f, 1.00f);
        colors[ImGuiCol_DragDropTarget] = ImVec4(0.50f, 0.51f, 1.00f, 1.00f);
        colors[ImGuiCol_NavHighlight] = ImVec4(0.27f, 0.29f, 1.00f, 1.00f);
        colors[ImGuiCol_NavWindowingHighlight] = ImVec4(0.50f, 0.51f, 1.00f, 1.00f);
        colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.20f, 0.18f, 0.55f, 0.50f);
        colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.20f, 0.18f, 0.55f, 0.50f);
    }

    void LoadFonts() {
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        io.Fonts->Clear();

        ImFontConfig font_cfg;
        font_cfg.FontDataOwnedByAtlas = false;
        io.Fonts->AddFontFromMemoryTTF((void*)Fonts::NormalFont, sizeof(Fonts::NormalFont), 26, &font_cfg);

        
    }

    bool CreateDeviceD3D(HWND hWnd) {
        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hWnd;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
        HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
        if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
            res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
        if (res != S_OK)
            return false;

        CreateRenderTarget();
        return true;
    }

    LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg) {
        case WM_SIZE:
            if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
                return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    bool ShowSaveFileDialog(std::wstring& filePath) {
        wchar_t fileName[MAX_PATH] = L""; // Wide-character buffer
        OPENFILENAMEW ofn; // Structure to configure the dialog

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = NULL; // Parent window handle (NULL for no parent)
        ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR; // Prompt before overwriting and keep current directory
        ofn.lpstrDefExt = L"exe"; // Default file extension

        // Show the Save File dialog
        if (GetSaveFileNameW(&ofn)) {
            filePath = fileName; // Store the selected file path
            return true;
        }
        else {
            std::wcerr << L"User canceled the save file dialog or an error occurred." << std::endl;
            return false;
        }
    }

    bool ShowSaveFileDialogDll(std::wstring& filePath) {
        wchar_t fileName[MAX_PATH] = L""; // Wide-character buffer
        OPENFILENAMEW ofn; // Structure to configure the dialog

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = NULL; // Parent window handle (NULL for no parent)
        ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0"; // Updated filter for .dll files
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR; // Prompt before overwriting and keep current directory
        ofn.lpstrDefExt = L"dll"; // Updated default file extension

        // Show the Save File dialog
        if (GetSaveFileNameW(&ofn)) {
            filePath = fileName; // Store the selected file path
            return true;
        }
        else {
            std::wcerr << L"User canceled the save file dialog or an error occurred." << std::endl;
            return false;
        }
    }

    // Function to trigger the file save dialog and call DumpProcess
    void SaveProcessDump(int processId) {
        std::wstring filePath;

        // Open the Save File dialog
        if (ShowSaveFileDialog(filePath)) {
            // Pass the file path to DumpProcess
            std::wcout << L"Selected file path: " << filePath << std::endl;

            // Call your function to dump the process
            Driver::DumpProcess(processId, filePath);
        }
        else {
            std::wcerr << L"No file path selected. Operation aborted." << std::endl;
        }
    }

    void SaveProcessDumpModule(int processId, const std::wstring& moduleName) {
        std::wstring filePath;

        // Open the Save File dialog
        if (ShowSaveFileDialogDll(filePath)) {
            // Pass the file path to DumpProcess
            std::wcout << L"Selected file path: " << filePath << std::endl;

            // Call your function to dump the process
            Driver::DumpModule(processId, moduleName, filePath);
        }
        else {
            std::wcerr << L"No file path selected. Operation aborted." << std::endl;
        }
    }

    static auto lastClickTime = std::chrono::steady_clock::now();
    static const std::chrono::seconds cooldown(3);

    namespace RenderPage {

        static char searchQuery[256] = "";
        static char moduleSearchQuery[256] = "";

        static int selectedProcessIndex = -1;
        static int selectedModuleIndex = -1;

        void RenderSearchBar(const char* label, char* buffer, int bufferSize) {
            ImGui::InputTextWithHint(label, "Search...", buffer, bufferSize);
        }

        void RenderProcessInfo() {
            ImGui::BeginChild("Process Info", ImVec2(ImGui::GetContentRegionAvail().x * 0.9, ImGui::GetContentRegionAvail().y), true);
            if (RenderPage::selectedProcessIndex >= 0) {
                auto filteredProcesses = ProcessInformation::processList;
                auto displayedProcesses = ProcessInformation::SearchProcessByNameOrId(filteredProcesses, RenderPage::searchQuery);

                if (RenderPage::selectedProcessIndex < displayedProcesses.size()) {
                    const auto& process = displayedProcesses[RenderPage::selectedProcessIndex];
                    //ImGui::Text("Process Info:");
                    ImGui::Text("ID: %lu", process.ProcessId);
                    ImGui::Text("Name: %s", process.ProcessName.c_str());

                    if (ImGui::Button("Dump")) {
                        SaveProcessDump(process.ProcessId);
                    }

                    ImGui::SameLine();

                    if (ImGui::Button("Suspend")) {
                        Driver::SuspendProcess(process.ProcessId);
                    }

                    ImGui::SameLine();

                    if (ImGui::Button("Resume")) {
                        Driver::ResumeProcess(process.ProcessId);
                    }

                    

                }
            }
            else {
                ImGui::Text("No process selected.");
            }
            ImGui::EndChild();
        }

        void RenderModuleInfo() {
            ImGui::BeginChild("Module Info", ImVec2(ImGui::GetContentRegionAvail().x * 0.9, ImGui::GetContentRegionAvail().y), true);

            if (RenderPage::selectedModuleIndex >= 0) {
                // Fetch and filter modules
                auto filteredModules = ModuleInformation::FilteredModuleList(ModuleInformation::moduleList);
                auto displayedModules = ModuleInformation::SearchModuleByName(filteredModules, RenderPage::moduleSearchQuery);

                if (RenderPage::selectedModuleIndex < displayedModules.size()) {
                    const auto& module = displayedModules[RenderPage::selectedModuleIndex];
                    // Display module information
                    //ImGui::Text("Module Info:");
                    ImGui::Text("Name: %s", module.ModuleName.c_str());
                    ImGui::Text("Base Address: 0x%p", module.BaseAddress);
                    if (module.Size >= 1024 * 1024) {
                        ImGui::Text("Size: %.2f MB", module.Size / (1024.0 * 1024.0));
                    }
                    else if (module.Size >= 1024) {
                        ImGui::Text("Size: %.2f KB", module.Size / 1024.0);
                    }
                    else {
                        ImGui::Text("Size: %lu bytes", module.Size);
                    }

                    // Add buttons for module-specific actions
                   
                    if (ImGui::Button("Dump")) {
                        std::wstring wideString(module.ModuleName.begin(), module.ModuleName.end());
                        SaveProcessDumpModule(ProcessInformation::processList[RenderPage::selectedProcessIndex].ProcessId, wideString);
                    }
                }
            }
            else {
                ImGui::Text("No module selected.");
            }

            if (ImGui::Button("Refresh")) {
                Driver::GetModuleList(ProcessInformation::processList[RenderPage::selectedProcessIndex].ProcessId);
            }
            ImGui::EndChild();
        }


        void RenderProcessList() {
            ImGui::BeginChild("Process List", ImVec2(ImGui::GetContentRegionAvail().x * 0.9, ImGui::GetContentRegionAvail().y * 0.7), true);
            ImGui::Text("Process List");

            ImGui::SameLine();

            ProcessInformation::GetAllProcesses();
 
            

            ImGui::Separator();

            // Fetch and filter processes

            
            auto filteredProcesses = ProcessInformation::processList;
            auto displayedProcesses = ProcessInformation::SearchProcessByNameOrId(filteredProcesses, RenderPage::searchQuery);

            // Display the process list
            if (ImGui::BeginListBox("##process_list", ImVec2(-FLT_MIN, -FLT_MIN))) {
                for (size_t i = 0; i < displayedProcesses.size(); i++) {
                    const auto& process = displayedProcesses[i];
                    if (ImGui::Selectable((process.ProcessName).c_str(), RenderPage::selectedProcessIndex == i)) {
                        RenderPage::selectedProcessIndex = i;
                        Driver::GetModuleList(process.ProcessId);
                    }
                }
                ImGui::EndListBox();
            }
            ImGui::EndChild();
        }

        void RenderModuleList() {
            ImGui::BeginChild("Module List", ImVec2(ImGui::GetContentRegionAvail().x * 0.9, ImGui::GetContentRegionAvail().y * 0.7), true);
            ImGui::Text("Module List");
            ImGui::Separator();

            // Fetch and filter modules
            auto filteredModules = ModuleInformation::FilteredModuleList(ModuleInformation::moduleList);
            auto displayedModules = ModuleInformation::SearchModuleByName(filteredModules, RenderPage::moduleSearchQuery);

            // Display the module list
            if (ImGui::BeginListBox("##module_list", ImVec2(-FLT_MIN, -FLT_MIN))) {
                for (size_t i = 0; i < displayedModules.size(); i++) {
                    const auto& module = displayedModules[i];

                    if(ImGui::Selectable((module.ModuleName).c_str(), RenderPage::selectedModuleIndex == i)) {
                        RenderPage::selectedModuleIndex = i;

                    }
                }
                ImGui::EndListBox();
            }
            ImGui::EndChild();
        }

    }

    void RenderUI() {
        ImGui::SetNextWindowSize(ImGui::GetMainViewport()->Size);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        if (ImGui::Begin("Kernelmode Dumper Utilities", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse)) {

            ImGui::Columns(2, NULL, false);

            // Left Column: Process List
            RenderPage::RenderSearchBar("##process_search", RenderPage::searchQuery, sizeof(RenderPage::searchQuery));
            RenderPage::RenderProcessList();
            RenderPage::RenderProcessInfo();

            

            ImGui::NextColumn();

            // Right Column: Module List
            RenderPage::RenderSearchBar("##module_search", RenderPage::moduleSearchQuery, sizeof(RenderPage::moduleSearchQuery));
            RenderPage::RenderModuleList();
            RenderPage::RenderModuleInfo();

            ImGui::Columns();
            
        }
        ImGui::End();
    }


    void MainLoop(HWND hwnd) {
        MSG msg;
        ZeroMemory(&msg, sizeof(msg));
        while (!Exit) {
            while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
                ::TranslateMessage(&msg);
                ::DispatchMessage(&msg);

                if (msg.message == WM_QUIT)
                {
                    Exit = true;
                    break;
                }
            }

            // Start ImGui frame
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();


            // Render UI
            RenderUI();

            // Render frame
            ImGui::Render();
            ImVec4 clear_color = ImVec4(0.f, 0.f, 0.f, 0.f);
            const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            g_pSwapChain->Present(1, 0); // Present with vsync
        }
    }

    void Run() {
        // Register window class
        WNDCLASSEX wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"KMDU Window", nullptr};
        ::RegisterClassExW(&wc);
        HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Kernelmode Dumper Utilities", WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, (GetSystemMetrics(SM_CXSCREEN) - 1280) / 2, (GetSystemMetrics(SM_CYSCREEN) - 1080) / 2, 1280, 1080, nullptr, nullptr, wc.hInstance, nullptr);
        if (!CreateDeviceD3D(hwnd))
        {
            CleanupDeviceD3D();
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
            return;
        }

        ::ShowWindow(hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(hwnd);
        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.IniFilename = NULL;

        SetupStyle();
        LoadFonts();

        // Setup Platform/Renderer bindings
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        // Main loop
        MainLoop(hwnd);

        // Cleanup
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        CleanupDeviceD3D();
        DestroyWindow(hwnd);
        UnregisterClass(wc.lpszClassName, wc.hInstance);
    }


}