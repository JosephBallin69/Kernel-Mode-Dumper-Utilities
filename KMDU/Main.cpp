#include <Windows.h>
#include <iostream>

#include "DriverHandler.h"
#include "Interface.h"

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	if(Driver::ConnectToDriver(L"\\\\.\\KMDU")) {

	}

	std::cout << "Status: " << Driver::DoesDriverRespond();

	Interface::Run();
	


	//Driver::DumpProcess(15680, L"C:\\ProcessDump.exe");
	
	//Driver::SuspendProcess(8388);
	//Driver::RemoveHandleProtection(1228);

	Driver::DisconnectFromDriver();

	
}