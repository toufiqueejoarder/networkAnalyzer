// GetPerTcpConnectionEStats.cpp : Defines the entry point for the console application.
//

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "tchar.h"
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
//#include <tcpestats.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <Psapi.h>
#include <filesystem>
using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int main();
void killProcess(DWORD pid);
void processName(DWORD processId);
void terminateOrKill();


void killProcess(DWORD processId) {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
		processId);

	TerminateProcess(hProcess, 0);

	CloseHandle(hProcess);
}

void processName(DWORD processId)
{
	string ret;
	HANDLE handle = OpenProcess(
		PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE,
		processId
	);
	if (handle)
	{
		DWORD buffSize = 1024;
		CHAR buffer[1024];
		if (QueryFullProcessImageNameA(handle, 0, buffer, &buffSize))
		{
			ret = buffer;
			string base_filename = ret.substr(ret.find_last_of("/\\") + 1);
			cout << "" << base_filename << endl;
		}
		else
		{
			printf("Error GetModuleBaseNameA : %lu", GetLastError());
		}
		CloseHandle(handle);
	} else {
		printf("Error OpenProcess : %lu", GetLastError());
	}

}

void terminateOrKill() {
	cout << "Enter PID of process to kill ('0' to end program)" << endl;
	DWORD pid;
	cin >> (pid);
	if (int(pid) == 0) return; // end program
	killProcess(pid);
}

int main()
{
	// Declare and initialize variables
	PMIB_TCPROW row;
	vector<unsigned char> buffer;
	DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
	DWORD dwRetValue = 0;
	char szLocalAddr[128];
	char szRemoteAddr[128];
	struct in_addr IpAddr;
	int i, count = 1;

	do {
		buffer.resize(dwSize, 0);
		dwRetValue = GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
	} while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);

	// Make a second call to GetTcpTable to get
	// the actual DATA we require
	if (dwRetValue == ERROR_SUCCESS)
	{
		PMIB_TCPTABLE_OWNER_PID pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
		row = (PMIB_TCPROW)pTcpTable->table;

		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			DWORD pid = pTcpTable->table[i].dwOwningPid;
			if ((int)pid == 0 || (int)pid == 4) continue; // System IDLE process, i.e. PID that is SYSTEM related gives error for OpenProcess in processName
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));

			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));

			if (strcmp(szLocalAddr, szRemoteAddr) == 0) continue; // List no connections to local server

			cout << "\nPID: " << pid << endl;
			processName(pTcpTable->table[i].dwOwningPid);

			printf("[%d] Local Addr: %s:%d\n", count, szLocalAddr, ntohs((u_short)pTcpTable->table[i].dwLocalPort));
			printf("[%d] Remote Addr: %s:%d\n", count, szRemoteAddr, ntohs((u_short)pTcpTable->table[i].dwRemotePort));

			++row;
			count += 1;
			}
	}

	terminateOrKill();

	return 0;
}
