#pragma once
#include "evasion.h"
#include "Header.h"

/*
Check if the DLL is loaded in the context of the process
*/

/*
VOID loaded_dlls()
{

	HMODULE hDll;


	CONST TCHAR* szDlls[] = {
		_T("avghookx.dll"),		// AVG
		_T("avghooka.dll"),		// AVG
		_T("snxhk.dll"),		// Avast
		_T("sbiedll.dll"),		// Sandboxie
		_T("dbghelp.dll"),		// WindBG
		_T("api_log.dll"),		// iDefense Lab
		_T("dir_watch.dll"),	// iDefense Lab
		_T("pstorec.dll"),		// SunBelt Sandbox
		_T("vmcheck.dll"),		// Virtual PC
		_T("wpespy.dll"),		// WPE Pro
		_T("cmdvrt64.dll"),		// Comodo Container
		_T("cmdvrt32.dll"),		// Comodo Container

	};

	WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	for (int i = 0; i < dwlength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking if process loaded modules contains: %s "), szDlls[i]);


		hDll = GetModuleHandle(szDlls[i]);
		if (hDll) exit(0);
	}
}


TCHAR* get_username() {
	TCHAR* username;
	DWORD nSize = (UNLEN + 1);

	username = (TCHAR*)malloc(nSize * sizeof(TCHAR));
	if (!username) {
		return NULL;
	}
	if (0 == GetUserName(username, &nSize)) {
		free(username);
		return NULL;
	}
	return username;
}


VOID known_usernames() {


	CONST TCHAR* szUsernames[] = {
		_T("CurrentUser"),
		_T("Sandbox"),

		_T("Emily"),
		_T("HAPUBWS"),
		_T("Hong Lee"),
		_T("IT-ADMIN"),
		_T("Johnson"), 
		_T("Miller"), 
		_T("milozs"),
		_T("Peter Wilson"),
		_T("timmy"),
		_T("user"),

		_T("sand box"),
		_T("malware"),
		_T("maltest"),
		_T("test user"),

		_T("virus"),

		_T("John Doe"),
	};
	TCHAR* username;

	if (NULL == (username = get_username())) {
		return;
	}

	TCHAR msg[256];
	WORD dwlength = sizeof(szUsernames) / sizeof(szUsernames[0]);
	for (int i = 0; i < dwlength; i++) {

		_stprintf_s(msg, sizeof(msg) / sizeof(msg[0]), _T("Checking if username matches : %s "), szUsernames[i]);


		BOOL matched = FALSE;
		if (0 == _tcsicmp(szUsernames[i], username)) {
			matched = TRUE;
			exit(0);
		}
	}

	free(username);
}

TCHAR* get_netbios_hostname() {
	TCHAR* hostname;
	DWORD nSize = (MAX_COMPUTERNAME_LENGTH + 1);

	hostname = (TCHAR*)malloc(nSize * sizeof(TCHAR));
	if (!hostname) {
		return NULL;
	}
	if (0 == GetComputerName(hostname, &nSize)) {
		free(hostname);
		return NULL;
	}
	return hostname;
}

TCHAR* get_dns_hostname() {
	TCHAR* hostname;
	DWORD nSize = 0;

	GetComputerNameEx(ComputerNameDnsHostname, NULL, &nSize);
	hostname = (TCHAR*)malloc((nSize + 1) * sizeof(TCHAR));
	if (!hostname) {
		return NULL;
	}
	if (0 == GetComputerNameEx(ComputerNameDnsHostname, hostname, &nSize)) {
		free(hostname);
		return NULL;
	}
	return hostname;
}


VOID known_hostnames() {


	CONST TCHAR* szHostnames[] = {
		_T("SANDBOX"),
		_T("7SILVIA"),

		_T("HANSPETER-PC"),
		_T("JOHN-PC"),
		_T("MUELLER-PC"),
		_T("WIN7-TRAPS"),

		_T("FORTINET"),

		_T("TEQUILABOOMBOOM"), 
	};
	TCHAR* NetBIOSHostName;
	TCHAR* DNSHostName;

	if (NULL == (NetBIOSHostName = get_netbios_hostname())) {
		return;
	}

	if (NULL == (DNSHostName = get_dns_hostname())) {
		free(NetBIOSHostName);
		return;
	}

	TCHAR msg[256];
	WORD dwlength = sizeof(szHostnames) / sizeof(szHostnames[0]);
	for (int i = 0; i < dwlength; i++) {

		_stprintf_s(msg, sizeof(msg) / sizeof(msg[0]), _T("Checking if hostname matches : %s "), szHostnames[i]);

		BOOL matched = FALSE;
		if (0 == _tcsicmp(szHostnames[i], NetBIOSHostName)) {
			matched = TRUE;
			exit(0);
		}
		else if (0 == _tcsicmp(szHostnames[i], DNSHostName)) {
			matched = TRUE;
			exit(0);
		}

	}

	free(NetBIOSHostName);
	free(DNSHostName);
}

VOID other_known_sandbox_environment_checks() {
	TCHAR* NetBIOSHostName;
	TCHAR* DNSHostName;
	TCHAR* username;
	BOOL matched;

	if (NULL == (username = get_username())) {
		return;
	}
	if (NULL == (NetBIOSHostName = get_netbios_hostname())) {
		free(username);
		return;
	}

	if (NULL == (DNSHostName = get_dns_hostname())) {
		free(username);
		free(NetBIOSHostName);
		return;
	}
	
	matched = FALSE;
	if ((0 == StrCmp(username, _T("Wilber"))) &&
		((0 == StrCmpNI(NetBIOSHostName, _T("SC"), 2)) ||
			(0 == StrCmpNI(NetBIOSHostName, _T("SW"), 2)))) {
		matched = TRUE;
		exit(0);
	}

	matched = FALSE;
	if ((0 == StrCmp(username, _T("admin"))) && (0 == StrCmp(NetBIOSHostName, _T("SystemIT")))) {
		matched = TRUE;
		exit(0);
	}

	matched = FALSE;
	if ((0 == StrCmp(username, _T("admin"))) && (0 == StrCmp(DNSHostName, _T("KLONE_X64-PC")))) {
		matched = TRUE;
		exit(0);
	}

	free(username);
	free(NetBIOSHostName);
	free(DNSHostName);
}


BOOL hybridanalysismacdetect()
{
	return check_mac_addr(_T("\x0A\x00\x27"));
}



VOID NumberOfProcessors()
{
//#if defined (ENV64BIT)
//	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x60) + 0xB8);

//#elif defined(ENV32BIT)
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64);

//#endif

	if (*ulNumberProcessors < 2) {
		exit(0);
	}
}

VOID str_trick()
{
	UCHAR mem[4] = { 0, 0, 0, 0 };

#if defined (ENV32BIT)
	__asm str mem;
#endif

	if ((mem[0] == 0x00) && (mem[1] == 0x40)) 
		exit(0);

}

VOID mouse_movement() {

	POINT positionA = {};
	POINT positionB = {};


	GetCursorPos(&positionA);


	Sleep(5000);


	GetCursorPos(&positionB);

	if ((positionA.x == positionB.x) && (positionA.y == positionB.y))

		exit(0);
}



VOID lack_user_input() {
	int correct_idle_time_counter = 0;
	DWORD current_tick_count = 0, idle_time = 0;
	LASTINPUTINFO last_input_info; // Contains the time of the last input
	last_input_info.cbSize = sizeof(LASTINPUTINFO);

	for (int i = 0; i < 128; ++i) {
		Sleep(0xb);
		// Retrieves the time of the last input event
		if (GetLastInputInfo(&last_input_info)) {
			current_tick_count = GetTickCount();
			if (current_tick_count < last_input_info.dwTime)
				// impossible case unless GetTickCount is manipulated
				exit(0);
			if (current_tick_count - last_input_info.dwTime < 100) {
				correct_idle_time_counter++;
				if (correct_idle_time_counter >= 10);
			}
		}
		else  // GetLastInputInfo must not fail
			exit(0);
	}
	exit(0);
}

VOID memory_space()
{
	DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
	MEMORYSTATUSEX statex = { 0 };

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	if (statex.ullTotalPhys < ullMinRam) exit(0);
}

VOID disk_size_getdiskfreespace()
{
	ULONGLONG minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL))));
	LPCWSTR pszDrive = NULL;
	BOOL bStatus = FALSE;

	// 64 bits integer, low and high bytes
	ULARGE_INTEGER totalNumberOfBytes;

	// If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).
	bStatus = GetDiskFreeSpaceEx(pszDrive, NULL, &totalNumberOfBytes, NULL);
	if (bStatus) {
		if (totalNumberOfBytes.QuadPart < minHardDiskSize)  // 80GB
			exit(0);
	}
}

VOID accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60 * 1000;

	dwStart = GetTickCount();

	Sleep(dwMillisecondsToSleep);

	dwEnd = GetTickCount();

	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000); // substracted 1s just to be sure
	else
		exit(0);
}


VOID cpuid_is_hypervisor()
{
	INT CPUInfo[4] = { -1 };


	__cpuid(CPUInfo, 1);
	if ((CPUInfo[2] >> 31) & 1)
		exit(0);
}

BOOL registry_disk_enum()
{
	HKEY hkResult = NULL;
	const TCHAR* szEntries[] = {
		_T("System\\CurrentControlSet\\Enum\\IDE"),
		_T("System\\CurrentControlSet\\Enum\\SCSI"),
	};
	const TCHAR* szChecks[] = {
		 _T("qemu"),
		 _T("virtio"),
		 _T("vmware"),
		 _T("vbox"),
		 _T("xen"),

		_T("VMW"),
		_T("Virtual"),

	};
	WORD dwEntriesLength = sizeof(szEntries) / sizeof(szEntries[0]);
	WORD dwChecksLength = sizeof(szChecks) / sizeof(szChecks[0]);
	BOOL bFound = FALSE;

	for (unsigned int i = 0; i < dwEntriesLength; i++) {
		DWORD cSubKeys = 0;
		DWORD cbMaxSubKeyLen = 0;
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szEntries[i], NULL, KEY_READ, &hkResult) != ERROR_SUCCESS) {
			continue;
		}

		if (RegQueryInfoKey(hkResult, NULL, NULL, NULL, &cSubKeys, &cbMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
			RegCloseKey(hkResult);
			continue;
		}

		DWORD subKeyBufferLen = (cbMaxSubKeyLen + 1) * sizeof(TCHAR);
		TCHAR* subKeyBuffer = (TCHAR*)malloc(subKeyBufferLen);
		if (!subKeyBuffer) {
			RegCloseKey(hkResult);
			continue;
		}

		for (unsigned int j = 0; j < cSubKeys; j++) {
			DWORD cchName = subKeyBufferLen;
			if (RegEnumKeyEx(hkResult, j, subKeyBuffer, &cchName, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
				continue;
			}
			for (unsigned int k = 0; k < dwChecksLength; k++) {
				//_tprintf(_T("Checking %s %s for %s (%d)\n"), szEntries[i], subKeyBuffer, szChecks[k], cSubKeys);
				if (StrStrI(subKeyBuffer, szChecks[k]) != NULL) {
					bFound = TRUE;
					break;
				}
			}
			if (bFound) {
				break;
			}
		}

		free(subKeyBuffer);
		RegCloseKey(hkResult);

		if (bFound) {
			break;
		}
	}
	return bFound;
}

*/
#define LODWORD(_qw)    ((DWORD)(_qw))
BOOL rdtsc_diff_locky()
{
	ULONGLONG tsc1;
	ULONGLONG tsc2;
	ULONGLONG tsc3;
	DWORD i = 0;

	// Try this 10 times in case of small fluctuations
	for (i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();

		// Waste some cycles - should be faster than CloseHandle on bare metal
		GetProcessHeap();

		tsc2 = __rdtsc();

		// Waste some cycles - slightly longer than GetProcessHeap() on bare metal
		CloseHandle(0);

		tsc3 = __rdtsc();

		// Did it take at least 10 times more CPU cycles to perform CloseHandle than it took to perform GetProcessHeap()?
		if ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10)
			return FALSE;
	}

	// We consistently saw a small ratio of difference between GetProcessHeap and CloseHandle execution times
	// so we're probably in a VM!
	return TRUE;
}

BOOL rdtsc_diff_vmexit()
{
	ULONGLONG tsc1 = 0;
	ULONGLONG tsc2 = 0;
	ULONGLONG avg = 0;
	INT cpuInfo[4] = {};

	// Try this 10 times in case of small fluctuations
	for (INT i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();
		__cpuid(cpuInfo, 0);
		tsc2 = __rdtsc();

		// Get the delta of the two RDTSC
		avg += (tsc2 - tsc1);
	}

	// We repeated the process 10 times so we make sure our check is as much reliable as we can
	avg = avg / 10;
	return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}