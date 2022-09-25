#pragma once
#include <winternl.h>
#include <shlwapi.h>
#include <lmcons.h>
#include <WbemCli.h>
#include <intrin.h>
#include <SetupAPI.h>


VOID loaded_dlls();
TCHAR* get_username();
VOID known_usernames();
TCHAR* get_netbios_hostname();
TCHAR* get_dns_hostname();
VOID known_hostnames();
VOID other_known_sandbox_environment_checks();
VOID NumberOfProcessors();
VOID str_trick();
VOID mouse_movement();
VOID lack_user_input();
VOID memory_space();
VOID disk_size_getdiskfreespace();
VOID accelerated_sleep();
VOID cpuid_is_hypervisor();
BOOL registry_disk_enum();
BOOL rdtsc_diff_vmexit();
BOOL rdtsc_diff_locky();


