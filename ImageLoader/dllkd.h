#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>
#include <windows.h>
#include <string>

#ifdef KEYLIB_EXPORTS
#define KEYLIB_API __declspec(dllexport)
#else
#define KEYLIB_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	KEYLIB_API int GetKey(BYTE* Key, DWORD* KeyLen);

#ifdef __cplusplus
}
#endif
