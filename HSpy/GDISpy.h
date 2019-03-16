#pragma once


typedef HDC(WINAPI *pfn_CreateCompatibleDC)(HDC);
static pfn_CreateCompatibleDC __CreateCompatibleDC = NULL;

typedef BOOL(WINAPI *pfn_DeleteDC)(HDC);
static pfn_DeleteDC __DeleteDC = NULL;

class CGDISpy
{
public:
	CGDISpy();
	~CGDISpy();

	static HDC WINAPI _myCreateCompatibleDC(HDC x);
	static BOOL WINAPI _myDeleteDC(HDC x);
};

