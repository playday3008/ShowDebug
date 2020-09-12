///////////////////////////////////////////////////////////////////////////////
//
// Helper.hpp
// 
// Author: playday3008 (GitHub) and Oleg Starodumov (www.debuginfo.com)
//
//

#pragma once

///////////////////////////////////////////////////////////////////////////////
// Include ShowDebug.hpp
//

#include "ShowDebug.hpp"

///////////////////////////////////////////////////////////////////////////////
// Helper namespace declaration
//

namespace Helper
{
	///////////////////////////////////////////////////////////////////////////////
	// Helper functions
	//

	// Get debuggee command line
	bool GetDebuggeeCommandLine(int argc, TCHAR* argv[], int StartIndex, TString& CmdLine);

	// Get file name from handle
	bool GetFileNameFromHandle(HANDLE hFile, TString& FileName);
	void GetFileNameFromHandleHelper(TString& FileName);

	// Get module size
	bool GetModuleSize(HANDLE hProcess, LPVOID ImageBase, DWORD& Size);

	// Close handle helper
	void CloseHandleHelper(HANDLE h);

	// Enable debug privilege
	bool EnableDebugPrivilege(bool Enable);

	// Detect Close signal from user
	BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);

	// Help and logo printers 
	void PrintHelp();
	void PrintLogo();
};
