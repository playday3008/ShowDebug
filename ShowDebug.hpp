///////////////////////////////////////////////////////////////////////////////
//
// ShowDebug.hpp
// 
// Author: playday3008 (GitHub) and Oleg Starodumov (www.debuginfo.com)
//
//

#pragma once

///////////////////////////////////////////////////////////////////////////////
// Include files
//

#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>
#include <versionhelpers.h>

#include <crtdbg.h>
#include <csignal>

#include <iostream>
#include <map>
#include <sstream>
#include <filesystem>

// Include Helper.hpp

#include "Helper.hpp"


///////////////////////////////////////////////////////////////////////////////
// Directives
//

#ifdef _UNICODE
#define _RPTFT0 _RPTFW0
#define _tcout wcout
#define _tstringstream wstringstream
#define _tstring wstring
#else
#define _RPTFT0 _RPTF0
#define _tcout cout
#define _tstringstream stringstream
#define _tstring string
#endif // _UNICODE

using namespace std;


///////////////////////////////////////////////////////////////////////////////
// Type definitions
//

typedef basic_string<TCHAR> TString;


///////////////////////////////////////////////////////////////////////////////
// CDebugger class declaration
//
// This class wraps the basic Debugging API operations and debug event processing
//

class CDebugger
{
public:

	// Constructor / destructor

	CDebugger();
	virtual ~CDebugger();
	

	// Operations 

	// StartProcess
	bool StartProcess(const TString& FileName, const TString& CmdLine);

	// AttachToProcess
	bool AttachToProcess(DWORD ProcessId);

	// DebugLoop
	bool DebugLoop(DWORD Timeout = INFINITE);


protected:

	// Debug event handlers

	virtual void OnCreateProcessEvent(DWORD ProcessId);
	virtual void OnExitProcessEvent(DWORD ProcessId);
	virtual void OnCreateThreadEvent(DWORD ThreadId);
	virtual void OnExitThreadEvent(DWORD ThreadId);
	virtual void OnLoadModuleEvent(LPVOID ImageBase, HANDLE hFile);
	virtual void OnUnloadModuleEvent(LPVOID ImageBase);
	virtual void OnExceptionEvent(DWORD ThreadId, const EXCEPTION_DEBUG_INFO& Info);
	virtual void OnDebugStringEvent(DWORD ThreadId, const OUTPUT_DEBUG_STRING_INFO& Info);
	virtual void OnTimeout();


	// Data members

	// Process handle
	HANDLE m_hProcess;

	// Collection of module names
	map<LPVOID, TString> m_ModuleNames;
};
