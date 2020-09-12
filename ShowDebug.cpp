///////////////////////////////////////////////////////////////////////////////
//
// ShowDebug.cpp
// 
// Author: playday3008 (GitHub) and Oleg Starodumov (www.debuginfo.com)
//
//


///////////////////////////////////////////////////////////////////////////////
// Description
//
// This example shows how to perform the following tasks:
//   * Start an application under debugger
//   * Attach the debugger to a process
//   * Implement the debugging loop
//   * Process debug events and display meaningful output
//
// In additional, the following implementation details can be interesting:
//   * What handles are passed to the debugger by the Debugging API, 
//     how the debugger should work with those handles, which of them should 
//     be closed, etc.
//   * Obtaining the module path and name from the module's file handle
//   * Wrapping of the debugger logic into a simple class
//
// Note: This example uses PSAPI.DLL, and thus cannot run on Windows 9x
//


///////////////////////////////////////////////////////////////////////////////
// Usage:
//
// ShowDebug -p <pid>   Attach to the specified process
// ShowDebug <CmdLine>  Launch the specified executable, with the specified 
//						command line parameters
//


///////////////////////////////////////////////////////////////////////////////
// Include ShowDebug.hpp
//

#include "ShowDebug.hpp"


/// <summary>
/// main()/wmain() function 
/// </summary>
/// <param name="argc">Number of strings in array argv</param>
/// <param name="argv">Array of command-line argument strings</param>
/// <returns>EXIT_SUCCESS or EXIT_FAILURE</returns>
int _tmain(int argc, TCHAR* argv[])
{
	// Command line parameter constants 

	const _tstring ccAttach = _T("-p");
	const _tstring ccHelp = _T("-?");


	// Print logo 

	Helper::PrintLogo();

	// Set Console title

	if (!SetConsoleTitle(_T("ShowDebug by playday3008"))) {
		_tcout << _T("SetConsoleTitle() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("SetConsoleTitle() failed."));
	}


	// Check Windows XP or greater version

	if (!IsWindowsXPOrGreater()) {
		MessageBox(nullptr, _T("You need at least Windows XP"), _T("Version Not Supported"), MB_OK | MB_ICONERROR);
		return EXIT_FAILURE;
	}


	// Enable debug privilege

	Helper::EnableDebugPrivilege(true);


	// Instantiate the debugger object 

	CDebugger Debugger;


	// Obtain and check command line parameters 

	if (argc < 2) {
		Helper::PrintHelp();
		return EXIT_SUCCESS;
	}

	if (ccHelp == argv[1]) {
		Helper::PrintHelp();
		return EXIT_SUCCESS;
	}
	else if (ccAttach == argv[1]) {
		// Attach requested

		DWORD ProcessId = _ttol(argv[2]);

		_tcout << _T("Mode:      Attach") << endl;
		_tcout << _T("Pid:       ") << ProcessId << endl;

		if (!Debugger.AttachToProcess(ProcessId)) {
			_tcout << _T("AttachToProcess() failed.") << endl;
			return EXIT_FAILURE;
		}
		else
			_tcout << _T("ShowDebug has attached to process ID (") << ProcessId << _T(").") << endl << endl;

	}
	else {
		// Launch requested

		TString CmdLine;

		if (!Helper::GetDebuggeeCommandLine(argc, argv, 1, CmdLine) || CmdLine.empty()) {
			// Something wrong with the command line...
			Helper::PrintHelp();
			return EXIT_SUCCESS;
		}

		_tcout << _T("Mode:      Launch") << endl;
		_tcout << _T("Command:   ") << CmdLine << endl << endl;

		if (!Debugger.StartProcess(_T(""), CmdLine)) {
			_tcout << _T("StartProcess() failed.") << endl;
			return EXIT_FAILURE;
		}

	}

	// Don't kill attached process after exit

	DebugSetProcessKillOnExit(false);


	// Ignore Ctrl+C event

	signal(SIGINT, SIG_IGN);

	// Detect Close event from user

	if (!SetConsoleCtrlHandler(Helper::CtrlHandler, TRUE)) {
		_tcout << endl << _T("Could not set control handler. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("ERROR: Could not set control handler."));
		return EXIT_FAILURE;
	}


	// Enter the debug loop

	Debugger.DebugLoop(INFINITE);


	// Complete

	return EXIT_SUCCESS;
}


/// <summary>
/// CDebugger - constructor
/// </summary>
CDebugger::CDebugger()
	: m_hProcess(nullptr)
{
	// no actions
}

/// <summary>
/// CDebugger - destructor 
/// </summary>
CDebugger::~CDebugger() = default;


/// <summary>
/// This function starts the specified executable under debugger
/// </summary>
/// <param name="FileName">Executable name</param>
/// <param name="CmdLine">Executable, with the specified command line parameters</param>
/// <returns>true or false</returns>
bool CDebugger::StartProcess(const TString& FileName, const TString& CmdLine)
{
	// Prepare parameters for CreateProcess

	LPCTSTR lpFileName = FileName.empty() ? nullptr : FileName.c_str();

	LPTSTR lpCmdLine = nullptr; // It should be writeable - we have to make a copy

	if (CmdLine.length() > 0) {
		lpCmdLine = static_cast<LPTSTR>(new TCHAR[CmdLine.length() + 1]);
		_tcscpy_s(lpCmdLine, (CmdLine.length() + 1) * sizeof(TCHAR), CmdLine.c_str());
	}


	// Create the process 

	STARTUPINFO si = { sizeof(si) };

	PROCESS_INFORMATION pi = { nullptr, nullptr, 0, 0 };

	if (!CreateProcess(lpFileName, lpCmdLine, nullptr, nullptr, FALSE,
		CREATE_NEW_CONSOLE | DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi))
	{
		_tcout << _T("CreateProcess() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("CreateProcess() failed."));
		return false;
	}

	// Set console title to "Name (process name - process id)"

	TCHAR szPath[MAX_PATH];

	if (GetProcessImageFileName(pi.hProcess, szPath, MAX_PATH) == 0) {
		_tcout << _T("GetProcessImageFileName() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("GetProcessImageFileName() failed."));
	}

	_tstringstream consoleName;
	auto ExeName = filesystem::path(szPath).filename()._tstring();

	consoleName << "ShowDebug (" << ExeName << " - " << pi.dwProcessId << ")";
#ifdef _DEBUG
	consoleName << " [DEBUG]";
#endif

	if (!SetConsoleTitle(consoleName.str().c_str())) {
		_tcout << _T("SetConsoleTitle() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("SetConsoleTitle() failed."));
	}

	// Show process name

	_tcout << _T("ShowDebug has started the process: ") << ExeName << endl << endl;

	// Close the process and thread handles 
	// (we can obtain them later with debug events)

	if (pi.hProcess != nullptr)
		if (!CloseHandle(pi.hProcess)) {
			_tcout << _T("CloseHandle() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CloseHandle() failed."));
		}

	if (pi.hThread != nullptr)
		if (!CloseHandle(pi.hThread)) {
			_tcout << _T("CloseHandle() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CloseHandle() failed."));
		}


	// Complete 

	return true;

}


/// <summary>
/// This function attaches the debugger to the specified process
/// </summary>
/// <param name="ProcessId">Process ID</param>
/// <returns>true or false</returns>
bool CDebugger::AttachToProcess(DWORD ProcessId)
{
	if (!DebugActiveProcess(ProcessId)) {
		_tcout << _T("DebugActiveProcess() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("DebugActiveProcess() failed."));
		return false;
	}

	// Set console title to "Name (process name - process id)"
	
	TCHAR szPath[MAX_PATH];
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, ProcessId);

	if (hProcess == nullptr) {
		_tcout << _T("OpenProcess() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("OpenProcess() failed."));
	}

	if (GetProcessImageFileName(hProcess, szPath, MAX_PATH) == 0) {
		_tcout << _T("GetProcessImageFileName() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("GetProcessImageFileName() failed."));
	}

	if (hProcess != nullptr)
		if (!CloseHandle(hProcess)) {
			_tcout << _T("CloseHandle() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CloseHandle() failed."));
		}

	_tstringstream consoleName;
	auto ExeName = filesystem::path(szPath).filename()._tstring();

	consoleName << "ShowDebug (" << ExeName << " - " << ProcessId << ")";
#ifdef _DEBUG
	consoleName << " [DEBUG]";
#endif

	if (!SetConsoleTitle(consoleName.str().c_str())) {
		_tcout << _T("SetConsoleTitle() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("SetConsoleTitle() failed."));
	}

	_tcout << _T("Process:   ") << ExeName << endl << endl;


	return true;
}


/// <summary>
/// This function implements the debugging loop and handles the debug events
/// </summary>
/// <param name="Timeout">The number of milliseconds to wait for a debugging event.</param>
/// <returns>true or false</returns>
bool CDebugger::DebugLoop(DWORD Timeout)
{
	// Run the debug loop and handle the events 

	DEBUG_EVENT DebugEvent;

	bool bContinue = true;

	bool bSeenInitialBreakpoint = false;

	while (bContinue) {
		// Call WaitForDebugEvent 

		if (WaitForDebugEvent(&DebugEvent, Timeout)) {
			// Handle the debug event 

			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
				// Save the process handle
				m_hProcess = DebugEvent.u.CreateProcessInfo.hProcess;

				// Handle the event
				OnCreateProcessEvent(DebugEvent.dwProcessId);
				OnCreateThreadEvent(DebugEvent.dwThreadId);
				OnLoadModuleEvent(DebugEvent.u.CreateProcessInfo.lpBaseOfImage,
					DebugEvent.u.CreateProcessInfo.hFile);

				// With this event, the debugger receives the following handles:
				//   CREATE_PROCESS_DEBUG_INFO.hProcess - debuggee process handle
				//   CREATE_PROCESS_DEBUG_INFO.hThread  - handle to the initial thread of the debuggee process
				//   CREATE_PROCESS_DEBUG_INFO.hFile    - handle to the executable file that was 
				//                                        used to create the debuggee process (.EXE file)
				// 
				// hProcess and hThread handles will be closed by the operating system 
				// when the debugger calls ContinueDebugEvent after receiving 
				// EXIT_PROCESS_DEBUG_EVENT for the given process
				// 
				// hFile handle should be closed by the debugger, when the handle 
				// is no longer needed
				//

				Helper::CloseHandleHelper(DebugEvent.u.CreateProcessInfo.hFile);

				break;

			case EXIT_PROCESS_DEBUG_EVENT:
				// Handle the event
				OnExitProcessEvent(DebugEvent.dwProcessId);

				// Reset the process handle (it will be closed at the next call 
				// to ContinueDebugEvent
				m_hProcess = nullptr;
				bContinue = false; // Last event - exit the loop
				break;

			case CREATE_THREAD_DEBUG_EVENT:
				OnCreateThreadEvent(DebugEvent.dwThreadId);

				// With this event, the debugger receives the following handle:
				//   CREATE_THREAD_DEBUG_INFO.hThread  - handle to the thread that has been created
				// 
				// This handle will be closed by the operating system 
				// when the debugger calls ContinueDebugEvent after receiving 
				// EXIT_THREAD_DEBUG_EVENT for the given thread
				// 

				break;

			case EXIT_THREAD_DEBUG_EVENT:
				OnExitThreadEvent(DebugEvent.dwThreadId);
				break;

			case LOAD_DLL_DEBUG_EVENT:
				OnLoadModuleEvent(DebugEvent.u.LoadDll.lpBaseOfDll, DebugEvent.u.LoadDll.hFile);

				// With this event, the debugger receives the following handle:
				//   LOAD_DLL_DEBUG_INFO.hFile    - handle to the DLL file 
				// 
				// This handle should be closed by the debugger, when the handle 
				// is no longer needed
				//

				Helper::CloseHandleHelper(DebugEvent.u.LoadDll.hFile);

				// Note: Closing the file handle here can lead to the following side effect:
				//   After the file has been closed, the handle value will be reused 
				//   by the operating system, and if the next "load dll" debug event 
				//   comes (for another DLL), it can contain the file handle with the same 
				//   value (but of course the handle now refers to that another DLL). 
				//   Don't be surprised!
				//

				break;

			case UNLOAD_DLL_DEBUG_EVENT:
				OnUnloadModuleEvent(DebugEvent.u.UnloadDll.lpBaseOfDll);
				break;

			case OUTPUT_DEBUG_STRING_EVENT:
				OnDebugStringEvent(DebugEvent.dwThreadId, DebugEvent.u.DebugString);
				break;

			case RIP_EVENT:
				break;

			case EXCEPTION_DEBUG_EVENT:
				OnExceptionEvent(DebugEvent.dwThreadId, DebugEvent.u.Exception);

				// By default, do not handle the exception 
				// (let the debuggee handle it if it wants to)

				ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

				// Now the special case - the initial breakpoint 

				DWORD ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;

				if (!bSeenInitialBreakpoint && (ExceptionCode == EXCEPTION_BREAKPOINT)) {
					// This is the initial breakpoint, which is used to notify the debugger 
					// that the debuggee has initialized 
					// 
					// The debugger should handle this exception
					// 

					ContinueStatus = DBG_CONTINUE;

					bSeenInitialBreakpoint = true;

				}
				break;
			}

			// Let the debuggee continue 

			if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus)) {
				_tcout << _T("ContinueDebugEvent() failed. Error: ") << GetLastError() << endl;
				_RPTFT0(_CRT_ASSERT, _T("ContinueDebugEvent() failed."));
				return false;
			}


			// Proceed to the beginning of the loop...

		}
		else
		{
			// WaitForDebugEvent failed...

			// Is it because of timeout ?

			DWORD ErrCode = GetLastError();

			if (ErrCode == ERROR_SEM_TIMEOUT)
				// Yes, report and continue
				OnTimeout();
			else {
				// No, exit the loop
				_tcout << _T("WaitForDebugEvent() failed. Error: ") << GetLastError() << endl;
				_RPTFT0(_CRT_ASSERT, _T("WaitForDebugEvent() failed."));
				return false;
			}
		}
	}


	// Complete 

	return true;

}


///////////////////////////////////////////////////////////////////////////////
// CDebugger - debug event handlers
//

/// <summary>
/// On create process event handler
/// triggered by CREATE_PROCESS_DEBUG_EVENT
/// </summary>
/// <param name="ProcessId">Process ID</param>
void CDebugger::OnCreateProcessEvent(DWORD ProcessId)
{
	_tcout << _T("The process ") << ProcessId << _T(" has created.") << endl;
}

/// <summary>
/// On exit process event handler
/// triggered by EXIT_PROCESS_DEBUG_EVENT
/// </summary>
/// <param name="ProcessId">Process ID</param>
void CDebugger::OnExitProcessEvent(DWORD ProcessId)
{
	_tcout << _T("The process ") << ProcessId << _T(" has exited.") << endl;
}

/// <summary>
/// On create thread event handler
/// triggered by CREATE_PROCESS_DEBUG_EVENT and CREATE_THREAD_DEBUG_EVENT
/// </summary>
/// <param name="ThreadId">Thread ID</param>
void CDebugger::OnCreateThreadEvent(DWORD ThreadId)
{
	_tcout << _T("The thread 0x") << hex << setw(4) << setfill(_T('0')) << ThreadId << _T(" (") << dec << ThreadId << _T(") has created.") << endl;
}

/// <summary>
/// On exit thread event handler
/// triggered by EXIT_THREAD_DEBUG_EVENT
/// </summary>
/// <param name="ThreadId">Thread ID</param>
void CDebugger::OnExitThreadEvent(DWORD ThreadId)
{
	_tcout << _T("The thread 0x") << hex << setw(4) << setfill(_T('0')) << ThreadId << _T(" (") << dec << ThreadId << _T(") has exited.") << endl;
}

/// <summary>
/// On load module event handler
/// triggered by CREATE_PROCESS_DEBUG_EVENT and LOAD_DLL_DEBUG_EVENT
/// </summary>
/// <param name="ImageBase">The base address of the executable image that the process is running.</param>
/// <param name="hFile">A handle to the process's image file.</param>
void CDebugger::OnLoadModuleEvent(LPVOID ImageBase, HANDLE hFile)
{
	// Check parameters and preconditions

	if (m_hProcess == nullptr) {
		_RPTFT0(_CRT_ASSERT, _T("Debuggee process handle is NULL."));
		return;
	}


	// Obtain the module name and save it for future use

	TString ImageName;

	if (!Helper::GetFileNameFromHandle(hFile, ImageName))
		ImageName = _T(""); // for safety

	m_ModuleNames[ImageBase] = ImageName;


	// Obtain the module size and the address range occupied by the module

	DWORD ModuleSize = 0;

	if (!Helper::GetModuleSize(m_hProcess, ImageBase, ModuleSize)) {
		ModuleSize = 0; // Just in case
		_RPTFT0(_CRT_ASSERT, _T("GetModuleSize() failed."));
	}

	LPVOID ImageEnd = static_cast<BYTE*>(ImageBase) + ModuleSize;


	// Report the event

	_tcout << _T("Loaded: '") << ImageName << _T("'. Address: (") << hex << ImageBase << _T(" - ") << hex << ImageEnd << _T(")") << endl;
}

/// <summary>
/// On unload module event handler
/// triggered by UNLOAD_DLL_DEBUG_EVENT
/// </summary>
/// <param name="ImageBase">The base address of the executable image that the process is running.</param>
void CDebugger::OnUnloadModuleEvent(LPVOID ImageBase)
{
	// Obtain the module name

	TString ImageName(_T("<unknown>"));

	auto pm = m_ModuleNames.find(ImageBase);

	if (pm != m_ModuleNames.end())
		ImageName = pm->second;


	// Report the event

	_tcout << _T("Unloaded: '") << ImageName << _T("'. Address: (") << hex << ImageBase << _T(")") << endl;


	// Remove the module name from the collection

	if (pm != m_ModuleNames.end())
		m_ModuleNames.erase(pm);

}

/// <summary>
/// On exception event handler
/// triggered by EXCEPTION_DEBUG_EVENT
/// </summary>
/// <param name="ThreadId">Thread ID</param>
/// <param name="Info">Contains exception information that can be used by a debugger.</param>
void CDebugger::OnExceptionEvent(DWORD ThreadId, const EXCEPTION_DEBUG_INFO& Info)
{
	_tcout << endl << _T("Exception (") << (Info.dwFirstChance ? _T("first-chance") : _T("second-chance")) << "):" << endl;

	_tcout << _T("  Code:        0x") << hex << Info.ExceptionRecord.ExceptionCode << endl;
	_tcout << _T("  Address:     0x") << hex << Info.ExceptionRecord.ExceptionAddress << endl;
	_tcout << _T("  ThreadId:    0x") << ThreadId << _T(" (") << dec << ThreadId << _T(")") << endl;
	_tcout << _T("  Flags:       0x") << hex << setw(8) << setfill(_T('0')) << Info.ExceptionRecord.ExceptionFlags << endl;
	_tcout << _T("  NumberParameters:  ") << Info.ExceptionRecord.NumberParameters << endl;

	DWORD NumParameters = Info.ExceptionRecord.NumberParameters;

	if (NumParameters > EXCEPTION_MAXIMUM_PARAMETERS)
		NumParameters = EXCEPTION_MAXIMUM_PARAMETERS;

	for (DWORD i = 0; i < NumParameters; i++) 
		_tcout << _T("    Parameter[") << i << _T("]:    ") << dec << Info.ExceptionRecord.ExceptionInformation[i] << endl;
	_tcout << endl;
}

/// <summary>
/// On debug string event handler
/// triggered by OUTPUT_DEBUG_STRING_EVENT
/// </summary>
/// <param name="ThreadId">Thread ID</param>
/// <param name="Info">ontains the address, format, and length, in bytes, of a debugging string.</param>
void CDebugger::OnDebugStringEvent(DWORD ThreadId, const OUTPUT_DEBUG_STRING_INFO& Info)
{
	// Check parameters and preconditions

	if (m_hProcess == nullptr) {
		_RPTFT0(_CRT_ASSERT, _T("Debuggee process handle is NULL."));
		return;
	}

	if ((Info.lpDebugStringData == nullptr) || (Info.nDebugStringLength == 0)) {
		_RPTFT0(_CRT_ASSERT, _T("No debug string information."));
		return;
	}


	// Read the string from the debuggee's address space

	if (Info.fUnicode) {
		// Read as Unicode string

		const SIZE_T cMaxChars = 0xFFFF;
		WCHAR Buffer[cMaxChars + 1] = { 0 };

		SIZE_T CharsToRead = Info.nDebugStringLength;

		if (CharsToRead > cMaxChars)
			CharsToRead = cMaxChars;

		SIZE_T BytesRead = 0;

		if (!ReadProcessMemory(m_hProcess, Info.lpDebugStringData, Buffer, CharsToRead * sizeof(WCHAR), &BytesRead) || (BytesRead == 0)) {
			_tcout << _T("ReadProcessMemory() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("ReadProcessMemory() failed."));
			return;
		}

		wcout << L"OutputDebugString(" << ThreadId << L"): " << Buffer;
	}
	else {
		// Read as ANSI string

		const SIZE_T cMaxChars = 0xFFFF;
		CHAR Buffer[cMaxChars + 1] = { 0 };

		SIZE_T CharsToRead = Info.nDebugStringLength;

		if (CharsToRead > cMaxChars)
			CharsToRead = cMaxChars;

		SIZE_T BytesRead = 0;

		if (!ReadProcessMemory(m_hProcess, Info.lpDebugStringData, Buffer, CharsToRead * sizeof(CHAR), &BytesRead) || (BytesRead == 0)) {
			_tcout << _T("ReadProcessMemory() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("ReadProcessMemory() failed."));
			return;
		}

		cout << "OutputDebugString(" << ThreadId << "): " << Buffer;
	}
}

/// <summary>
/// On timeout handler
/// triggered by ERROR_SEM_TIMEOUT
/// </summary>
void CDebugger::OnTimeout()
{
	_tcout << _T("DebugLoop - Timeout.") << endl;
}
