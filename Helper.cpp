///////////////////////////////////////////////////////////////////////////////
//
// Helper.cpp
// 
// Author: playday3008 (GitHub) and Oleg Starodumov (www.debuginfo.com)
//
//


///////////////////////////////////////////////////////////////////////////////
// Include Helper.hpp
//

#include "Helper.hpp"


/// <summary>
/// This function constructs the debuggee command line from the command line 
/// parameters of the debugger
///
/// The first two parameters receive the debugger's command line, 
/// StartIndex parameter identifies the first parameter on the debugger's 
/// command line that belongs to the debuggee's command line 
/// (that is, the path/name of the debuggee executable)
///
/// The constructed command line is returned in the last parameter
/// </summary>
/// <param name="argc">Number of strings in array argv</param>
/// <param name="argv">Array of command-line argument strings</param>
/// <param name="StartIndex">Identifies the first parameter on the debugger's </param>
/// <param name="CmdLine">Pointer to write constructed command line</param>
/// <returns></returns>
bool Helper::GetDebuggeeCommandLine(int argc, TCHAR* argv[], int StartIndex, TString& CmdLine)
{
	// Cleanup the [out] parameter

	CmdLine = _T("");


	// Check parameters 

	_ASSERTE(argc > 0);
	_ASSERTE(argv != nullptr);
	_ASSERTE(StartIndex >= 0);
	_ASSERTE(StartIndex < argc);

	if ((argc <= 0) || (argv == nullptr) || (StartIndex < 0) || (StartIndex >= argc)) {
		_RPTFT0(_CRT_ASSERT, _T("Invalid parameter."));
		return false;
	}


	// Concatenate the parameters to the destination string 

	while (StartIndex < argc) {
		bool HasSpace = (_tcschr(argv[StartIndex], _T(' ')) != nullptr);

		if (HasSpace)
			CmdLine += _T("\"");

		CmdLine += argv[StartIndex];

		if (HasSpace)
			CmdLine += _T("\"");

		if (StartIndex < argc)
			CmdLine += _T(" ");

		StartIndex++;
	}


	// Complete 

	return true;

}


/// <summary>
/// This function uses the file handle to obtain the name of the file.
/// 
/// The implementation is based on MSDN sample (see "Obtaining a File Name 
/// From a File Handle" article).
/// 
/// Note: This function uses PSAPI library, and therefore the sample 
/// does not support Windows 9x operating systems.
/// </summary>
/// <param name="hFile">A handle to the process's image file.</param>
/// <param name="FileName">Pointer to File Name</param>
/// <returns>true or false</returns>
bool Helper::GetFileNameFromHandle(HANDLE hFile, TString& FileName)
{
	// Cleanup the [out] parameter

	FileName = _T("");


	// Check parameters 

	// Is the handle valid ?

	if ((hFile == nullptr) || (hFile == INVALID_HANDLE_VALUE)) {
		_RPTFT0(_CRT_ASSERT, _T(""));
		return false;
	}

	// Does the file have a non-zero size ?
	// (files with zero size cannot be mapped)

	DWORD FileSizeHi = 0;

	DWORD FileSizeLo = GetFileSize(hFile, &FileSizeHi);

	if ((FileSizeLo == INVALID_FILE_SIZE) && (GetLastError() != NO_ERROR)) {
		// GetFileSize failed 
		_tcout << _T("GetFileSize() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("GetFileSize() failed."));
		return false;
	}
	else if ((FileSizeLo == 0) && (FileSizeHi == 0)) {
		// File size is zero
		_RPTFT0(_CRT_ASSERT, _T("File size is zero."));
		return false;
	}


	// Obtain the file name

	bool bSuccess = false;

	HANDLE hMapFile;
	PVOID pViewOfFile = nullptr;

	do {
		// Map the file into memory 

		hMapFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 1, nullptr);

		if (hMapFile == nullptr) {
			// File cannot be mapped
			_tcout << _T("CreateFileMapping() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CreateFileMapping() failed."));
			break;
		}

		pViewOfFile = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 1);

		if (pViewOfFile == nullptr) {
			// View of file cannot be mapped
			_tcout << _T("MapViewOfFile() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("MapViewOfFile() failed."));
			break;
		}


		// Obtain the file name 

		const DWORD cBufSize = MAX_PATH;
		TCHAR szFileName[cBufSize + 1] = { 0 };

		if (!GetMappedFileName(GetCurrentProcess(), pViewOfFile, szFileName, cBufSize)) {
			// GetMappedFileName failed
			_tcout << _T("GetMappedFileName() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("GetMappedFileName() failed."));
			break;
		}


		// Save the file name 

		FileName = szFileName;


		// The file name returned by GetMappedFileName will contain the device name. 
		// Let's replace it with the drive name, if it is available 

		GetFileNameFromHandleHelper(FileName);


		// Record the success

		bSuccess = true;

	} while (false);


	// Cleanup

	if (pViewOfFile != nullptr)
		if (!UnmapViewOfFile(pViewOfFile)) {
			_tcout << _T("UnmapViewOfFile() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("UnmapViewOfFile() failed."));
		}

	if (hMapFile != nullptr)
		if (!CloseHandle(hMapFile)) {
			_tcout << _T("CloseHandle() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CloseHandle() failed."));
		}


	// Complete 

	return bSuccess;

}

/// <summary>
/// Replace device name with the drive name
/// </summary>
/// <param name="FileName">Pointer to File Name</param>
void Helper::GetFileNameFromHandleHelper(TString& FileName)
{
	// Check the parameter

	if (FileName.length() == 0)
		return;


	// Obtain the list of drives available in the system

	const DWORD cBufSize = 512;
	TCHAR szDrives[cBufSize + 1] = { 0 };

	DWORD rv = GetLogicalDriveStrings(cBufSize, szDrives);

	if ((rv == 0) || (rv > cBufSize)) {
		_tcout << _T("GetLogicalDriveStrings() failed. Error: ") << GetLastError() << endl;
		_RPTFT0(_CRT_ASSERT, _T("GetLogicalDriveStrings() failed."));
		return;
	}


	// Walk through the list of drives and find the one 
	// that corresponds to the given file name

	TCHAR* p = szDrives;

	do {
		_ASSERTE(!IsBadStringPtr(p, UINT_MAX));

		TCHAR szDrive[3] = _T(" :");
		_tcsncpy_s(szDrive, 3, p, 2);
		szDrive[2] = 0;

		TCHAR szDevice[cBufSize + 1] = { 0 };

		rv = QueryDosDevice(szDrive, szDevice, cBufSize);

		if ((rv == 0) || (rv >= cBufSize)) {
			_tcout << _T("QueryDosDevice() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("QueryDosDevice() failed."));
		}
		else {
			// Is the device name the same as in the file name ?

			size_t DevNameLen = _tcslen(szDevice);

			if (_tcsnicmp(FileName.c_str(), szDevice, DevNameLen) == 0) {
				// Yes, it is -> Substitute it into the file name

				TCHAR szNewFileName[cBufSize + 1] = { 0 };

				_stprintf_s(szNewFileName, _T("%s%s"), szDrive, FileName.c_str() + DevNameLen);

				FileName = szNewFileName;

				return; // Complete

			}
		}


		// Proceed to the next drive name 

		while (*p++);

	} while (*p);


	// Drive not found, do not change the file name

}


/// <summary>
/// This function obtains the size of the module by analyzing the virtual 
/// memory information of the process
/// </summary>
/// <param name="hProcess">Process handle</param>
/// <param name="ImageBase">The base address of the executable image that the process is running.</param>
/// <param name="Size">Pointer to module size</param>
/// <returns>true or false</returns>
bool Helper::GetModuleSize(HANDLE hProcess, LPVOID ImageBase, DWORD& Size)
{
	// Check parameters and preconditions 

	if (hProcess == nullptr) {
		_RPTFT0(_CRT_ASSERT, _T("Process handle is null."));
		return false;
	}

	if (ImageBase == nullptr) {
		_RPTFT0(_CRT_ASSERT, _T("Module address is null."));
		return false;
	}


	// Scan the address space of the process and determine where the memory region 
	// allocated for the module ends (that is, we are looking for the first range 
	// of pages whose AllocationBase is not the same as the load address of the module)

	bool bFound = false;

	MEMORY_BASIC_INFORMATION mbi;

	BYTE* QueryAddress = static_cast<BYTE*>(ImageBase);

	while (!bFound) {
		if (VirtualQueryEx(hProcess, QueryAddress, &mbi, sizeof(mbi)) != sizeof(mbi))
			break;

		if (mbi.AllocationBase != ImageBase) {
			// Found, calculate the module size
			Size = static_cast<DWORD>(QueryAddress - static_cast<BYTE*>(ImageBase));
			bFound = true;
			break;
		}

		QueryAddress += mbi.RegionSize;

	}


	// Complete

	return bFound;
}


/// <summary>
/// Close handle helper
/// </summary>
/// <param name="h">A handle to the process's image file.</param>
void Helper::CloseHandleHelper(HANDLE h)
{
	if ((h != nullptr) && (h != INVALID_HANDLE_VALUE))
		if (!CloseHandle(h)) {
			_tcout << _T("CloseHandle() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CloseHandle() failed."));
		}
}


/// <summary>
/// This function enables or disables debug privilege
/// </summary>
/// <param name="Enable">Enable/Disable Debug privileges</param>
/// <returns>true or false</returns>
bool Helper::EnableDebugPrivilege(bool Enable)
{
	bool Success = false;

	HANDLE hToken = nullptr;

	do {
		// Open the process' token

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			_tcout << _T("OpenProcessToken() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("OpenProcessToken() failed."));
			break;
		}


		// Lookup the privilege value 

		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;

		if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
			_tcout << _T("LookupPrivilegeValue() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("LookupPrivilegeValue() failed."));
			break;
		}


		// Enable/disable the privilege

		tp.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
			_tcout << _T("AdjustPrivilegeValue() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("AdjustPrivilegeValue() failed."));
			break;
		}


		// Success 

		Success = true;

	} while (false);


	// Cleanup

	if (hToken != nullptr)
		if (!CloseHandle(hToken)) {
			_tcout << _T("CloseHandle() failed. Error: ") << GetLastError() << endl;
			_RPTFT0(_CRT_ASSERT, _T("CloseHandle() failed."));
		}


	// Complete 

	return Success;

}


/// <summary>
/// Detect Close event from user
/// triggered by SetConsoleCtrlHandler()
/// </summary>
/// <param name="fdwCtrlType">The type of control signal received by the handler.</param>
/// <returns>FALSE</returns>
BOOL WINAPI Helper::CtrlHandler(DWORD fdwCtrlType)
{
	if (fdwCtrlType == CTRL_CLOSE_EVENT) {
		std::_tcout << _T("ShowDebug will closed, and debug process will stoped, debugging process stay alive") << std::endl;
		Sleep(1000);
		std::_tcout << _T("Goodbye in 3s") << std::endl;
		Sleep(1000);
		std::_tcout << _T("Goodbye in 2s") << std::endl;
		Sleep(1000);
		std::_tcout << _T("Goodbye in 1.5s") << std::endl;
		Sleep(500);
		std::_tcout << _T("GOODBYE") << std::endl;
		Sleep(500);
	}
	return FALSE;
}


///////////////////////////////////////////////////////////////////////////////
// Help and logo printers 
//

void Helper::PrintHelp()
{
	_tcout << _T("Usage:") << endl;
	_tcout << _T("  ShowDebug -p <pid>   attach to the process") << endl;
	_tcout << _T("  ShowDebug <CmdLine>  launch the process") << endl << endl;
}

void Helper::PrintLogo()
{
	_tcout << _T("ShowDebug") << endl;
	_tcout << _T("Author: playday3008 (GitHub) and Oleg Starodumov (www.debuginfo.com)") << endl << endl;
}
