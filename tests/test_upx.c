#include <stdio.h>
#include <windows.h>

void main()
{
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  if (!CreateProcessA(
          NULL,
          "\"C:\\Windows\\System32\\calc.exe\"",
          NULL,
          NULL,
          FALSE,
          0,
          NULL,
          NULL,
          &si,
          &pi))
  {
    puts("CreateProcess failed.");
    return;
  }
  // Wait until child process exits.
  WaitForSingleObject(pi.hProcess, INFINITE);

  // Close process and thread handles.
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
}
