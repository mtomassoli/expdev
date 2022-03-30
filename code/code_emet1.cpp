#include <Windows.h>
#include <winnt.h>
#include <stdio.h>

int main() {
    CONTEXT context;
    printf("sizeof(context) = 0x%x\n", sizeof(context));
    printf("contextFlags offset = 0x%x\n", (int)&context.ContextFlags - (int)&context);
    printf("CONTEXT_DEBUG_REGISTERS = 0x%x\n", CONTEXT_DEBUG_REGISTERS);
    printf("EIP offset = 0x%x\n", (int)&context.Eip - (int)&context);
    printf("Dr0 offset = 0x%x\n", (int)&context.Dr0 - (int)&context);
    printf("Dr1 offset = 0x%x\n", (int)&context.Dr1 - (int)&context);
    printf("Dr2 offset = 0x%x\n", (int)&context.Dr2 - (int)&context);
    printf("Dr3 offset = 0x%x\n", (int)&context.Dr3 - (int)&context);
    printf("Dr6 offset = 0x%x\n", (int)&context.Dr6 - (int)&context);
    printf("Dr7 offset = 0x%x\n", (int)&context.Dr7 - (int)&context);

    _asm {
        // Attach handler to the exception handler chain.
        call    here
    here:
        add     dword ptr [esp], 0x22       // [esp] = handler
        push    dword ptr fs:[0]
        mov     fs:[0], esp

        // Generate the exception.
        xor     eax, eax
        div     eax

        // Restore the exception handler chain.
        pop     dword ptr fs:[0]
        add     esp, 4
        jmp     skip

    handler:
        mov     ecx, [esp + 0Ch]; skip div
        add     dword ptr [ecx + 0B8h], 2               // skip the "div eax" instruction
        xor     eax, eax
        mov     dword ptr [ecx + 04h], eax              // clean dr0
        mov     dword ptr [ecx + 08h], 0x11223344       // just for debugging!
        mov     dword ptr [ecx + 0Ch], eax              // clean dr2
        mov     dword ptr [ecx + 10h], eax              // clean dr3
        mov     dword ptr [ecx + 14h], eax              // clean dr6
        mov     dword ptr [ecx + 18h], eax              // clean dr7
        ret
    skip:
    }

    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &context);
    if (context.Dr1 == 0x11223344)
        printf("Everything OK!\n");
    else
        printf("Something's wrong :(\n");

    return 0;
}
