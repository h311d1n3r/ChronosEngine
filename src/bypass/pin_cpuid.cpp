#include "pin.H"
#include <stdio.h>
#include <stdint.h>

uint64_t leaf_val = 0;
uint64_t rcx, rdx;

VOID CPUIDHook_Before(CONTEXT *ctx) {
    leaf_val = PIN_GetContextReg(ctx, REG_RAX);
    rcx = PIN_GetContextReg(ctx, REG_RCX);
    rdx = PIN_GetContextReg(ctx, REG_RDX);
}

VOID CPUIDHook_After(CONTEXT *ctx) {
    if(leaf_val == 1) {
        printf("[PATCHING CPUID LEAF 1]\n");
        
        uint64_t rcx_mask = 0xFFFFFFFFFFFFFFFF;
        uint64_t rdx_mask = 0xFFFFFFFFFFFFFFFF;
        
        rcx_mask ^= 1; // SSE3
        rcx_mask ^= (1 << 9); // SSSE3
        rcx_mask ^= (1 << 19); // SSE4.1
        rcx_mask ^= (1 << 20); // SSE4.2
        rcx_mask ^= (1 << 28); // AVX
        
        rdx_mask ^= (1 << 25); // SSE
        rdx_mask ^= (1 << 26); // SSE2
        
        PIN_SetContextReg(ctx, REG_RCX, rcx & rcx_mask);
        PIN_SetContextReg(ctx, REG_RDX, rdx & rdx_mask);
        PIN_ExecuteAt(ctx);
    }
}

VOID Instruction(INS ins, VOID *v) {
    if (INS_Opcode(ins) == XED_ICLASS_CPUID) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CPUIDHook_Before, IARG_CONTEXT, IARG_END);
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)CPUIDHook_After, IARG_CONTEXT, IARG_END);
    }
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_StartProgram();
    return 0;
}