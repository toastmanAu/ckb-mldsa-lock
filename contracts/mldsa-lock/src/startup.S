/*
 * Minimal RISC-V entry point for CKB-VM.
 *
 * CKB-VM starts execution at the ELF entry address (_start).
 * We set up the global pointer, then call main().
 * After main returns, we issue the exit ecall (a7=93).
 */

    .section .text.startup, "ax"
    .global _start
    .type _start, @function

_start:
    .option push
    .option norelax
1:  auipc  gp, %pcrel_hi(__global_pointer$)
    addi   gp, gp, %pcrel_lo(1b)
    .option pop

    /* argc = *(sp), argv = sp + 8 (CKB-VM calling convention) */
    lw     a0, 0(sp)
    addi   a1, sp, 8
    li     a2, 0

    call   main

    /* exit(main_result): a7=93, a0=exit_code, ecall */
    li     a7, 93
    ecall
    .size _start, . - _start
