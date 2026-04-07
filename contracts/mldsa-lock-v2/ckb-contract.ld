/*
 * CKB contract linker script for RISC-V bare-metal target.
 * Produces two LOAD segments: R-X (text/rodata) and RW (data/bss).
 * CKB-VM requires segments not be both writable and executable.
 */

ENTRY(_start)

SECTIONS {
    . = 0x10000;

    /* ── Read-Execute segment ──────────────────────────────────── */
    .text : {
        *(.text.startup)
        *(.text*)
    }

    /* .rodata MUST start on a page boundary (0x1000). Without this,
     * a page can contain tail bytes of .text (R-E LOAD segment) AND the
     * beginning of .rodata (R LOAD segment). CKB-VM loads LOAD segments
     * at page granularity and freezes the first one it sees — the second
     * then tries to write into a frozen page and the VM halts with
     * MemWriteOnFreezedPage. */
    . = ALIGN(0x1000);

    .rodata : ALIGN(0x1000) {
        *(.rodata*)
        *(.srodata*)
    }

    /* ── Read-Write segment (starts at next page boundary) ─────── */
    . = ALIGN(0x1000);

    .sdata : {
        /* __global_pointer$ lets the linker relax gp-relative accesses.
         * Must be defined 0x800 bytes into the combined sdata/sbss region. */
        __global_pointer$ = . + 0x800;
        *(.sdata*)
    }

    .data : ALIGN(8) {
        *(.data*)
    }

    .sbss : ALIGN(8) {
        *(.sbss*)
    }

    .bss : ALIGN(8) {
        *(.bss*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.riscv.attributes*)
    }
}
