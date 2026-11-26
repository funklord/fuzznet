/* The MPS2 AN385's memory as qemu gives it (project.md sec 1481): 4 MiB
 * of SSRAM at 0 for code and data, a second 4 MiB at 0x20000000 for the
 * stack. qemu loads the ELF in place, so nothing is copied at start. */
ENTRY(reset_handler)

MEMORY
{
	code (rwx) : ORIGIN = 0x00000000, LENGTH = 4M
	ram  (rw)  : ORIGIN = 0x20000000, LENGTH = 4M
}

SECTIONS
{
	.vectors : { KEEP(*(.vectors)) } > code
	.text : { *(.text*) *(.rodata*) } > code
	.data : { *(.data*) } > code
	.bss (NOLOAD) : {
		. = ALIGN(4);
		__bss_start = .;
		*(.bss*) *(COMMON)
		. = ALIGN(4);
		__bss_end = .;
	} > code
	__stack_top = ORIGIN(ram) + LENGTH(ram);
}
