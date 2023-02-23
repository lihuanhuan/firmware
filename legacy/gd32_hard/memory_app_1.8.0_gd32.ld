/* GD32F470VK - 3072K Flash, 256K RAM */
/* program starts at 0x08010400 */
MEMORY
{
	rom (rx) : ORIGIN = 0x08010000, LENGTH = 3072K - 320K
	ram (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
	/*
	ram1 (rwx) : ORIGIN = 0x10000000, LENGTH = 64K
	*/
}
SECTIONS
{
	.confidential (NOLOAD) : {
		*(confidential)
		ASSERT ((SIZEOF(.confidential) <= 32K), "Error: Confidential section too big!");
	} >ram

	.header : ALIGN(4) {
		KEEP(*(.header));
	} >rom AT>rom
}

INCLUDE cortex-m-generic.ld

_codelen = SIZEOF(.text) + SIZEOF(.data) + SIZEOF(.ARM.exidx);

_ram_start = ORIGIN(ram);
_ram_end = ORIGIN(ram) + LENGTH(ram);
_stay_in_bootloader_flag_addr = ABSOLUTE(0x20010000);
_stack = _ram_end - 8;
__stack_chk_guard = _ram_end - 8;
system_millis = _ram_end - 4;

_data_size = SIZEOF(.data);
