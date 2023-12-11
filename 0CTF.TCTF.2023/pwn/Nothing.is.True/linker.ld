SECTIONS

{

. = 0x2f000;

.text : { *(.text) }

. = 0x31000;

.data : { *(.data) }

.bss : { *(.bss) }

}
