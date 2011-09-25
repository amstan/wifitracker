/*!
******************************************************************************
\file app.ld
\date 2006-12-01
\author andrew, hoges
\brief Sample Application Linker Script.

This linker script provides the memory layout for applications being compiled
to run on the device.

The default application start point is app_start(). This is the first 
function to be called by the operating system once the device has initialised 
itself.

\par Copyright
Information contained herein is proprietary to and constitutes valuable
confidential trade secrets of G2 Microsystems Pty. Ltd., or its licensors, and
is subject to restrictions on use and disclosure.

\par
Copyright (c) 2004, 2005, 2006, 2007, 2008 G2 Microsystems Pty. Ltd. All
rights reserved.

\par
The copyright notices above do not evidence any actual or
intended publication of this material.
******************************************************************************
*/

ENTRY(app_start)

MEMORY
{
    rom : ORIGIN = 0x00000000, LENGTH = 0x80000
    ram : ORIGIN = 0x40000000, LENGTH = 0x20000
}

SECTIONS
{
    .vectors 0x00000000 : {
        __vectors_start = ABSOLUTE(.);
        KEEP (*(.vectors)) __vectors_end = ABSOLUTE(.);
    } > rom

    .g2_text : {
        _sromtext = ABSOLUTE(.);
        *(.g2_text*) *(.gnu.warning) *(.gnu.linkonce*) *(.g2_init)
    } > rom

    _eromtext = .;
    PROVIDE (_eromtext = .);

    .g2_rodata ALIGN (0x8) : {
        . = .; KEEP (*(.g2_rodata))
    } > rom

    .g2_data 0x40000000 : AT ((LOADADDR (.g2_rodata) + SIZEOF (.g2_rodata) + 8 - 1) & ~ (8 - 1)) {
        __ram_data_start = ABSOLUTE (.);
        *(.g2_data*) *(.g2_data1) _GOT1_START_ = ABSOLUTE (.);
        *(.got1) _GOT1_END_ = ABSOLUTE (.);
        _GOT2_START_ = ABSOLUTE (.);
        *(.got2) _GOT2_END_ = ABSOLUTE (.);
        . = ALIGN (4);
        KEEP(*( SORT (.ecos.table.*)));
        __CTOR_LIST__ = ABSOLUTE (.);
        KEEP(*(SORT(.ctors*))) __CTOR_END__ = ABSOLUTE (.);
        __DTOR_LIST__ = ABSOLUTE (.);
        KEEP(*(SORT(.dtors*))) __DTOR_END__ = ABSOLUTE (.);
        _GOT_START = ABSOLUTE (.);
        _GLOBAL_OFFSET_TABLE_ = ABSOLUTE (.) + 32768;
        _SDA_BASE_ = ABSOLUTE (.);
        *(.got.plt) *(.got) _GOT_END_ = ABSOLUTE (.);
        *(.dynamic) *(.g2_sdata*) *(.g2_sbss*) *(.eh_frame)
    } > ram

    __g2_data_start = LOADADDR (.g2_data);
    . = ALIGN (8);

    __ram_data_end = .;
    PROVIDE (__ram_data_end = .);

    _edata = .;
    PROVIDE (edata = .);

    .g2_bss : {
        __bss_start = ABSOLUTE (.);
        *(.g2_scommon) *(.g2_dynbss) *(.g2_bss) *(g2_COMMON) __bss_end = ABSOLUTE (.);
    } > ram __heap1 = ALIGN (0x8);

    .text ALIGN (0x1) : {
        sramtext = ABSOLUTE(.); *(.text) *(.text.*)
    } > ram eramtext = .;
    PROVIDE (eramtext = .);

    .rodata ALIGN (0x1) : {
        . = .; *(.rodata*)
    } > ram

    .data ALIGN (0x1) : {
        __app_ram_data_start = ABSOLUTE (.);
        *(.data) *(.data.*) *(.data1) *(.sdata) *(.sbss)
    } > ram

    . = ALIGN (8);

    __app_ram_data_end = .;
    PROVIDE (__app_ram_data_end = .);

    _app_edata = .;
    PROVIDE (app_edata = .);

    .bss ALIGN (0x8) : {
        __app_bss_start = ABSOLUTE (.);
        *(.scommon) *(.dynbss) *(.bss) *(.bss.*) *(COMMON) __app_bss_end = ABSOLUTE (.);
    } > ram

    . = ALIGN(8);
    _end = .;
    PROVIDE (end = .);

    .debug 0 : {
        *(.debug)
    }
    .line 0 : {
        *(.line)
    }
    .debug_srcinfo 0 : {
        *(.debug_srcinfo)
    }
    .debug_sfnames 0 : {
        *(.debug_sfnames)
    }
    .debug_aranges 0 : {
        *(.debug_aranges)
    }
    .debug_pubnames 0 : {
        *(.debug_pubnames)
    }
    .debug_info 0 : {
        *(.debug_info)
    }
    .debug_abbrev 0 : {
        *(.debug_abbrev)
    }
    .debug_line 0 : {
        *(.debug_line)
    }
    .debug_frame 0 : {
        *(.debug_frame)
    }
    .debug_str 0 : {
        *(.debug_str)
    }
    .debug_loc 0 : {
        *(.debug_loc)
    }
    .debug_macinfo 0 : {
        *(.debug_macinfo)
    }
    .debug_weaknames 0 : {
        *(.debug_weaknames)
    }
    .debug_funcnames 0 : {
        *(.debug_funcnames)
    }
    .debug_typenames 0 : {
        *(.debug_typenames)
    }
    .debug_varnames 0 : {   
        *(.debug_varnames)
    }
}

