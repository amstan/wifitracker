/*!
******************************************************************************
\file appstart.c
\date 2006-12-20
\author andrew tbriers
\brief First function load point from the boot code.

The file contains the first function (app_start) called after the boot code
finishes performing its initialisation. For this case, in which eCos threads are
used, it is responsible for installing the thread(s).

\par Copyright
Information contained herein is proprietary to and constitutes valuable
confidential trade secrets of G2 Microsystems Pty. Ltd., or its licensors, and
is subject to restrictions on use and disclosure.

\par
Copyright (c) 2004, 2005, 2006, 2007, 2008 G2 Microsystems Pty. Ltd. All rights reserved.

\par
The copyright notices above do not evidence any actual or
intended publication of this material.
******************************************************************************
*/

#include <g2types.h>
#include <flashfiledefs.h>
#include <rom_hash.h>
#include <cyg/kernel/kapi.h>
#include <cyg/hal/hal_arch.h>
#include <sys_event.h>
#include <ao_timer.h>
#include <timerdefs.h>
#include <useruart.h>

#include "console802dot11.h"

#include <patches.h>


#define THREAD_PRIORITY     4

// Declare default alarm handling function
void GenerateTimerEvent();

/*
 * Now declare (and allocate space for) some kernel objects, like the thread
 * we will use
 */
cyg_handle_t app_main_thread_handle;
static cyg_thread app_main_thread_info;      /* space for thread object */
static char app_main_thread_stack[CYGNUM_HAL_STACK_SIZE_MINIMUM];       /* space for main thread stack - 4608 is current minimum size */

/*
 * These two global variables are used to ensure that the linker doesn't
 * accidentally relocate the ROM data or bss sections
 */
extern byte g2_data_section_hook;
extern byte g2_bss_section_hook;

/*!
******************************************************************************
Main entry point for the user application. Called from the boot code after
initialisation. This function needs to return so the scheduler will start up
and start running the thread.

\return errorcode   The error condition (if any) that exists after running
                    the main application
\retval 0           The main function ran successfully
\retval non-0       There was an error, the value indicates what type

\param[in] file_handle  The flash file handle of the application
\param[in] rom_hash_hi  The upper 64 bits of the ROM's hash
\param[in] rom_hash_lo  The lower 64 bits of the ROM's hash
*/

uint32 app_start(uint32 handle, uint64 rom_hash_hi, uint64 rom_hash_lo)
{
    uint32 app_result = FILE_VALID_EXECUTION_COMPLETE; // in case we don't match, pretend we finished

    g2_data_section_hook = 0;
    g2_bss_section_hook = 0;

    if (CheckROMHash(rom_hash_hi, rom_hash_lo))
    {
        // Install any software update patches.
        InstallPatches();

        cyg_thread_create(THREAD_PRIORITY, Console802dot11AppMainThread, handle,
                      "Console-controlled 802.11 App Main Thread", (void*)app_main_thread_stack, CYGNUM_HAL_STACK_SIZE_MINIMUM,
                      &app_main_thread_handle, &app_main_thread_info);

        cyg_thread_resume(app_main_thread_handle);
        app_result = FILE_VALID;
    }

    return app_result;  // indicate whether we're compatible
}
