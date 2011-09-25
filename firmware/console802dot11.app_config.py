"""
Filename:       console802dot11.app_config.py
Date:           2006-12-20
Author:         tbriers
Description:    Sample Application Configuration Generation Script for the
                Console-controlled 802.11 Example Application.

This file defines a number of application configuration items used by the
Console-controlled 802.11 example application. These configuration items can
be read and written in the same manner that the ROM configuration items are,
i.e. using NVM_ConfigRead() and NVM_ConfigWrite(). This script will generate
a header file that can then be used by the application code.

Information contained herein is proprietary to and constitutes valuable
confidential trade secrets of G2 Microsystems Pty. Ltd., or its licensors, and
is subject to restrictions on use and disclosure.

Copyright (c) 2004, 2005, 2006, 2007, 2008 G2 Microsystems Pty. Ltd. All rights reserved.

The copyright notices above do not evidence any actual or
intended publication of this material.
"""

from read_params import *
import sys

nvm = NVMConfig(prefix = "nvm_app_", outfilename = sys.argv[1], config_name = "APP_NVM_CONFIG", config_base_addr = 0x00, config_end_addr = 0x100)

nvm.uint32("server_ip_address")
nvm.uint32("server_port")
nvm.uint32("app_transmit_timer_period")
nvm.uint32("join_bss_timeout_period")

# WEP config
# 13 bytes (or 104 bits) is the maximum WEP key size
nvm.bytes("wep_default_key1", 13)
nvm.bytes("wep_default_key2", 13)
nvm.bytes("wep_default_key3", 13)
nvm.bytes("wep_default_key4", 13)
nvm.byte("wep_active_key")
nvm.byte("wep_mode")


nvm.bytes("bss_ssid", 33)
nvm.uint32("channel")

nvm.uint32("dns_address")


nvm.dump_footer()

