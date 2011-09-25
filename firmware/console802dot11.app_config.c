/*!
******************************************************************************
\file console802dot11.app_config.c
\date 2006-12-20
\author tbriers
\brief

This file contains the GenerateNVMConfig() function which is compiled and
called by the createnvm tool to generate the binary non-volatile memory image
for the Console-controlled 802.11 example application.

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
#include <mac.h>
#include <mac_hw_defines.h>
#include <nvm_g2lib_config.h>  // grab the ROM application configuration definitions
#include <nvm_config.h>        // NVM_ConfigWrite, NVM_ConfigRead
#include <calibration.h>        // calibration flags
#include <useruart.h>
#include <reportinglevels.h>
#include <wepdefs.h>

#include <lwip_network_timers.h>

#include <sys_event.h>   // DEFAULT_IMAGE_LOAD_EVENT

#define G2_APP
#include <lwip/inet.h>
#include <lwip/ip_addr.h>
#undef G2_APP
#include <rom_hash.h>

#include "console802dot11.app_config.h"

#define WEP_USE_104_BIT_KEY 1
#define WEP_USE_40_BIT_KEY 0

//#define USE_STATIC_IP_ADDRESS

// Define if we want to use 40 or 104 bit WEP keys. Use WEP_USE_40_BIT_KEY or WEP_USE_104_BIT_KEY for the definition.
#define WEP_MODE        WEP_USE_104_BIT_KEY
//#define WEP_MODE        WEP_USE_40_BIT_KEY

// Define the default key. It must be between 1 and 4.
#define WEP_DEFAULT_KEY 1                   // The first key is usually the default one.

// Define the default WEP keys for both lengths.
#define WEP_KEY_104_1   {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90}
#define WEP_KEY_104_2   {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
#define WEP_KEY_104_3   {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
#define WEP_KEY_104_4   {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

#define WEP_KEY_40_1    {0x12, 0x34, 0x56, 0x78, 0x90}
#define WEP_KEY_40_2    {0x22, 0x22, 0x22, 0x22, 0x22}
#define WEP_KEY_40_3    {0x33, 0x33, 0x33, 0x33, 0x33}
#define WEP_KEY_40_4    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

// Depending on the selected key length declare the key set
#if WEP_MODE == WEP_USE_104_BIT_KEY
#define WEP_KEYSET  {WEP_KEY_104_1, WEP_KEY_104_2, WEP_KEY_104_3, WEP_KEY_104_4}
#else
#define WEP_KEYSET  {WEP_KEY_40_1, WEP_KEY_40_2, WEP_KEY_40_3, WEP_KEY_40_4}
#endif

/*!
******************************************************************************
Set some of the ROM and Application software configuration values.

\return void    Nothing.
*/

void GenerateNVMConfig()
{
    struct ip_addr ip_address;
    struct ip_addr server_ip_address;
    struct ip_addr netmask;
    struct ip_addr gw;
    struct ip_addr dns;


#ifdef USE_STATIC_IP_ADDRESS
    // Static IP address if required.
    IP4_ADDR(&ip_address, 192,168,1,187);
    IP4_ADDR(&netmask, 255,255,255,0);
    IP4_ADDR(&gw, 192,168,1,99); 
    IP4_ADDR(&dns, 192,168,1,99);
#else // DHCP
    // IP address - These must be configured to 0 for DHCP to work.
    IP4_ADDR(&ip_address, 0,0,0,0);
    IP4_ADDR(&netmask, 0,0,0,0);
    IP4_ADDR(&gw, 0,0,0,0);
    IP4_ADDR(&dns, 0,0,0,0);
#endif

    // Report Server IP Address - This should be changed to fit the developer's network setup
    IP4_ADDR(&server_ip_address, 192,168,1,99);
    // Report server port - should be the same as the value in report_server.py
    uint32 server_port = 50007;

    /*
     * The BSS SSID of the AP with which this application will associate.
     * This should be changed to fit the developer's network setup
     * Normally, the user will scan for this.
     */
    //char join_ssid[MAX_SSID_LEN] = "ap-ssid-change-me";
    //NVM_ConfigWriteBytes(nvm_app_bss_ssid, (byte*)join_ssid);

    /*
     * The channel of the AP with which this application will associate.
     * This should be changed to fit the developer's network setup
     */
    NVM_ConfigWrite(nvm_app_channel, 1);

    NVM_ConfigWrite(nvm_g2lib_vbatt_wifi_mode, 1);

    NVM_ConfigWrite(nvm_g2lib_mac_preferred_rate, SUPPORTED_RATE_54_MBIT_PER_SEC_MASK);
    NVM_ConfigWrite(nvm_g2lib_mac_11g_protection_mode, 0);

    NVM_ConfigWrite(nvm_g2lib_mac_auto_rate_selection, 1); // Change rate automagically

    // Application NVM configuration
    NVM_ConfigWrite(nvm_app_server_ip_address, server_ip_address.addr); // report server
    NVM_ConfigWrite(nvm_app_server_port, server_port); // report server port

    NVM_ConfigWrite(nvm_app_join_bss_timeout_period, 10);   // Timeout for transitions in the Join BSS state machine

    SetUartPrintLevel(REPORTING_LEVEL_INFO, CONSOLE_PRINT, SYSTEM_PRINT | MAC_RX_PRINT | MAC_TX_PRINT | EVENT_PRINT | WPA_PRINT);

    // ROM NVM configuration
    NVM_ConfigWrite(nvm_g2lib_ip_address, ip_address.addr); // Static IP address
    NVM_ConfigWrite(nvm_g2lib_netmask, netmask.addr);
    NVM_ConfigWrite(nvm_g2lib_gw_ip_address, gw.addr);
    NVM_ConfigWrite(nvm_g2lib_gw_ip_address, gw.addr);

    // DNS address
    NVM_ConfigWrite(nvm_app_dns_address, dns.addr);

    NVM_ConfigWrite(nvm_g2lib_mac_listen_interval, (10 * 15) << 8);   // sleep for up to 15s

    // WEP Keys - The 4 default 104bit keys are listed using one variable.
    wep_key_t wep_keys[WEP_MAX_DEFAULT_KEYS] = WEP_KEYSET;

    // Write in the keys as well as setting the default key to 0 - key IDs range from 0-3.
    NVM_ConfigWriteBytes(nvm_app_wep_default_key1, (byte*)wep_keys[0]);
    NVM_ConfigWriteBytes(nvm_app_wep_default_key2, (byte*)wep_keys[1]);
    NVM_ConfigWriteBytes(nvm_app_wep_default_key3, (byte*)wep_keys[2]);
    NVM_ConfigWriteBytes(nvm_app_wep_default_key4, (byte*)wep_keys[3]);
    NVM_ConfigWrite(nvm_app_wep_active_key, (WEP_DEFAULT_KEY)-1);
    NVM_ConfigWrite(nvm_app_wep_mode, WEP_MODE);

    NVM_ConfigWrite(nvm_g2lib_lwip_network_timers, LWIP_ARP_TIMER_ENABLE | LWIP_DHCP_TIMER_ENABLE |  LWIP_DNS_TIMER_ENABLE | LWIP_AUTOIP_TIMER_ENABLE);
    NVM_ConfigWrite(nvm_g2lib_mac_cts_rate, MAC_HW_RATE_11MBPS);    // CTS frames transmitted at 11Mbit/s.

    NVM_ImageMapSetMapping(DEFAULT_IMAGE_LOAD_EVENT, "console802dot11");
}

