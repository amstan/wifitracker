/*!
******************************************************************************
\file console802dot11.c
\date 2006-12-20
\author tbriers, hoges
\brief Console-controlled 802.11 Example application.

This program combines the functionality of the DHCP example application with
the threaded console application.

It can locate an AP with a given SSID, authenticate, associate and then obtain
a DHCP lease from the network.  During initialisation, it also sets up the UART
interrupts.

The console implements a number commands which can be used to control the
flow of data over the 802.11 link. These include the "scan" command, to find a
list of available APs with which to associate, the "associate" and "deauth"
commands, which can be used to control the state of the association with the
selected AP, and the "send" command, which takes the remainder of the command
line, packages it into a UDP frame and sends it to the report server (see the
README.txt file for a description of the server).

IF the SSID and channel number are correctly specified in the configuration file,
the app will automatically attempt authentication and association at start-up.

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
#include <registers.h>

#include <cyg/hal/hal_arch.h>

#include <wifiif.h>
#include <mac.h>
#include <channel.h>
#include <mac_hw.h>
#include <wlan_gpio.h>

#include <timerdefs.h>
#include <nvm_config.h>
#include <useruart.h>
#include <sys_event.h>
#include <nvm.h>
#include <sensor.h>
#include <ie.h>
#include <powermetrics.h>
#include <ecos_timer.h>
#include <join_bss_fsm.h>

#include <patch_api.h>
#include <patchtablemap.h>

#include <cyg/kernel/kapi.h>
#include <string.h>
#include <flash.h>
#include <flashfiles.h>
#include <watchdog.h>
#include <ecos_timer.h>

#include <lwip/icmp.h>
#include <lwip/inet.h>
#include <lwip/ip.h>
#include <lwip/memp.h>
#include <lwip/err.h>
#include <lwip/stats.h>
#include <lwip/sys.h>
#include <lwip/dhcp.h>
#include <lwip/opt.h>
#include <lwip/mem.h>
#include <lwip/dns.h>

#include <netif/etharp.h>  // for ETHTYPE_ARP
#include <exceptions.h>
#include <wep.h>
#include <wpa.h>
#include <wps.h>
#include <entropy.h>
#include <crypto_common.h>
#include <crypto_modes.h>
#include <crypto_crc32.h>
#include <console.h>
#include <nvm.h>
#include <eapol.h>
#include <ad_hoc.h>
#include <lwip/autoip.h> // Used with adhoc connections

#include <network_thread.h>


#include "console802dot11.h"
#include "console802dot11.app_config.h"

#include <wifi_scan.h>

#define TAB_COMPLETE

uint64 dhcp_start_time = 0;

extern cyg_handle_t join_bss_alarm_handle;
uint32 join_bss_timeout_count = 0;
#define MAX_ASSOC_ATTEMPTS    10

static void EAPOL_DoneCallback(void);

// The number of RSSI Scan results to store for this application.
#define RSSI_SCAN_BUFFER_LEN  25
#define RX_BUFFER_SIZE (1024 * 5)

byte app_mac_rx_buffer[RX_BUFFER_SIZE];

extern struct etharp_entry arp_table[ARP_TABLE_SIZE];

// UDP rx test variables
#define UDP_TIMER_PERIOD  1000
#define UDP_RECEIVE_TIMEOUT_SUBTYPE  0x42

uint32 cumulative_rx_udp_bytes = 0;
uint32 udp_last_rx_time = 0;
uint32 udp_rx_start_time = 0;
cyg_handle_t udp_rx_test_alarm_handle = 0;
cyg_alarm udp_rx_test_alarm;

// Length of time to scan for RSSI results for this application in milliseconds.
#define ACTIVE_RSSI_SCAN_TIME 200  // don't need so long for an active scan
#define PASSIVE_RSSI_SCAN_TIME        500

char* rate_strings[] = {"1", "2", "5.5", "11", "-", "-", "-", "-", "6", "9", "12", "18", "24", "36", "48", "54"};

// Zero terminated list of channels to scan
static uint32 channels_to_scan[] = { 1, 6, 11, 0 };
uint32 rssi_scan_count = 0;

typedef struct {
    uint32 count;
    int32 rssi_min;
    int32 rssi_max;
    int32 rssi_total;
} rate_data_t;

typedef struct {
    rate_data_t success[16];
    rate_data_t failure[16];
    uint32 received_total;
    uint32 filtered;
} sniff_stats_t;

static bool sniffing = FALSE;
static uint32 sniff_ctrl_store = 0;
static uint32 sniff_mgmt_store = 0;
static uint32 sniff_data_store = 0;

static uint32 sniff_ctrl_filter = C_MAC_RX_FTYPE_CTRL_MASK_BITS;
static uint32 sniff_mgmt_filter = C_MAC_RX_FTYPE_MGMT_DATA_MASK_BITS;
static uint32 sniff_data_filter = C_MAC_RX_FTYPE_MGMT_DATA_MASK_BITS;

static byte sniff_mac_filter[MAC_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static bool sniff_mac_filter_en = FALSE;
static bool sniff_prom_mode = TRUE;

static uint64 sniff_start_time = 0;
static sniff_stats_t sniff_stats;

void SnifferDisable(void);
void SnifferEnable(void);
void SnifferClearStats(void);

// 802.11 channel on which we'll transmit/receive
uint32 current_channel = 0;

extern uint32 rx_isr_count;
extern uint32 rx_dsr_count;

// Buffer to store RSSI scan results
static wifi_scan_info_t RSSI_ScanBuffer[RSSI_SCAN_BUFFER_LEN];

extern int atoi(const char* int_str);

#define ECHO_DATA_LEN 1000
struct ip_addr ping_ip_address;
void handle_ping_response(struct pbuf* pbufptr);
uint64 LastPingTime = 0;

#define MAX_PENDING_PING_REQUESTS  10
#define MAX_PENDING_PING_TIME      5000 // milliseconds
uint64 ping_time[MAX_PENDING_PING_REQUESTS] = { 0 };
uint16 ping_seq[MAX_PENDING_PING_REQUESTS] = { 0 };
extern u16_t ping_sequence_number;

char scan_ssidbuf[MAX_SSID_LEN + 1];

void DumpRxFrame(pbufptr_t pbufptr);

/*
 * Counter to store how many button press events occur.  This is used in the
 * creation of a frame to send to the report server.
 */
static uint32 buttonpress_count = 0;

// Flag whether we should print received frames.
static bool rx_print = FALSE;

/*
 * Buffer space to construct the data to transmit to the report server.  This is
 * used for the payload of the UDP packet and is updated with information
 * regarding the button press state.
 */
#define REPORT_PAYLOAD_SIZE 256 // enough buffer space to store a fair sized message from the console
static char report_string[REPORT_PAYLOAD_SIZE];

// Network Interface for the chip for use with LWIP and other network functions
extern struct netif wifi_if;

// Unique identifiers for eCos timer events for this application
#define STATISTICS_TIMER_SUBTYPE        4

//! The BSS SSID of the AP with which this application will associate.
char bss_ssid[MAX_SSID_LEN + 1];

// Local structure for UDP
struct udp_pcb local_udp_pcb;

extern char ip_thread_stack[];

#define MEM_SIZE_ALIGNED  LWIP_MEM_ALIGN_SIZE(MEM_SIZE)
static u8_t ram_heap[MEM_SIZE_ALIGNED + (2*SIZEOF_STRUCT_MEM) + MEM_ALIGNMENT];

// Forward Declarations
static void InitialiseApplication(void);
static void InitialiseDeviceAtPowerOnReset(void);
static err_t UDP_Init();
static void SendReport(void);
static void UpdateReportData(sys_event_t* eventptr);
static void RxCharDSR(cyg_vector_t vector, cyg_ucount32 count, cyg_addrword_t isr_data);

static bool SnifferReceiveHandler(pbufptr_t pbufptr);

static void DisplayRSSI_Scan(wifi_scan_info_t* rssi_bufptr, uint32 rssi_buf_len, uint32 scan_count);

void Patched_eCos_WatchdogKick(void);
bool Patched_MAC_DiscardUnwantedFrameInDSR(byte* frameptr, uint32 framelen);
err_t Patched_MAC_OutputScatter(byte* payloadptr, uint32 length, uint32 frame_type, tx_meta_data_t* mdptr);

bool ConsoleOpen_Init(void);
bool ConsoleWPA_Init(void);
wpa_conf_t wpa_config = {0};

static void DHCP_StateHandler(unsigned char state);
static void HandleReportServerResponse(sys_event_t* eventptr);
void adhoc_autoip_status_callback(struct netif *netif);

#define MAX_LINE_LENGTH  128
#define DELIMIT " "

#define MAX_ARGUMENTS      18

#define UART_RX_FIFO_LEN 128
byte uart_rx_fifo[UART_RX_FIFO_LEN + 1];

#ifdef USE_UART_TX_INTERRUPT
#define UART_TX_FIFO_LEN 1024
byte uart_tx_fifo[UART_TX_FIFO_LEN + 1];
#else
#define UART_TX_FIFO_LEN 0
#define uart_tx_fifo    NULL
#endif

cyg_handle_t inactivity_alarm_handle = 0;
cyg_alarm inactivity_alarm;

uint32 isr_event_count = 0;

uint32 rep_count = 0;

static struct netconn* conn = NULL;

static struct netconn* rx_conn = NULL;

extern const command_t commands[];

int32 my_file_handle = INVALID_FILE_HANDLE;

extern uint32 NetworkThreadPost_FailureCount;

#define TCP_TEST_MAX_DATA_LENGTH  500
byte tcp_test_data[TCP_TEST_MAX_DATA_LENGTH] = { 0 };

uint32 tcp_port = 50008;
uint32 tcp_send_length = 100;
uint32 tcp_send_count = 100;

byte wpa_password[WPA_PASSPHRASE_LEN_MAX + 1] = "password";

void *original_discard = NULL;
static bool previous_addr_mode = 0;

/*!
******************************************************************************
Console-controlled 802.11 Example Application main thread.

Loop "forever", calling GetNextEvent(). When we run out of events,
GetNextEvent() will block. This program calls PowerDownDisable and leaves a
couple of eCos timers running all the time so the processor will never be put
into the low-power state.

\return     void    Nothing.

\param[in]  file_handle Data passed in by cyg_thread_create() - in this case
                        it is the flash file handle of the application.
*/

void Console802dot11AppMainThread(cyg_addrword_t file_handle)
{

    my_file_handle = file_handle;

    sys_event_t* eventptr = NULL;

    ExcpInitHandler();

    PatchTableInsertPatch(eCos_WatchdogKick_PATCH_INDEX, Patched_eCos_WatchdogKick);

    /*
     * These two counters provide diagnostic information about the current
     * execution of the application.  This is only used in the event display
     * prints, which may be useful during application development.
     */
    int event_count = 0;
    uint32 restart_count = NVM_ConfigRead(nvm_g2lib_restart_count);

    UartPrintf(CONSOLE_PRINT, "\n<SDK Version %s-%s>\n", SDK_DESIGNATION, GetSDK_VersionString());
    UartPrintf(REPORTING_LEVEL_INFO | STARTUP_PRINT, "\n\nConsole-controlled 802.11 Example Application\n");
    UartPrintf(REPORTING_LEVEL_INFO | STARTUP_PRINT, "---------------------------------------------\n");


    RealTimeClockGetMilliseconds(&dhcp_start_time);

    // best for a console is to run both Rx and Tx interrupts
    UserUartInterruptInit(uart_tx_fifo, UART_TX_FIFO_LEN, uart_rx_fifo, UART_RX_FIFO_LEN, RxCharDSR);

    if (GetPowerOnReset())
    {
        InitialiseDeviceAtPowerOnReset();
    }
    InitialiseApplication();

    // Initialise Console
    ConsoleMaxParams = MAX_ARGUMENTS;
    ConsoleInitUseFreeMem(commands, MAX_LINE_LENGTH);

    while (1)
    {
        eventptr = GetNextEvent();
        event_count++;
        switch (eventptr->type)
        {
        case APP_RELOAD_EVENT:
            UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "%d/%d APP_RELOAD_EVENT\n");
            break;
        case WATCHDOG_RESET_EVENT:
            /*
             *  This event will only occur if an there is an error in the
             *  software. It has been left in this application because it can
             *  be useful to handle this case during development. This event
             *  should never been seen in normal operation.
             */
            UartPrintf(REPORTING_LEVEL_ERROR, "%d/%d *ERROR* WATCHDOG_RESET_EVENT (reset at: 0x%x)\n\n%s", event_count, restart_count, eventptr->subtype, ConsolePromptString);
            // fall through to PoR
        default:
            if (eventptr->type != WATCHDOG_RESET_EVENT)
            {
                UartPrintf(REPORTING_LEVEL_WARNING, "Unexpected event (type %d/0x%x: %s)\n", eventptr->type, eventptr->type, GetEventName(eventptr->type));
            }
            // fall through to PoR
        case POWER_ON_RESET_EVENT:
            if (eventptr->type == POWER_ON_RESET_EVENT)
            {
                UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d POR_EVENT subtype %d\n", event_count, restart_count, eventptr->subtype);
            }
            /*
             * POWER_ON_RESET_EVENT: This event will normally occur once only
             * in the lifetime of a device. The application will generally invoke
             * operations to initialise the always-on side of the chip.
             */
            UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d Handled POR_EVENT subtype %d\n", event_count, restart_count, eventptr->subtype);
            break;

        case RX_CHAR_EVENT:
            UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d RX_CHAR_EVENT subtype %d\n", event_count, restart_count, eventptr->subtype);

            // Halt sniffing on any character press
            if (UartGetRxCharsAvailable() && (sniffing == TRUE))
            {
                SnifferDisable();
            }

            while (UartGetRxCharsAvailable() != 0)
            {
#ifdef TAB_COMPLETE
                ConsoleProcessCharWithTabComplete(UartGetChar());
#else
                ConsoleProcessChar(UartGetChar());
#endif
            }
            break;


        case IP_RX_DATA_EVENT:
            /*
             * IP_RX_DATA_EVENT: This occurs for frames that have been passed
             * through the LWIP stack, for example, a UDP frame that has
             * arrived at a port which we are listening on.  It will not occur
             * for frames which LWIP can handle itself, such as ARP and ICMP.
             */
            UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d IP_RX_EVENT\n", event_count, restart_count);
            // Handle responses from our simple report server.
            HandleReportServerResponse(eventptr);
            break;

        // we use eCos timers to stimulate the application to send various frames, depending on its current state
        case ECOS_TIMER_EVENT:
            /*
             * ECOS_TIMER_EVENT: This application uses the event
             * subtype to identify which timer has expired.
             */
            UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d ECOS_TIMER_EVENT subtype %d\n", event_count, restart_count, eventptr->subtype);
            switch (eventptr->subtype)
            {
            case WPA_EAPOL_TIMEOUT_SUBTYPE:
                UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "EAPOL Timeout occurred. Four way handshake failed.\n");
                // deauth and try again
                MAC_SendDeauthentication(*MAC_GetBSSID(), 0x0001);
                join_bss_timeout_count = 0;
                JoinBSS_FSM_TransmitRequest();
                break;

            case SCAN_TIMER_SUBTYPE:
                WiFiScanTimerEvent();
                break;

            case UDP_RECEIVE_TIMEOUT_SUBTYPE:
                eCosTimerDisable(udp_rx_test_alarm_handle);
                float rx_bytes = cumulative_rx_udp_bytes;
                float udp_rx_time = udp_last_rx_time - udp_rx_start_time;
                UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Received %d bytes in %.1fms (%d %d) @ %.2fMbit/s)\n\n%s", cumulative_rx_udp_bytes, udp_rx_time, udp_rx_start_time, udp_last_rx_time, ((rx_bytes * 8000.0)/udp_rx_time) / 1000000.0, ConsolePromptString);
                cumulative_rx_udp_bytes = 0;
                udp_last_rx_time = 0;
                udp_rx_start_time = 0;
                break;
            }
            break;

        case DHCP_COMPLETE_EVENT:
            /*
             * DHCP_COMPLETE_EVENT: This occurs when DHCP has obtained a
             * lease, bound the addresses to the interface and then set the
             * network interface to be up.
             */
        {
            MAC_EnableHwStats();
            uint64 dhcp_time;
            RealTimeClockGetMilliseconds(&dhcp_time);
            dhcp_time -= dhcp_start_time;
            UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d DCHP_COMPLETE_EVENT\n", event_count, restart_count);

            UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "DHCP Completed in %lldms: IP: %u.%u.%u.%u  NM: %u.%u.%u.%u  GW: %u.%u.%u.%u  DNS: %u.%u.%u.%u (Renew: %d sec)\n\n%s",
                       dhcp_time,

                       ip4_addr1(&wifi_if.ip_addr),
                       ip4_addr2(&wifi_if.ip_addr),
                       ip4_addr3(&wifi_if.ip_addr),
                       ip4_addr4(&wifi_if.ip_addr),

                       ip4_addr1(&wifi_if.netmask),
                       ip4_addr2(&wifi_if.netmask),
                       ip4_addr3(&wifi_if.netmask),
                       ip4_addr4(&wifi_if.netmask),

                       ip4_addr1(&wifi_if.gw),
                       ip4_addr2(&wifi_if.gw),
                       ip4_addr3(&wifi_if.gw),
                       ip4_addr4(&wifi_if.gw),

                       ip4_addr1(&wifi_if.dhcp->offered_dns_addr[0]),
                       ip4_addr2(&wifi_if.dhcp->offered_dns_addr[0]),
                       ip4_addr3(&wifi_if.dhcp->offered_dns_addr[0]),
                       ip4_addr4(&wifi_if.dhcp->offered_dns_addr[0]),
                       wifi_if.dhcp->offered_t2_rebind,
                       ConsolePromptString);

            // avoid trying to ARP self
            for (int i = 0; i < ARP_TABLE_SIZE; i++)
            {
                if (arp_table[i].state == ETHARP_STATE_EMPTY)
                {
                    arp_table[i].state = ETHARP_STATE_STABLE;
                    memcpy(&arp_table[i].ipaddr, &wifi_if.ip_addr, sizeof(struct ip_addr));
                    arp_table[i].ctime = 100;
                    arp_table[i].q = NULL;
                    memcpy(&arp_table[i].ethaddr, MAC_GetMyMACAddress(), MAC_ADDR_LEN);
                    arp_table[i].netif = &wifi_if;
                    i = ARP_TABLE_SIZE;
                }
            }

            break;
        }

        case MAC_RX_EVENT:
        {
            /*
             * MAC_RX_EVENT: This occurs for all frames received that are not
             * passed into the LWIP stack. The main thread delegates their
             * handling to the JoinBSS state machine
             */
            JoinBSS_FSM_ReceiveResponse(eventptr);
            break;
        }

        case FRAME_SENT_EVENT:
        {
            pbufptr_t pbufptr = (pbufptr_t)eventptr->subtype;

            tx_meta_data_t* mdptr = GetTxMetaDataPtr(pbufptr);

            UartPrintf(REPORTING_LEVEL_ERROR, "\rFrame Tx %s %d. Tx rate:%sMbit/s Retries:%d Status = 0x%x (vbatt %duV).\n\n%s", ((mdptr->notify & NOTIFY_FAIL_FLAG) == 0) ? "Success" : "Failure", mdptr->notify & ~NOTIFY_FAIL_FLAG, rate_strings[mdptr->rate], mdptr->retries, mdptr->tx_status, (10 * SmuResultAsMicrovolts(mdptr->vbatt)), ConsolePromptString);

            pbuf_free(pbufptr);
            break;
        }

        case EAPOL_FAILURE_EVENT:
            UartPrintf(REPORTING_LEVEL_ERROR, "EAPOL handshake failed at state %d.\n", eventptr->subtype);
            break;

        case BUTTON_EVENT:
            UartPrintf(REPORTING_LEVEL_INFO | EVENT_PRINT, "%d/%d BUTTON_EVENT (state: %s)\n", event_count, restart_count, "PRESSED");

            UpdateReportData(eventptr);

            // Immediately send the periodic report
            SendReport();

            ResetButtons();
            break;
        }

        EventDispose(eventptr);
        WatchdogHoldOff(AO_TICK_SOURCE_ONE_512TH_HZ, 0xfffff);
    }
}


/*!
******************************************************************************
Disconnect callback function to the JoinBSS state machine.

\return void
*/

static void DisconnectCallback(join_bss_disconnect_reason_t reason, uint32 data)
{
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Disconnected from %s. Reason: %d, Data: %d\n\n%s", bss_ssid, reason, data, ConsolePromptString);

    MAC_SendDeauthentication(*MAC_GetBSSID(), 0x0001);

    dhcp_stop(&wifi_if);
    netif_set_down(&wifi_if);
}


/*!
******************************************************************************
*/

static bool SnifferReceiveHandler(pbufptr_t pbufptr)
{
    bool handled = FALSE;
    if (sniffing)
    {
        sniff_stats.received_total++;

        // Record some statistics based on rate
        rx_meta_data_t* mdptr = GetRxMetaDataPtr(pbufptr);
        sniff_stats.success[mdptr->rate].count++;
        handled = TRUE;

        DumpRxFrame(pbufptr);
    }
    return handled;
}


/*!
******************************************************************************
This callback has been attached to the Join BSS state machine to be executed
as soon as the device is connected to an Access Point.  It configures and starts
DHCP.  If DHCP was already running then it restarts it.

\param[in] void
*/

static void ConnectCallback(void)
{
    UartPrintf(CONSOLE_PRINT, "\nConnected.\n");

    if (NVM_ConfigRead(nvm_g2lib_ip_address) != 0)
    {
        // Configure a static IP address
        struct ip_addr ipaddr;
        struct ip_addr netmask;
        struct ip_addr gw;
        struct ip_addr dnsserver;

        ipaddr.addr = NVM_ConfigRead(nvm_g2lib_ip_address);
        netmask.addr = NVM_ConfigRead(nvm_g2lib_netmask);
        gw.addr = NVM_ConfigRead(nvm_g2lib_gw_ip_address);
        dnsserver.addr = NVM_ConfigRead(nvm_app_dns_address);

        netif_set_addr(&wifi_if, &ipaddr, &netmask, &gw);
        dns_setserver(0, &dnsserver);
        netif_set_up(&wifi_if);

        UartPrintf(CONSOLE_PRINT, "Using Static IP Configuration.\n\n%s", ConsolePromptString);
    }
    else
    {
        /*
         * The call to dhcp_start allocates the DHCP structure and sets a pointer
         * to it from in the network interface structure.
         */
        if (!netif_is_up(&wifi_if))
        {
            RealTimeClockGetMilliseconds(&dhcp_start_time);

            if (wifi_if.dhcp == NULL)
            {
                UartPrintf(CONSOLE_PRINT, "\nDHCP: Starting... %lld (%d)\n", dhcp_start_time, MAC_GetRxBroadcastStatus());
                dhcp_start(&wifi_if);
            }
            else
            {
                UartPrintf(CONSOLE_PRINT, "\nDHCP: Restarting...\n");

                RealTimeClockGetMilliseconds(&dhcp_start_time);

                dhcp_stop(&wifi_if);

                // Disable the network interface so DHCP will restart correctly.
                netif_set_down(&wifi_if);

                // Receive the next DHCP complete event.
                dhcp_start(&wifi_if);
            }
        }
        else
        {
            RealTimeClockGetMilliseconds(&dhcp_start_time);
            EventPost(DHCP_COMPLETE_EVENT, DHCP_BOUND);
        }
    }
}


/*!
******************************************************************************
EAPOL Callback function.

This function is called by the WPA subsystem once the WPA four way handshake
has successfully completed. It should kick off any network communication that
is required by the application - in this examples case, send some UDP packets.

\return     void.
*/

static void EAPOL_DoneCallback(void)
{
    UartPrintf(REPORTING_LEVEL_ERROR, "EAPOL Done Callback.\n");
    WPA_State.eapol_done_callback = NULL;
    ConnectCallback();
}


/*!
******************************************************************************
As this application uses direct access to the LWIP API, a receive callback
must be provided for UDP.

\param[in] void
*/

static void UDP_ReceiveCallback(void* arg, struct udp_pcb* pcb, struct pbuf* pbufptr, struct ip_addr* addr, u16_t port)
{
    char packet_print_buffer[REPORT_PAYLOAD_SIZE];
    uint32 len;

    if (udp_last_rx_time != 0)
    {   // used as a flag to tell when we're running the UDP rx test
        cumulative_rx_udp_bytes += pbufptr->len;
        udp_last_rx_time = GetUpTime();
        if (udp_rx_start_time == 0)
        {
            udp_rx_start_time = udp_last_rx_time;
            eCosTimerInit(cyg_current_time() + (UDP_TIMER_PERIOD MILLISECONDS),
                          UDP_TIMER_PERIOD MILLISECONDS,
                          (cyg_addrword_t)UDP_RECEIVE_TIMEOUT_SUBTYPE,
                          &udp_rx_test_alarm_handle,
                          &udp_rx_test_alarm);
        }
    }
    if (rx_print == TRUE)
    {
        // Copy the UDP payload into a temporary buffer so we can zero terminate it for printing.
        if (pbufptr->len > sizeof(packet_print_buffer))
        {
            memcpy(packet_print_buffer, pbufptr->payload, sizeof(packet_print_buffer)); // copy the buffer so it can be modified for printing
            len = sizeof(packet_print_buffer);
        }
        else
        {
            memcpy(packet_print_buffer, pbufptr->payload, pbufptr->len);
            len = pbufptr->len;
        }

        packet_print_buffer[len] = '\0';  // ensure the data is string delimited

        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\b\bReceived: %s\n\n%s", packet_print_buffer, ConsolePromptString);
    }

    pbuf_free(pbufptr);
}


/*!
******************************************************************************
Configure a new UDP connection for our simple report mechanism.  This
initialises the data structures required to use LWIP's direct API to transmit
and receive UDP messages on a specific port.

Allocation of the UDP data structure has been done using the application space
in the variable local_udp_pcb.  This is so that bothD HCP & UDP can be run
simultaneously with the limited buffer space.

The server IP address and port to which the application sends its report data
are read from application specific NVM configuration.

\return err_t LWIP error structure indicating the success (or failure) of the connect call.
\param[in] void
*/

static err_t UDP_Init(void)
{
    static struct ip_addr server_addr;
    uint32 server_port;

    // Get the server IP address and port from NVM.
    server_addr.addr = NVM_ConfigRead(nvm_app_server_ip_address);
    server_port = NVM_ConfigRead(nvm_app_server_port);

    /*
     * Initialise the LWIP UDP connection (sets up conn data structures etc)
     * Refer to LWIP documentation.
     */
    struct udp_pcb* local_udp_pcb_ptr = &local_udp_pcb;

    memset(local_udp_pcb_ptr, 0, sizeof(struct udp_pcb));
    local_udp_pcb_ptr->ttl = UDP_TTL;

    udp_recv(local_udp_pcb_ptr, UDP_ReceiveCallback, &wifi_if);
    udp_bind(local_udp_pcb_ptr, IP_ADDR_ANY, 4096);
    return udp_connect(local_udp_pcb_ptr, &server_addr, server_port);
}


/*!
******************************************************************************
Send a report using the initialised UDP connection.

LWIP will handle ARP if required.

\return void
\param[in] void
*/

static void SendReport(void)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated()) // only send report if the application is associated
    {
        struct pbuf* pbufptr;
        struct udp_pcb* local_udp_pcb_ptr = &local_udp_pcb;

        /*
         * Reference, rather than copy, the report data (including the string
         * delimiter) to the pbuf structure.  This saves on memory as only a
         * small pbuf structure to contain the header information is required.
         * and the report data already formatted in the application is used as
         * the payload.
         */
        pbufptr = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_REF);
        pbufptr->payload = report_string;
        pbufptr->len = pbufptr->tot_len = strlen(report_string) + 1;

        pbufptr->buf_startptr = pbufptr->payload;
        pbufptr->buf_endptr = report_string + sizeof(report_string);

        tx_meta_data_t* metadataptr = pbuf_setmetadataptr(pbufptr, sizeof(tx_meta_data_t));

        memset(metadataptr, 0, sizeof(tx_meta_data_t) - sizeof(uint32*));  // zero all the metadata except the pointer at the end

        metadataptr->notify = 5;


        udp_send(local_udp_pcb_ptr, pbufptr);

        /*
         * Free the buffer.  There is limited buffer space so it is
         * good practice to cleanup immediately.
         */
        pbuf_free(pbufptr);
    }
}


/*!
******************************************************************************
Format a string to send to the application report server.

\return void
\param[in] eventptr Pointer to the AO event
*/

static void UpdateReportData(sys_event_t* eventptr)
{
    // Update the periodic report  with the latest button press state and count
    if (eventptr->type == BUTTON_EVENT)
    {
        buttonpress_count++;
    }
    diag_sprintf(report_string, "Button Press: %s Event Count: %d", "NOT PRESSED", buttonpress_count);
}


extern struct udp_pcb* dns_pcb;
struct dns_table_entry dns_table_space[DNS_TABLE_SIZE] = {{0}}; // must be initialised to zero

byte topup_mem[30 * LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf))];
byte topup_msg[30 * LWIP_MEM_ALIGN_SIZE(sizeof(struct tcpip_msg))];
byte sys_memvar[2 * ADDITIONAL_NETWORK_CONNECTION_SIZE];


/*!
******************************************************************************
Initialise the device on reboot.

This function should be run every time the application executes.
*/

static void InitialiseApplication(void)
{
    MAC_Init(ip_thread_stack, app_mac_rx_buffer, RX_BUFFER_SIZE, ram_heap, MEM_SIZE_ALIGNED);

    char            bssid_str_buf[MAC_STRING_BUFFER_SIZE];
    MAC_addr_t*     device_mac;

    device_mac = MAC_GetMyMACAddress();
    UartPrintf(REPORTING_LEVEL_INFO | STARTUP_PRINT, "MAC Address: %s\n", MAC_FormatAddressString((byte*)device_mac, bssid_str_buf));


    MAC_EnableHwStats();
    MAC_ClearRxStats();
    MAC_ClearTxStats();

    if (dns_pcb == NULL)
    {
        dns_init(dns_table_space, DNS_TABLE_SIZE, NULL, DNS_MSG_SIZE, 2);
    }

    tcp_port = NVM_ConfigRead(nvm_app_server_port);

    MAC_SetMgmtAndDataFilter(0);

    lwip_stats_topup_start();

    memp_topup(MEMP_RX_PBUF, topup_mem, sizeof(topup_mem));
    memp_topup(MEMP_TCPIP_MSG_API, topup_msg, sizeof(topup_msg));
    sys_topup(sys_memvar, sizeof(sys_memvar));

    lwip_stats_topup_end();

    MAC_HW_RestoreAppTxRates();

    join_bss_alarm_handle = 0;

    current_channel = NVM_ConfigRead(nvm_app_channel);

    if (current_channel != 0)
    {
        int32 err = 0;
        err = MAC_SetChannelNum(current_channel);
        if (err != MAC_CHANNEL_STATUS_OK)
        {
            UartPrintf(REPORTING_LEVEL_ERROR | STARTUP_PRINT, "Failed to set channel frequency for channel %d (err = %d)\n", current_channel, err);
            current_channel = 0;
        }
    }

#ifdef BOARDCONF_ANTENNA_DEFAULT
    MAC_HW_SelectAntenna(BOARDCONF_ANTENNA_DEFAULT);
#endif

    // Install the state change handler.
    DHCP_StateMachineCallback = DHCP_StateHandler;

    UDP_Init();

    /*
     * The interface has to be disabled for DHCP - which will enable it when
     * an address has been configured
     */
    netif_set_down(&wifi_if);

#ifdef BOARDCONF_SENSOR_SWITCH // Only Initialise if the board has a switch
    PushButtonSingleInterruptInit(BOARDCONF_SENSOR_SWITCH);
#endif


    // Initialise the data to be transmitted.
    diag_sprintf(report_string, "Button Press: %s Event Count: %d", "NOT PRESSED", buttonpress_count);

    // Get the SSID of the AP with which to associate, from NVM
    NVM_ConfigReadBytes(nvm_app_bss_ssid, (byte*)bss_ssid);

    PowerDownDisable();

    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "802.11 interface is %s\nIP: %u.%u.%u.%u  NM: %u.%u.%u.%u GW: %u.%u.%u.%u\n",
               netif_is_up(&wifi_if) ? "UP" : "DOWN",
               ip4_addr1(&wifi_if.ip_addr),
               ip4_addr2(&wifi_if.ip_addr),
               ip4_addr3(&wifi_if.ip_addr),
               ip4_addr4(&wifi_if.ip_addr),

               ip4_addr1(&wifi_if.netmask),
               ip4_addr2(&wifi_if.netmask),
               ip4_addr3(&wifi_if.netmask),
               ip4_addr4(&wifi_if.netmask),

               ip4_addr1(&wifi_if.gw),
               ip4_addr2(&wifi_if.gw),
               ip4_addr3(&wifi_if.gw),
               ip4_addr4(&wifi_if.gw));

    UartPrintf(CONSOLE_PRINT, "\n\n");
}


/*!
******************************************************************************
Initialise the device on the power-on reset.

This function should be run once only, not on each reboot.
*/

static void InitialiseDeviceAtPowerOnReset(void)
{
#ifdef BOARDCONF_SENSOR_SWITCH // Only Initialise if the board has a switch
    PushButtonInit(BOARDCONF_SENSOR_SWITCH, TRUE, FALSE);
#endif
}


/*!
******************************************************************************
Provide an event based on the state change of DHCP. This function is installed
into a callback routine within the DHCP state machine.

*/

static void DHCP_StateHandler(unsigned char state)
{
    switch (state)
    {
    case DHCP_RENEWING:
        RealTimeClockGetMilliseconds(&dhcp_start_time);
        UartPrintf(CONSOLE_PRINT, "DHCP: Renewing Lease...\n");
        break;

    case DHCP_REBINDING:
        RealTimeClockGetMilliseconds(&dhcp_start_time);
        UartPrintf(CONSOLE_PRINT, "DHCP: Rebinding Lease...\n");
        break;

    case DHCP_BOUND:
        EventPost(DHCP_COMPLETE_EVENT, state);
        break;
    }
}



// ******************************************************************************
// Console Functionality
// ******************************************************************************

cmd_err_t busy_command(uint32 argc, char** argv);
cmd_err_t dig_command(uint32 argc, char** argv);
cmd_err_t exit_command(uint32 argc, char** argv);
cmd_err_t ls_command(uint32 argc, char** argv);
cmd_err_t ifdown_command(uint32 argc, char** argv);
cmd_err_t ifup_command(uint32 argc, char** argv);
cmd_err_t send_command(uint32 argc, char** argv);
cmd_err_t scatter_command(uint32 argc, char** argv);
cmd_err_t udp_flood_command(uint32 argc, char** argv);
cmd_err_t udp_rx_command(uint32 argc, char** argv);
cmd_err_t tx_vbatt_command(uint32 argc, char** argv);
cmd_err_t vbatt_command(uint32 argc, char** argv);
cmd_err_t rxon_command(uint32 argc, char** argv);
cmd_err_t rxoff_command(uint32 argc, char** argv);
cmd_err_t associate_command(uint32 argc, char** argv);
cmd_err_t adhoc_command(uint32 argc, char** argv);
cmd_err_t channel_command(uint32 argc, char** argv);
cmd_err_t rate_command(uint32 argc, char** argv);
cmd_err_t deauth_command(uint32 argc, char** argv);
cmd_err_t sleep_command(uint32 argc, char** argv);
cmd_err_t state_command(uint32 argc, char** argv);
cmd_err_t sniff_command(uint32 argc, char** argv);
cmd_err_t ping_command(uint32 argc, char** argv);
cmd_err_t arp_table_command(uint32 argc, char** argv);
cmd_err_t mtu_command(uint32 argc, char** argv);
cmd_err_t netmsg_command(uint32 argc, char** argv);
cmd_err_t thread_info_command(uint32 argc, char** argv);
cmd_err_t tcp_connect_command(uint32 argc, char** argv);
cmd_err_t tcp_close_command(uint32 argc, char** argv);
cmd_err_t tcp_send_command(uint32 argc, char** argv);
cmd_err_t tcp_recv_command(uint32 argc, char** argv);
cmd_err_t tcp_tx_test_command(uint32 argc, char** argv);
cmd_err_t tcp_port_command(uint32 argc, char** argv);
cmd_err_t tcp_rx_test_command(uint32 argc, char** argv);
cmd_err_t scan_command(uint32 argc, char** argv);
cmd_err_t probe_command(uint32 argc, char** argv);
cmd_err_t http_get_command(uint32 argc, char** argv);
cmd_err_t passwd_command(uint32 argc, char** argv);
cmd_err_t filter_command(uint32 argc, char** argv);
cmd_err_t ant_select_command(uint32 argc, char** argv);


static const command_t commands[] = {
    { "?",            HelpCommand,       0, DELIMIT, NULL, NULL, NULL},
    { "busy",         busy_command,      1, DELIMIT, NULL, "<timeout(ms)>", "Be busy for timeout ms. Interrupts remain enabled."},
    { "dir",          ls_command,        0, DELIMIT, NULL, NULL, NULL},
    { "exit",         exit_command,      0, DELIMIT, NULL, NULL, "Exit."},
    { "help",         HelpCommand,       0, DELIMIT, NULL, "[<command> [<example_num>]]", "Print help message or command example."},
    { "ls",           ls_command,        0, DELIMIT, NULL, NULL, "List all files in flash."},
    { "vbatt",        vbatt_command,     0, DELIMIT, NULL, NULL, "Measure battery voltage"},

    CMD_TABLE_DIV("----- CONNECT COMMANDS -----"),
    { "associate",    associate_command, 0, DELIMIT, NULL, "[<ssid>]", "Associate with an infrastructure BSS."},
    { "adhoc",        adhoc_command,     0, DELIMIT, NULL, "[<ssid>]", "Associate with an adhoc IBSS."},
    { "deauth",       deauth_command,    0, DELIMIT, NULL, NULL, "Disassociate and deauthenticate from an infrastructure BSS."},
    { "fscan",        scan_command,      0, DELIMIT, NULL, "[<count>]", "Scan periodically for infrastructure BSSs to join ignoring duplicates."},
    { "ifdown",       ifdown_command,    0, DELIMIT, NULL, NULL, "Bring the IP interface into the down state."},
    { "ifup",         ifup_command,      0, DELIMIT, NULL, NULL, "Bring the IP interface into the up state."},
    { "qscan",        scan_command,      0, DELIMIT, NULL, "Passively scan for infrastructure BSSs to join."},
    { "rxoff",        rxoff_command,     0, DELIMIT, NULL, NULL, "Disable printing of messages received from the report server."},
    { "rxon",         rxon_command,      0, DELIMIT, NULL, NULL, "Enable printing of messages received from the report server."},
    { "scan",         scan_command,      0, DELIMIT, NULL, "[<ssid>]", "Scan for infrastructure BSSs to join."},
    CMD_TABLE_DIV(""),

    CMD_TABLE_DIV("----- TRANSMIT COMMANDS -----"),
    { "dig",          dig_command,       1, DELIMIT, NULL, "<domain>", "Do a DNS lookup on an address"},
    { "ping",         ping_command,      0, DELIMIT, NULL, "<ping_IP_address>", "Send an ICMP echo request to the specified IP address. Ping the default gateway if no IP_address is specified."},
    { "probe",        probe_command,     0, DELIMIT, NULL, NULL, NULL},
    { "scatter",      scatter_command,   0, DELIMIT, NULL, NULL, "Send a more-or-less constant stream of frames."},
    { "udp_tx_test",    udp_flood_command,   1, DELIMIT, NULL, "<count> [<length>]", "Send a more-or-less constant stream of UDP packets."},
    { "udp_rx_test",       udp_rx_command,    0, DELIMIT, NULL, "<length>", "Kick off a stream of UDP packets from the server by sending one to it."},
    { "send",         send_command,      1, "\"\'",  NULL, "<message>", "Send <message> to the report server."},
    { "sleep",        sleep_command,     0, DELIMIT, NULL, NULL, "Send a power-down (Null Function Data) frame to the AP."},
    { "tx_vbatt",     tx_vbatt_command,  0, DELIMIT, NULL, "[<length>]", "Transmit a frame of specified length and measure battery at end."},
    CMD_TABLE_DIV(""),

    CMD_TABLE_DIV("----- CONFIG COMMANDS -----"),
    { "ant_select",   ant_select_command,1, DELIMIT, NULL, "<antenna>", "Select antenna configuration to use" },
    { "channel",      channel_command,   0, DELIMIT, NULL, "[<chan>]", "Read/Set the 802.11 channel."},
    { "mtu",          mtu_command,       0, DELIMIT, NULL, "<mtu>", "Change the MTU"},
    { "passwd",       passwd_command,    0, DELIMIT, NULL, "<mode> [key] <password>", "Set the WEP40, WEP104 and WPA passwords"},
    { "rate",         rate_command,      0, DELIMIT, NULL, NULL, NULL},
    CMD_TABLE_DIV(""),

    CMD_TABLE_DIV("----- STATUS COMMANDS -----"),
    { "netmsg",       netmsg_command,     0, DELIMIT, NULL, NULL, "Check that the network thread is running"},
    { "sharp",        arp_table_command,  0, DELIMIT, NULL, NULL, "Show the contents of the ARP table."},
    { "state",        state_command,      0, DELIMIT, NULL, NULL, "Print out current channel, SSID and association state."},
    { "thread",       thread_info_command,0, DELIMIT, NULL, NULL, "Display thread info"},
    CMD_TABLE_DIV(""),

    CMD_TABLE_DIV("----- TCP COMMANDS -----"),
    { "http_get",     http_get_command,   1, DELIMIT, NULL, "<URL>", "Retrieve a http page"},
    { "tcp_close",    tcp_close_command,  0, DELIMIT, NULL, NULL, "Close a connection to a TCP server"},
    { "tcp_conn",     tcp_connect_command,0, DELIMIT, NULL, NULL, "Create a connection to a TCP server"},
    { "tcp_port",     tcp_port_command,   0, DELIMIT, NULL, "<port>", "Change the TCP port"},
    { "tcp_recv",     tcp_recv_command,   0, DELIMIT, NULL, NULL, "Receive a packet from a TCP server"},
    { "tcp_rx_test",  tcp_rx_test_command,0, DELIMIT, NULL, NULL, "Start a TCP receive throughput test"},
    { "tcp_send",     tcp_send_command,   0, DELIMIT, NULL, NULL, "Send a packet to a TCP server"},
    { "tcp_tx_test",  tcp_tx_test_command,1, DELIMIT, NULL, "<count> [<length>]", "Start a TCP transmit throughput test"},
    CMD_TABLE_DIV(""),

    CMD_TABLE_DIV("----- SNIFF COMMANDS -----"),
    { "filter",       filter_command,    0, " :",    NULL, "<type> <value>", "Configure the filter for the sniff command"},
    { "sniff",        sniff_command,     0, DELIMIT, NULL, NULL, "Start sniffing packets"},

// aliases
    { "abort",        deauth_command,    0, DELIMIT, NULL, NULL, NULL},
    { "assoc",        associate_command, 0, DELIMIT, NULL, NULL, NULL},
    { "stop_adhoc",   deauth_command,    0, DELIMIT, NULL, NULL, NULL},
    { "chan",         channel_command,   0, DELIMIT, NULL, NULL, NULL},
    { "deauthenticate", deauth_command,  0, DELIMIT, NULL, NULL, NULL},
    { "disassoc",     deauth_command,    0, DELIMIT, NULL, NULL, NULL},
    { "status",       state_command,     0, DELIMIT, NULL, NULL, NULL},
    CMD_TABLE_END
};


/*!
******************************************************************************
Check for Association status, Deauthenticate if we have and power down.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t exit_command(uint32 argc, char** argv)
{

    if (MAC_GetAssociated())
    {
        UartPrintf(CONSOLE_PRINT, "Disassociating/Deauthenticating from %s on channel %d...\n\n", bss_ssid, current_channel);
        MAC_SendDeauthentication(*MAC_GetBSSID(), 0x0001);
    }

    UartPrintf(CONSOLE_PRINT, "\nexiting...\n");
    UartFlush();
    SuccessfulPowerDown();

    return ERR_CMD_OK;
}


/*!
******************************************************************************
List the files in the flash file system.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t ls_command(uint32 argc, char** argv)
{
    char filename[MAX_FILENAME_LENGTH + 1];

    uint32 file_count = 0;
    for (int i = 0; (i < MAX_FLASH_FILES); i++)
    {
        uint32 sector_address = i * FLASH_SECTOR_SIZE;
        byte file_id = FlashReadByte(sector_address + SECTOR_HEADER_FILE_ID_OFFSET);
        if ((file_id == i) && (file_id != (INVALID_FILE_HANDLE & 0xff)))
        {
            file_count++;
        }
    }
    UartPrintf(CONSOLE_PRINT, "\nFlash File System contains %d files:\n", file_count);

    for (int i = 0; (i < MAX_FLASH_FILES); i++)
    {
        int32 len = FileGetName(i, filename);
        if (len > 0)
        {
            uint32  sector_count = 0;
            for (uint32 sector_index = 0; (sector_index < FLASH_TOTAL_SECTORS); sector_index++)
            {
                uint32 sector_address = sector_index * FLASH_SECTOR_SIZE;
                byte file_id = FlashReadByte(sector_address + SECTOR_HEADER_FILE_ID_OFFSET);
                if (file_id == i)
                {
                    sector_count++;
                }
            }
            UartPrintf(CONSOLE_PRINT, "%-2d %32s    %d sector%c\n", i, filename, sector_count, (sector_count == 1) ? ' ' : 's');
        }
    }

    UartPrintf(CONSOLE_PRINT, "\n");

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Be busy for a few milliseconds.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t busy_command(uint32 argc, char** argv)
{
    uint32 business_time = argtoi(argv[1]);
    WatchdogHoldOff(0, business_time PMU_DOZE_MILLISECONDS);
    PMU_BusyWait(business_time PMU_DOZE_MILLISECONDS);

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Send a string to the report server.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t send_command(uint32 argc, char** argv)
{
    diag_sprintf(report_string, "%s", argv[1]);
    if (netif_is_up(&wifi_if) && MAC_GetAssociated()) // only send report if the application is associated
    {
        SendReport();
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "Failed to send - not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "Failed to send - DHCP not completed.\n\n");
        }
    }

    return ERR_CMD_OK;
}


#define PACKET_LENGTH_FIXED_TOTAL 500
#define BOGUS_PROBE_SSID "g2-scatter"

uint32 scatter_length = PACKET_LENGTH_FIXED_TOTAL;
uint32 scatter_delay = 0;


/*!
******************************************************************************
Send a more-or-less constant stream of frames.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t scatter_command(uint32 argc, char** argv)
{
    if (!MAC_GetAuthenticated())
    {
        uint32 max_tx = 0xffffffff;
        scatter_length = PACKET_LENGTH_FIXED_TOTAL;

        if (argc > 1)
        {
            max_tx = argtoi(argv[1]);
        }

        if (argc > 2)
        {
            scatter_length = argtoi(argv[2]);
        }

        if (argc > 3)
        {
            scatter_delay = argtoi(argv[3]);
        }

        WatchdogHoldOff(7, 7);

        void *saved_mac_output = PatchTableGetPatchPointer(MAC_Output_PATCH_INDEX);
        PatchTableInsertPatch(MAC_Output_PATCH_INDEX, Patched_MAC_OutputScatter);

        uint32 save_assoc_rate_flag = NVM_ConfigRead(nvm_g2lib_mac_associate_at_lower_rate);
        NVM_ConfigWrite(nvm_g2lib_mac_associate_at_lower_rate, 0);
        bool save_tx_force = MAC_GetTxForce();

        MAC_SetTxForce(FALSE);
        UartPrintf(CONSOLE_PRINT, "Scatter %u times with length %d\n", max_tx, scatter_length);

        UartPrintf(CONSOLE_PRINT, "NAV Update enable: %d, Max NAV value: %d, NAV value: %d, NAV Backoff value: %d, CCA Ignore: %d, CCA Use Active: %d\n", MAC_HW_GetNVMUpdateEnable(), MAC_HW_GetNAVMax(), MAC_HW_GetNAVvalue(), MAC_HW_GetNAVvalue(), MAC_HW_GetNAVBackoff(), MAC_HW_GetCCAIgnore(), MAC_HW_GetCCAUseActive());

        for (uint32 i = 0; i < max_tx; i++)
        {
            MAC_SendProbeRequest(BOGUS_PROBE_SSID, (byte*)broadcast_id, (uint16)NVM_ConfigRead(nvm_g2lib_mac_supported_rates));
            PMU_BusyWait(scatter_delay PMU_DOZE_MILLISECONDS);
            UartPrintf(CONSOLE_PRINT, ".");
            if (((i+1) % 80) == 0)
            {
                UartPrintf(CONSOLE_PRINT, "\n");
            }
        }
        UartPrintf(CONSOLE_PRINT, "Done.\n");
        MAC_SetTxForce(save_tx_force);
        NVM_ConfigWrite(nvm_g2lib_mac_associate_at_lower_rate, save_assoc_rate_flag);

        PatchTableInsertPatch(MAC_Output_PATCH_INDEX, saved_mac_output);
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: Cannot scatter while authenticated\n");
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Send a more-or-less constant stream of UDP packets.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t udp_flood_command(uint32 argc, char** argv)
{
    uint32 flood_length = 1000;
    uint32 flood_delay = 0;


    if (netif_is_up(&wifi_if) && MAC_GetAssociated()) // only send report if the application is associated
    {
        uint32 max_tx = 0xffffffff;

        if (argc > 1)
        {
            max_tx = argtoi(argv[1]);
        }

        if (argc > 2)
        {
            flood_length = argtoi(argv[2]);
        }

        if (argc > 3)
        {
            flood_delay = argtoi(argv[3]);
        }

        UartPrintf(CONSOLE_PRINT, "Send %u times with length %d\n", max_tx, flood_length);

        WatchdogHoldOff(7, 7);

        char flood_payload[flood_length + 64];
        for (uint32 i = 0; i < flood_length; i++)
        {
            flood_payload[i] = ' ' + (i & 0x5f);
            if (flood_payload[i] == 0x7f)
            {
                flood_payload[i] = '-';
            }
        }

        struct pbuf* pbufptr;
        struct udp_pcb* local_udp_pcb_ptr = &local_udp_pcb;

        /*
         * Reference, rather than copy, the report data (including the string
         * delimiter) to the pbuf structure.  This saves on memory as only a
         * small pbuf structure to contain the header information is required.
         * and the report data already formatted in the application is used as
         * the payload.
         */
        pbufptr = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_REF);

        for (uint32 i = 0; i < max_tx; i++)
        {

            pbufptr->payload = flood_payload;
            pbufptr->len = pbufptr->tot_len = flood_length;

            pbufptr->buf_startptr = pbufptr->payload;
            pbufptr->buf_endptr = flood_payload + flood_length + 64;

            tx_meta_data_t* metadataptr = pbuf_setmetadataptr(pbufptr, sizeof(tx_meta_data_t));

            memset(metadataptr, 0, sizeof(tx_meta_data_t) - sizeof(uint32*));  // zero all the metadata except the pointer at the end

            udp_send(local_udp_pcb_ptr, pbufptr);
            if (flood_delay != 0)
            {
                PMU_BusyWait(flood_delay PMU_DOZE_MILLISECONDS);
            }

        }

        /*
         * Free the buffer.  There is limited buffer space so it is
         * good practice to cleanup immediately.
         */
        pbuf_free(pbufptr);
        UartPrintf(CONSOLE_PRINT, "Done.\n");
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "Failed to send - not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "Failed to send - DHCP not completed.\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Send a more-or-less constant stream of frames.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t udp_rx_command(uint32 argc, char** argv)
{
    uint32 flood_length = 1000;

    if (netif_is_up(&wifi_if) && MAC_GetAssociated() && (udp_last_rx_time == 0)) // only trigger the test if the application is associated and we're not already running the test
    {
        if (argc > 1)
        {
            flood_length = argtoi(argv[1]);
        }

        UartPrintf(CONSOLE_PRINT, "Trigger Rx UDP test with length %d\n", flood_length);

        char flood_payload[flood_length + 64];
//        char* flood_payload = (char*)mem_malloc(flood_length + 64);
        for (uint32 i = 0; i < flood_length; i++)
        {
            flood_payload[i] = ' ' + (i & 0x5f);
            if (flood_payload[i] == 0x7f)
            {
                flood_payload[i] = '-';
            }
        }

        struct pbuf* pbufptr;
        struct udp_pcb* local_udp_pcb_ptr = &local_udp_pcb;

        /*
         * Reference, rather than copy, the report data (including the string
         * delimiter) to the pbuf structure.  This saves on memory as only a
         * small pbuf structure to contain the header information is required.
         * and the report data already formatted in the application is used as
         * the payload.
         */
        pbufptr = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_REF);

        pbufptr->payload = flood_payload;
        pbufptr->len = pbufptr->tot_len = flood_length;

        pbufptr->buf_startptr = pbufptr->payload;
        pbufptr->buf_endptr = flood_payload + flood_length + 64;

        tx_meta_data_t* metadataptr = pbuf_setmetadataptr(pbufptr, sizeof(tx_meta_data_t));

        memset(metadataptr, 0, sizeof(tx_meta_data_t) - sizeof(uint32*));  // zero all the metadata except the pointer at the end

        udp_send(local_udp_pcb_ptr, pbufptr);

        pbuf_free(pbufptr);
        udp_last_rx_time = GetUpTime();  // indicate we're running the test
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "Failed to trigger rx test - not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            if (!netif_is_up(&wifi_if))
            {
                UartPrintf(CONSOLE_PRINT, "Failed to send - DHCP not completed.\n\n");
            }
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Send a frame of the specified size and check the battery after the tx.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t tx_vbatt_command(uint32 argc, char** argv)
{
    scatter_length = PACKET_LENGTH_FIXED_TOTAL;

    if (argc > 1)
    {
        scatter_length = argtoi(argv[1]);
    }

    void *saved_mac_output = PatchTableGetPatchPointer(MAC_Output_PATCH_INDEX);
    PatchTableInsertPatch(MAC_Output_PATCH_INDEX, Patched_MAC_OutputScatter);

    int32 vbatt_pre_wifi = SmuMeasureBatteryFixed() / 1000;
    // Make sure the battery measurement logic is set up for wifi mode etc:
    SmuSetWifiMode(WIFI_MODE_ON);

    MAC_SendProbeRequest(BOGUS_PROBE_SSID, (byte*)broadcast_id, (uint16)NVM_ConfigRead(nvm_g2lib_mac_supported_rates));

    int32 vbatt_first = SmuGetWifiFirstFixedResult() /1000;
    int32 vbatt_max = SmuGetWifiMaxFixedResult() /1000;
    int32 vbatt_min = SmuGetWifiMinFixedResult() /1000;
    int32 vbatt_last = SmuGetWifiLastFixedResult() /1000;

    UartPrintf(CONSOLE_PRINT, "  vdd_batt drooped %dmV during transmit of %d bytes.\n", vbatt_pre_wifi - vbatt_min, scatter_length);
    UartPrintf(CONSOLE_PRINT, "           before calling tx:    vdd_batt = %4dmV\n", vbatt_pre_wifi);
    UartPrintf(CONSOLE_PRINT, "           at start of transmit: vdd_batt = %4dmV\n", vbatt_first);
    UartPrintf(CONSOLE_PRINT, "           at end of transmit:   vdd_batt = %4dmV\n", vbatt_last);
    UartPrintf(CONSOLE_PRINT, "           maximum seen:         vdd_batt = %4dmV\n", vbatt_max);
    UartPrintf(CONSOLE_PRINT, "           minimum seen:         vdd_batt = %4dmV\n", vbatt_min);

    PatchTableInsertPatch(MAC_Output_PATCH_INDEX, saved_mac_output);

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Measure the battery voltage.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t vbatt_command(uint32 argc, char** argv)
{
    if (argc > 1)
    {
      // SMU resolution vs conversion time: corresponds to ~ (n+1)*12us conversion time
      SmuSetClockDivisor(argtoi(argv[1]));
    }

    UartPrintf(CONSOLE_PRINT, "  vdd_batt =%2.3fV\n\n",SmuMeasureBattery());
    return ERR_CMD_OK;
}


/*!
******************************************************************************
If applicable, select the antenna to be used. This selection does not affect
the default, which is set by boardconf. This feature is useful, for example,
if an RF test connector that may be needed for conducted measurements is
located in the antenna branch that is not to be used by default in a user
application.

\par Usage
  cal> antenna_select [ANTENNA]

  ANTENNA - antenna number as defined by the board configuration

\par Requirements
  That antenna_select_setup has been run.

\param[in] argc Number of arguments
\param[in] argv Pointer to array of arguments
\return cmd_err_t
*/

cmd_err_t ant_select_command(uint32 argc, char** argv)
{
    uint32 antenna = argtoi(argv[1]);
    if (antenna < BOARDCONF_ANTENNA_COUNT)
    {
        MAC_HW_SelectAntenna(antenna);
        UartPrintf(CONSOLE_PRINT, "OK: Selected Antenna %d\n", antenna);
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: Antenna value must be between 0 and %d inclusive\n", BOARDCONF_ANTENNA_COUNT-1);
    }

    return ERR_CMD_OK;
}



/*!
******************************************************************************
Enable printing of received frames.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t rxon_command(uint32 argc, char** argv)
{
    UartPrintf(CONSOLE_PRINT, "Receive packet prints enabled\n\n");
    rx_print = TRUE;

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Disable printing of received frames.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t rxoff_command(uint32 argc, char** argv)
{
    UartPrintf(CONSOLE_PRINT, "Receive packet prints disabled\n\n");
    rx_print = FALSE;

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Put the IP interface in the down state.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t ifdown_command(uint32 argc, char** argv)
{
    dhcp_stop(&wifi_if);

    wifi_if.ip_addr.addr = 0;
    wifi_if.gw.addr = 0;
    wifi_if.netmask.addr = 0;

    // Disable the network interface so DHCP will restart correctly.
    netif_set_down(&wifi_if);

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Put the IP interface in the up state.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t ifup_command(uint32 argc, char** argv)
{

    dhcp_stop(&wifi_if);

    // Disable the network interface so DHCP will restart correctly.
    netif_set_down(&wifi_if);

    RealTimeClockGetMilliseconds(&dhcp_start_time);
    // Receive the next DHCP complete event.
    dhcp_start(&wifi_if);
    return ERR_CMD_OK;
}


static void HandleReportServerResponse(sys_event_t* eventptr)
{

    // The connection pointer is passed as the event subtype
    struct netconn* connptr = (struct netconn*)eventptr->subtype;
    struct netbuf* bufptr = netconn_recv(connptr);

    if (bufptr != NULL)
    {
        UartPrintf(REPORTING_LEVEL_INFO, "inpkt %p\n", bufptr);
        netbuf_delete(bufptr);
    }
    else
    {
        UartPrintf(REPORTING_LEVEL_WARNING, "UDP Rx Handler got NULL buffer\n");
        return;
    }
}


/*!
******************************************************************************
Connect to the server IP address and port configured in NVM.

On the server side, use the tcpecho.py script found within the apps/scripts
directory. The script should be run with its port set to the same value
as configured in "server_port" in this application.
*/

cmd_err_t tcp_connect_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {

        static struct ip_addr server_addr;
        err_t err = ERR_VAL;

        UartPrintf(REPORTING_LEVEL_INFO, "\nAttempting TCP connection ...");

        if (conn)
        {
            netconn_delete(conn);
            conn = NULL;
        }

        // Get the server IP address and port from NVM.
        server_addr.addr = NVM_ConfigRead(nvm_app_server_ip_address);

        conn = netconn_new_with_proto_and_callback(NETCONN_TCP, 0, NULL);
        err = netconn_connect(conn, &server_addr, tcp_port);

        if (err == ERR_OK)
        {
            UartPrintf(REPORTING_LEVEL_INFO, "Connected.\n");

        }
        else
        {
            UartPrintf(REPORTING_LEVEL_INFO, "ERROR: netconn_connect (%d %s)\n\n", err, lwip_strerr(err));
            netconn_delete(conn);
        }
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Disconnect the connection with the server IP address and port configured in NVM.

On the server side, use the tcpecho.py script found within the apps/scripts
directory. The script should be run with its port set to the same value
as configured in "server_port" in this application.

*/

cmd_err_t tcp_close_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {

        err_t err = ERR_VAL;

        UartPrintf(REPORTING_LEVEL_INFO, "\nAttempting TCP connection ...");

        if (conn)
        {
            err = netconn_delete(conn);
            if (err == ERR_OK)
            {
                conn = NULL;
            }
        }

        if (err == ERR_OK)
        {
            UartPrintf(REPORTING_LEVEL_INFO, "Closed connection.\n");
        }
        else
        {
            UartPrintf(REPORTING_LEVEL_INFO, "ERROR: netconn_delete (%d %s)\n\n", err, lwip_strerr(err));
            netconn_delete(conn);
        }
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Send a packet to the server IP address and port configured in NVM.

On the server side, use the tcpecho.py script found within the apps/scripts
directory. The script should be run with its port set to the same value
as configured in "server_port" in this application.
*/

cmd_err_t tcp_send_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {

        err_t err = ERR_VAL;

        UartPrintf(REPORTING_LEVEL_INFO, "\nAttempting to send ...");
#define TCP_PACKET_LENGTH 500
        if (conn)
        {
            byte transmit_buffer[TCP_PACKET_LENGTH];
            memset(transmit_buffer, '*', TCP_PACKET_LENGTH);
            UartPrintf(REPORTING_LEVEL_INFO, " (%d Rx bytes queued) ", conn->recv_avail);
            err = netconn_write(conn, transmit_buffer, TCP_PACKET_LENGTH, NETCONN_COPY);
        }

        if (err == ERR_OK)
        {
            UartPrintf(REPORTING_LEVEL_INFO, "Sent %d bytes OK.\n", TCP_PACKET_LENGTH);

        }
        else
        {
            UartPrintf(REPORTING_LEVEL_INFO, "ERROR: netconn_write (%d %s)\n\n", err, lwip_strerr(err));
        }
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Receive a packet from the server IP address and port configured in NVM.

On the server side, use the tcpecho.py script found within the apps/scripts
directory. The script should be run with its port set to the same value
as configured in "server_port" in this application.
*/

cmd_err_t tcp_recv_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {
        err_t err = ERR_VAL;
        uint16 len = 0;
        UartPrintf(REPORTING_LEVEL_INFO, "\nAttempting to receive ...");

        if (conn)
        {
            if (conn->recv_avail != 0)
            {
                UartPrintf(REPORTING_LEVEL_INFO, "%d bytes available to receive\n", conn->recv_avail);
                struct netbuf* bufptr = NULL;

                bufptr = netconn_recv(conn);
                if (bufptr != NULL)
                {
                    err = ERR_OK;
                    len = netbuf_len(bufptr);
                    netbuf_delete(bufptr);
                }
            }
            else
            {
                err = ERR_OK;
                UartPrintf(REPORTING_LEVEL_INFO, "No data available to receive\n");
            }
        }

        if (err == ERR_OK)
        {
            UartPrintf(REPORTING_LEVEL_INFO, "Received OK len=%d.\n", len);
        }
        else
        {
            UartPrintf(REPORTING_LEVEL_INFO, "ERROR: netconn_recv (%d %s)\n", err, lwip_strerr(err));
        }
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Start a transmit test.  Will connect to the server and port configured in the
NVM and perform a throughput test.  Has two optional command line parameters
to specify the number of netconn_writes to perform and the size of each
netconn_write.  Once the test has completed it will close the connection
and cleanup any used data structures.

On the server side, use the tcptp.py script found within the apps/scripts
directory.  The script should be run in receive mode (default) listening on
the port configured in application.

*/

cmd_err_t tcp_tx_test_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {

        static struct ip_addr server_addr;
        err_t err = ERR_VAL;
        tcp_send_length = 1000;

        if (argc > 1)
        {
            tcp_send_count = argtoi(argv[1]);
        }

        if (argc > 2)
        {
            tcp_send_length = argtoi(argv[2]);
        }


        memset(tcp_test_data, 0x2b, TCP_TEST_MAX_DATA_LENGTH);

        UartPrintf(REPORTING_LEVEL_INFO, "\nAttempting TCP connection ...");

        if (conn)
        {
            netconn_delete(conn);
            conn = NULL;
        }

        // Get the server IP address and port from NVM.
        server_addr.addr = NVM_ConfigRead(nvm_app_server_ip_address);

        conn = netconn_new_with_proto_and_callback(NETCONN_TCP, 0, NULL);
        err = netconn_connect(conn, &server_addr, tcp_port);

        if (err == ERR_OK)
        {
            UartPrintf(REPORTING_LEVEL_INFO, "Connected.\n");

            uint64 tcp_start_time = 0;
            uint64 tcp_end_time = 0;
            uint32 bytes_sent = 0;

            RealTimeClockGetMilliseconds(&tcp_start_time);
            for (int i = 0; (i < tcp_send_count) && (err == ERR_OK); i++)
            {
                err = netconn_write(conn, tcp_test_data, tcp_send_length, 0);
                bytes_sent += tcp_send_length;
                if (err != ERR_OK)
                {
                    UartPrintf(REPORTING_LEVEL_INFO, "ERROR: netconn_write (%d %s)\n", err, lwip_strerr(err));
                }
            }
            RealTimeClockGetMilliseconds(&tcp_end_time);

            netconn_close(conn);
            netconn_delete(conn);
            conn = NULL;

            uint64 send_time = tcp_end_time - tcp_start_time;
            float speed = (float)(bytes_sent / send_time) * 8000.0 / 1024.0 / 1024.0;
            UartPrintf(REPORTING_LEVEL_INFO, "%d bytes in %lld milliseconds (%.2fMbit/s)\n", bytes_sent, send_time, speed);
        }
        else
        {
            UartPrintf(REPORTING_LEVEL_INFO, "ERROR: netconn_connect (%d %s)\n", err, lwip_strerr(err));
            netconn_delete(conn);
        }
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Run a TCP receive test.  Will wait forever listening on the configured port
for a connection to occur.  Receives data until the connection is closed then
reports on the throughput.

Use in conjunction with the tcptp.py script found in the apps/script directory.
This script should be configured in transmit mode to connect to the IP and port
of the device.

*/

cmd_err_t tcp_rx_test_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {
        err_t err;
        struct netconn* new_connptr;
        struct netbuf* inbuf;

        if (rx_conn)
        {
            netconn_delete(rx_conn);
            rx_conn = NULL;
        }

        rx_conn = netconn_new_with_proto_and_callback(NETCONN_TCP, 0, NULL);
        err = netconn_bind(rx_conn, IP_ADDR_ANY, tcp_port);

        netconn_listen(rx_conn);

        UartPrintf(REPORTING_LEVEL_INFO, "Waiting for Connection on port %d...\n", tcp_port);

        new_connptr = netconn_accept(rx_conn);

        struct ip_addr addr;
        uint16 from_port;
        netconn_getaddr(new_connptr, &addr, &from_port, 0); // get the IP address and port whence the packet originated.
        UartPrintf(REPORTING_LEVEL_INFO, "%lld TCP connection from %u.%u.%u.%u:%d\n",
                   GetUpTime(),
                   ip4_addr1(&addr),
                   ip4_addr2(&addr),
                   ip4_addr3(&addr),
                   ip4_addr4(&addr),
                   from_port);

        void* data;
        uint16 data_len;
        uint32 bytes_recv = 0;
        uint64 tcp_start_time = 0;
        uint64 tcp_end_time = 0;

        RealTimeClockGetMilliseconds(&tcp_start_time);
        inbuf = netconn_recv(new_connptr);
        while (inbuf != NULL)
        {
            do
            {
                netbuf_data(inbuf, &data, &data_len);
                bytes_recv += data_len;
            } while(netbuf_next(inbuf) >= 0);

            netbuf_delete(inbuf);
            inbuf = netconn_recv(new_connptr);
        }
        RealTimeClockGetMilliseconds(&tcp_end_time);

        uint64 recv_time = tcp_end_time - tcp_start_time;
        float speed = (float)(bytes_recv / recv_time) * 8000.0 / 1024.0 / 1024.0;
        UartPrintf(REPORTING_LEVEL_INFO, "%d bytes received in %lld ms (%f Mbit/s)\n", bytes_recv, recv_time, speed);

        netconn_close(new_connptr);
        netconn_delete(new_connptr);
        netconn_delete(rx_conn);
        rx_conn = NULL;
    }
    else
    {
        if (!MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Not associated (SSID: %s channel %d)\n\n", bss_ssid, current_channel);
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Change the port used by the TCP commands.  If no port is provided, it will
return the currently configured one.

*/

cmd_err_t tcp_port_command(uint32 argc, char** argv)
{
    if (argc > 1)
    {
        tcp_port = atoi(argv[1]);
    }
    UartPrintf(CONSOLE_PRINT, "TCP port is set to %d\n", tcp_port);
    return ERR_CMD_OK;
}


/*!
******************************************************************************


*/

cmd_err_t passwd_command(uint32 argc, char** argv)
{
    wep_key_t wep_keys[WEP_MAX_DEFAULT_KEYS] = {{0}};

    uint32 wep_key_len = 0;

    if (argc > 1)
    {
        if (strcmp(argv[1], "wpa") == 0)
        {
            if (argc > 2)
            {
                strcpy(wpa_password, argv[2]);
            }
            else
            {
                UartPrintf(CONSOLE_PRINT, "ERROR: Must supply a password\n");
            }
        }
        else if (strcmp(argv[1], "wep104") == 0)
        {
            wep_key_len = WEP_104_KEY_LEN;
            NVM_ConfigWrite(nvm_app_wep_mode, WEP_USE_104_BIT_KEY);
        }
        else if (strcmp(argv[1], "wep40") == 0)
        {
            wep_key_len = WEP_40_KEY_LEN;
            NVM_ConfigWrite(nvm_app_wep_mode, WEP_USE_40_BIT_KEY);
        }
        else if (strcmp(argv[1], "key") == 0)
        {
            if (argc > 2)
            {
                int32 active_key = argtoi(argv[2]);
                if (active_key > 0 && active_key < 5)
                {
                    active_key--;
                    NVM_ConfigWrite(nvm_app_wep_active_key, active_key);
                }
            }
            else
            {
                UartPrintf(CONSOLE_PRINT, "ERROR: Must supply active key number\n");
            }
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Key mode must be either wpa, wep104, wep40, key\n");
        }

        if (wep_key_len)
        {
            if (argc > (2 + wep_key_len))
            {
                int32 key = argtoi(argv[2]);

                if (key > 0 && key < 5)
                {
                    key--;

                    for (int i = 0; i < wep_key_len; i++)
                    {
                        wep_keys[key][i] = argtoi(argv[i+3]);
                    }
                    switch (key)
                    {
                    case 0:
                        NVM_ConfigWriteBytes(nvm_app_wep_default_key1, (byte*)wep_keys[key]);
                        break;
                    case 1:
                        NVM_ConfigWriteBytes(nvm_app_wep_default_key2, (byte*)wep_keys[key]);
                        break;
                    case 2:
                        NVM_ConfigWriteBytes(nvm_app_wep_default_key3, (byte*)wep_keys[key]);
                        break;
                    case 3:
                        NVM_ConfigWriteBytes(nvm_app_wep_default_key4, (byte*)wep_keys[key]);
                        break;
                    }
                }
                else
                {
                    UartPrintf(CONSOLE_PRINT, "ERROR: Must supply key between 1-4\n");
                }
            }
            else
            {
                UartPrintf(CONSOLE_PRINT, "ERROR: Insufficent key elements\n");
            }
            wep_key_len = 0;
        }
    }

    NVM_ConfigReadBytes(nvm_app_wep_default_key1, (byte*)wep_keys[0]);
    NVM_ConfigReadBytes(nvm_app_wep_default_key2, (byte*)wep_keys[1]);
    NVM_ConfigReadBytes(nvm_app_wep_default_key3, (byte*)wep_keys[2]);
    NVM_ConfigReadBytes(nvm_app_wep_default_key4, (byte*)wep_keys[3]);

    UartPrintf(CONSOLE_PRINT, "Configured Passwords\n\n");
    UartPrintf(CONSOLE_PRINT, "WPAv1 & WPAv2:\n  Key1: %s\n\n", wpa_password);
    switch(NVM_ConfigRead(nvm_app_wep_mode))
    {
    case WEP_USE_104_BIT_KEY:
        UartPrintf(CONSOLE_PRINT, "WEP104:\n");
        wep_key_len = WEP_104_KEY_LEN;
        break;

    case WEP_USE_40_BIT_KEY:
        UartPrintf(CONSOLE_PRINT, "WEP40:\n");
        wep_key_len = WEP_40_KEY_LEN;
        break;
    }

    for (int i = 0; i < WEP_MAX_DEFAULT_KEYS; i++)
    {
        UartPrintf(CONSOLE_PRINT, "  Key%d: ",i+1);
        for (int j = 0; j < wep_key_len; j++)
        {
            UartPrintf(CONSOLE_PRINT, "0x%02x ", wep_keys[i][j]);
        }

        if (NVM_ConfigRead(nvm_app_wep_active_key) == i)
        {
            UartPrintf(CONSOLE_PRINT, "(active)");
        }
        UartPrintf(CONSOLE_PRINT, "\n");
    }
    return ERR_CMD_OK;
}


#define HTTP_PREFIX "http://"
#define GET_MESSAGE "GET /%s HTTP/1.1\nHost:%s\nConnection: close\n\n"
#define HTTP_BUFFER_SIZE  1500
char http_buffer[HTTP_BUFFER_SIZE] = {0};


/*!
******************************************************************************
Example of how to retrieve some data from an HTTP server.

*/

static void http_get(char *hostname, char *page, struct ip_addr *server_addr)
{
    void* data;
    uint16 data_len;
    struct netconn* http_conn = NULL;
    struct netbuf* inbuf = NULL;
    uint32 rx_total = 0;

    // Format the HTTP GET message
    uint32 http_len = diag_sprintf(http_buffer, GET_MESSAGE, page, hostname);

    // Initialise a new TCP connection
    http_conn = netconn_new_with_proto_and_callback(NETCONN_TCP, 0, NULL);

    // Connect to the server on port 80
    err_t err = netconn_connect(http_conn, server_addr, 80);
    if (err == ERR_OK)
    {
        // Send the HTTP GET message to the server
        err = netconn_write(http_conn, http_buffer, http_len, 0);
        if (err == ERR_OK)
        {
            // Wait for the server response
            inbuf = netconn_recv(http_conn);

            while (inbuf != NULL)
            {
                do
                {
                    // Receive data on the connection
                    netbuf_data(inbuf, &data, &data_len);

                    if (data_len < HTTP_BUFFER_SIZE)
                    {
                        memcpy(http_buffer, data, data_len);
                        http_buffer[data_len] = '\0';
                        UartPrintf(REPORTING_LEVEL_INFO, "%s\n", http_buffer);
                    }
                    else
                    {
                        UartPrintf(REPORTING_LEVEL_WARNING, "WARNING: Insufficent buffer size to format output (%d available, %d required)\n", HTTP_BUFFER_SIZE, data_len);
                    }

                    rx_total += data_len;

                } while(netbuf_next(inbuf) >= 0);

                netbuf_delete(inbuf);
                inbuf = netconn_recv(http_conn);
            }
        }
        else
        {
            UartPrintf(REPORTING_LEVEL_ERROR, "ERROR: netconn_write (%d %s)\n", err, lwip_strerr(err));
        }
        UartPrintf(REPORTING_LEVEL_INFO, "\nReceived %d bytes of data\n\n", rx_total);

        // Cleanup the connection
        netconn_close(http_conn);
        netconn_delete(http_conn);
        conn = NULL;
    }
    else
    {
        UartPrintf(REPORTING_LEVEL_ERROR, "ERROR: netconn_connect (%d %s)\n", err, lwip_strerr(err));
        netconn_delete(http_conn);
    }
}


/*!
******************************************************************************
HTTP Get command.  Retrieves a webpage's source and displays it.

*/

cmd_err_t http_get_command(uint32 argc, char** argv)
{
    char data[256] = {0};
    strcpy(data, argv[1]);

    char *domain = data;
    uint16 domain_len = strlen(domain);
    char *page = "index.html";
    char *user_page = NULL;
    int16 i = 0;
    int16 http_prefix_len = strlen(HTTP_PREFIX);
    struct ip_addr addr;

    // Strip off any http:// from the domain
    if (strncmp(data, HTTP_PREFIX, http_prefix_len) == 0)
    {
        domain = data + http_prefix_len;
        memset(data, 0, http_prefix_len);
    }

    // Find the page to download from the domain
    while ((user_page == NULL) && (i < (domain_len + 1)))
    {
        if (data[i] == '/')
        {
            user_page = &data[i+1];
            data[i] = 0;
        }
        i++;
    }

    // Set the page if one was found, otherwise use the default
    if (user_page != NULL)
    {
        page = user_page;
    }

    UartPrintf(CONSOLE_PRINT, "\nGet - http://%s/%s\n\n", domain, page);

    // Lookup the IP address of the domain
    err_t err = netconn_gethostbyname(domain, &addr);
    if (err == ERR_OK)
    {
        // Use HTTP get retrieve and display the data
        http_get(domain, page, &addr);
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: %s (%d)\n", lwip_strerr(err), err);
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
DNS lookup command.  Resolves a domain name provided as a parameter to an IP
address.  Uses the DNS server either configured in NVM or obtained from DHCP.

*/

cmd_err_t dig_command(uint32 argc, char** argv)
{
    if (NetworkThreadEnabled())
    {
        char domain[256];
        strcpy(domain, argv[1]);
        struct ip_addr addr;
        err_t err = netconn_gethostbyname(domain, &addr);
        if (err == ERR_OK)
        {
            UartPrintf(CONSOLE_PRINT, "%s = %u.%u.%u.%u\n",
                       domain,
                       ip4_addr1(&addr),
                       ip4_addr2(&addr),
                       ip4_addr3(&addr),
                       ip4_addr4(&addr)
                       );
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: %s (%d)\n", lwip_strerr(err), err);
        }
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: DNS requires the network thread\n");
    }
    return ERR_CMD_OK;
}


/*!
******************************************************************************
Set the Wifi interface MTU.  If no parameter is provided, returns the
currently configured MTU.

*/

cmd_err_t mtu_command(uint32 argc, char** argv)
{
    if (argc > 1)
    {
        uint32 mtu = atoi(argv[1]);
        LWIP_SetMTU(mtu);
    }
    UartPrintf(CONSOLE_PRINT, "MTU is set to %d\n", LWIP_GetMTU());
    return ERR_CMD_OK;
}


/*!
******************************************************************************
Simple function to be run from the Network Thread context.

*/

void netmsg_callback(void* ctx)
{
    UartPrintf(CONSOLE_PRINT, "\rHi from the network thread\n\n%s", ConsolePromptString);
}


/*!
******************************************************************************
Example of using the callback functionality within the Network Thread.
Executes a simple function from the Network Thread context.  Useful for debug
to ensure the Network Thread is still processing events and callback changes have
not caused deadlock.

*/

cmd_err_t netmsg_command(uint32 argc, char** argv)
{
    err_t err = tcpip_callback_with_block(netmsg_callback, NULL, 1);
    if (err != ERR_OK)
    {
        UartPrintf(CONSOLE_PRINT, "ERROR in netmsg : %d\n", err);
    }
    return ERR_CMD_OK;
}

#define NULL_THREAD_NAME "----------"


/*!
******************************************************************************
Display information on the current threads state.

*/

cmd_err_t thread_info_command(uint32 argc, char** argv)
{
    cyg_handle_t thread = 0;
    cyg_uint16 id = 0;

    UartPrintf(CONSOLE_PRINT, "STATE  SETPRIO  CURPRIO  NAME                                      STACK_BASE STACK_SIZE\n");
    while (cyg_thread_get_next(&thread, &id))
    {
        cyg_thread_info info;
        char* state_string;

        cyg_thread_get_info(thread, id, &info);

        if (info.name == NULL)
            info.name = NULL_THREAD_NAME;

        if (info.state == 0)
        {
            state_string = "RUN";
        }
        else if (info.state & 0x04)
        {
            state_string = "SUSP";
        }
        else
        {
            switch (info.state & 0x1b)
            {
            case 0x01: state_string = "SLEEP"; break;
            case 0x02: state_string = "CNTSLEEP"; break;
            case 0x08: state_string = "CREATE"; break;
            case 0x10: state_string = "EXIT"; break;
            default: state_string = "????"; break;
            }
        }

        UartPrintf(CONSOLE_PRINT, "%-6s %7d %8d  %-43s %08x %5d (%5d)\n", state_string, info.set_pri, info.cur_pri, info.name, info.stack_base, info.stack_size, info.stack_used);
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Callback for scan completion

\return error_val Always returns ERR_CMD_OK.
*/

void scan_callback(uint32 result_count)
{
    rssi_scan_count = result_count;
    DisplayRSSI_Scan(RSSI_ScanBuffer, RSSI_SCAN_BUFFER_LEN, result_count);
}


/*!
******************************************************************************
Scan for any APs with which we can associate.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t scan_command(uint32 argc, char** argv)
{
    if (!IsIBSS_Active())
    {
        char* scan_ssidptr;
        bool passive_scan;
        uint32 scan_time;
        bool remove_duplicates;

        if (strcmp(argv[0], "qscan") == 0)
        {
            passive_scan = TRUE;
            scan_time = PASSIVE_RSSI_SCAN_TIME;
            remove_duplicates = FALSE;
            scan_ssidptr = NULL;
        }
        else if (strcmp(argv[0], "fscan") == 0)
        {
            passive_scan = TRUE;
            scan_time = PASSIVE_RSSI_SCAN_TIME;
            remove_duplicates = TRUE;
            scan_ssidptr = NULL;
        }
        else
        {
            passive_scan = FALSE;
            scan_time = ACTIVE_RSSI_SCAN_TIME;
            remove_duplicates = FALSE;
            if (argc > 1)
            {
                strncpy(scan_ssidbuf, argv[1], MAX_SSID_LEN + 1);
                scan_ssidptr = scan_ssidbuf;
            }
            else
            {
                scan_ssidptr = NULL;
            }
        }

        // Perform an RSSI scan with a timeout of scan_time on Power on.
        rssi_scan_count = 0;  // start from scratch

        StartWiFiScan(RSSI_ScanBuffer, RSSI_SCAN_BUFFER_LEN, scan_time, channels_to_scan, scan_callback, passive_scan, remove_duplicates, scan_ssidptr);
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: Can't scan while in ad-hoc mode; use 'deauth' command to leave ad-hoc mode.\n");
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Scan for any APs with which we can associate.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t probe_command(uint32 argc, char** argv)
{
    char* scan_ssidptr = NULL;
    char* rep_argptr = NULL;
    char* ssid_argptr = NULL;

    switch (argc)
    {
    case 0:
    case 1:
        break;
    case 2:
        rep_argptr = argv[1];
        ssid_argptr = argv[1];
        break;
    case 3:
    default:
        ssid_argptr = argv[1];
        rep_argptr = argv[2];
        break;
    }

    rep_count = 1;
    if (rep_argptr != NULL)
    {
        for (int i = 0; (i < MAX_SSID_LEN + 1) && (rep_argptr[i] != 0); i++)
        {
            if ((rep_argptr[i] < '0') || (rep_argptr[i] > '9'))
            {
                rep_argptr = NULL;
            }
        }
        if (rep_argptr != NULL)
        {
            rep_count = atoi(rep_argptr);
            if (rep_argptr == ssid_argptr)
            {
                ssid_argptr = NULL;
            }
        }
        if (ssid_argptr != NULL)
        {
            strncpy(scan_ssidbuf, ssid_argptr, MAX_SSID_LEN + 1);
            scan_ssidptr = scan_ssidbuf;
        }
    }
    if (rep_count == 0)
    {
        rep_count++;
    }
    if (scan_ssidptr != NULL)
    {
        UartPrintf(CONSOLE_PRINT, "Probing %d time%s for %s on channel %d\n", rep_count, (rep_count == 1) ? "" : "s", scan_ssidptr, MAC_GetChannelNum());
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "Probing %d time%s on channel %d\n", rep_count, (rep_count == 1) ? "" : "s", MAC_GetChannelNum());
    }
    rep_count--;

    MAC_SendProbeRequest(scan_ssidptr, (byte*)broadcast_id, (uint16)NVM_ConfigRead(nvm_g2lib_mac_supported_rates));

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Associate with a given infrastructure BSS.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t associate_command(uint32 argc, char** argv)
{
    uint32 ap_index = 0xffffffff;
    byte wpa_version = 0x00;

    uint16 rates = (uint16)NVM_ConfigRead(nvm_g2lib_mac_supported_rates);

    if (argc > 2)
    {
        rates = axtoi(argv[2]);
    }

    if (!MAC_GetAssociated())
    {
        if (argc > 1)
        {
            strncpy(bss_ssid, argv[1], MAX_SSID_LEN + 1);
        }

        if (strlen(bss_ssid) != 0)
        {
            join_bss_timeout_count = 0;
            uint32 join_bss_timeout_period = NVM_ConfigRead(nvm_app_join_bss_timeout_period);

            if (join_bss_alarm_handle != 0)
            {
                cyg_alarm_disable(join_bss_alarm_handle);
            }

            // make sure we use the right channel for the SSID
            wifi_scan_info_t* rssi_bufptr = RSSI_ScanBuffer;

            uint32 channel = 0;

            for (int i = 0; i < rssi_scan_count; i++)
            {
                if (strcmp(bss_ssid, rssi_bufptr[i].ssid) == 0)
                {
                    channel = rssi_bufptr[i].channel;
                    MAC_SetBSSID(rssi_bufptr[i].addr);
                    ap_index = i;
               }
            }
            if (channel != 0)
            {
                MAC_SetChannelNum(channel);
                current_channel = channel;
            }

            if (ap_index != 0xffffffff)
            {
                UartPrintf(REPORTING_LEVEL_ERROR, "Supported rates for association: 0x%x\n", rates);
                if (RSSI_ScanBuffer[ap_index].capabilities & FRAME_CAPABILITIES_IBSS)
                {
                    char* temp[2] = {"adhoc", bss_ssid};
                    adhoc_command(2, temp);
                }
                else
                {
                    MAC_EnableBroadcastRx();

                    // set protection mode, short/long preamble config and use of short slot time according to AP's capabilities and ERP configuration
                    MAC_SetFrameConfig(RSSI_ScanBuffer[ap_index].capabilities, RSSI_ScanBuffer[ap_index].erp_config);

                    MAC_SetWMM_State(RSSI_ScanBuffer[ap_index].wmm_enabled != 0);

                    MAC_SetWPS_State((RSSI_ScanBuffer[ap_index].wpa_config & WPS_SUPPORTED) != 0);
                    UartPrintf(REPORTING_LEVEL_ERROR, "WPS Supported = %d\n", MAC_GetWPS_State());

                    if (RSSI_ScanBuffer[ap_index].wmm_enabled != 0xff)
                    {
                        MAC_SetWMM_PS_State((RSSI_ScanBuffer[ap_index].wmm_enabled & WMM_QOS_INFO_U_APSD_ENABLED_MASK) != 0);
                        MAC_SetWMM_ACM_Categories(RSSI_ScanBuffer[ap_index].wmm_enabled & WMM_QOS_INFO_AC_APSD_ENABLED_MASK);
                    }
                    else
                    {
                        MAC_SetWMM_PS_State(FALSE);
                        MAC_SetWMM_ACM_Categories(0);
                    }

                    // restore defaults before checking AP's capabilities
                    MAC_HW_RestoreAppTxRates();

                    uint32 hw_rate = MAC_SetHighestSupportedRate(RSSI_ScanBuffer[ap_index].supported_rates, MAC_HW_BitFieldBitToHwRate(NVM_ConfigRead(nvm_g2lib_mac_preferred_rate)));
                    if (hw_rate != 0xffffffff)
                    {
                        UartPrintf(REPORTING_LEVEL_ERROR | STARTUP_PRINT, "Set highest rate to %s, RTS rate %s and %s preamble\n", rate_strings[hw_rate], rate_strings[MAC_HW_GetRTSRate()], ((MAC_GetUsingShortPreamble()) ? "short" : "long"));
                    }

                    switch (RSSI_ScanBuffer[ap_index].security_mode)
                    {
                    case SECURITY_MODE_WEP:
                    {
                        uint32  random_num;
                    // Enable WEP, Set the default keys and the current key ID to use

                        WEP_Init(NVM_ConfigRead(nvm_app_wep_mode));
                        WEP_SetKeyFromNVM(nvm_app_wep_default_key1, 0);
                        WEP_SetKeyFromNVM(nvm_app_wep_default_key2, 1);
                        WEP_SetKeyFromNVM(nvm_app_wep_default_key3, 2);
                        WEP_SetKeyFromNVM(nvm_app_wep_default_key4, 3);
                        WEP_SetActiveKey(NVM_ConfigRead(nvm_app_wep_active_key));

                        // Set a random initialization vector to start with
                        if (CryptoGetRandNum(0, WEP_MAX_INIT_VECTOR, &random_num) == FALSE)
                        {
                            UartPrintf(REPORTING_LEVEL_ERROR | STARTUP_PRINT, "Failed to get random number for initial WEP IV!\n");
                        }
                        else
                        {
                            UartPrintf(REPORTING_LEVEL_ERROR | STARTUP_PRINT, "Setting WEP IV to %u\n", random_num);
                            WEP_SetIV(random_num);
                        }

                        MAC_SetDecryptionFunctionPtr(WEP_Decrypt);
                        MAC_SetEncryptionFunctionPtr(WEP_Encrypt);

                        JoinBSS(join_bss_timeout_period, DisconnectCallback, ConnectCallback, bss_ssid, rates, ConsoleOpen_Init);
                        break;
                    }

                    case SECURITY_MODE_WPA_MIXED:
                    case SECURITY_MODE_WPA2:
                    case SECURITY_MODE_WPA1:
                    {
                        if ((RSSI_ScanBuffer[ap_index].security_mode == (SECURITY_MODE_WPA2)) && (RSSI_ScanBuffer[ap_index].security_mode != SECURITY_MODE_WPA1))
                        {
                            wpa_version = (WPA_VERSION_2 | RSSI_ScanBuffer[ap_index].wpa_config);
                        }
                        else if (RSSI_ScanBuffer[ap_index].security_mode == SECURITY_MODE_WPA_MIXED)
                        {
                            wpa_version = (WPA_VERSION_2 | RSSI_ScanBuffer[ap_index].wpa_config);
                        }
                        else if (RSSI_ScanBuffer[ap_index].security_mode == SECURITY_MODE_WPA1)
                        {
                            wpa_version = (WPA_VERSION_1 | RSSI_ScanBuffer[ap_index].wpa_config);
                        }

                        /*
                         * Select either a raw 64 byte hex array as the pre-shared key,
                         * or use a passphrase which is passed to WPA_PassPhrasetoPSK()
                         * to generate the 64 byte pre-shared key.
                         */
                        byte    passphrase_output[WPA_PASSPHRASE_OUTPUT_LEN];

                        // Generate our PSK from the ASCII Pass Phrase
                        WPA_PassPhrasetoPSK(wpa_password, bss_ssid, strlen(bss_ssid), passphrase_output);
                        memcpy(&wpa_config.PSK, passphrase_output, DOT11_PMK_KEY_LEN);

                        UartPrintf(REPORTING_LEVEL_INFO, "Pre Shared Key is :");
                        UartDumpBytes(REPORTING_LEVEL_INFO, (byte*)wpa_config.PSK, DOT11_PMK_KEY_LEN);

                        wpa_config.WPA_version = wpa_version;
                        wpa_config.callback = EAPOL_DoneCallback;

                        JoinBSS(join_bss_timeout_period, DisconnectCallback, WPA_Start_4WayHS_Timeout, bss_ssid, rates, ConsoleWPA_Init);
                        break;
                    }
                    case SECURITY_MODE_OPEN:
                    default:
                        OpenAssociationInit();
                        JoinBSS(join_bss_timeout_period, DisconnectCallback, ConnectCallback, bss_ssid, rates, ConsoleOpen_Init);
                        break;

                    }
                    UartPrintf(CONSOLE_PRINT, "Attempting to associate with %s (WMM = %d) on channel %d...\n", bss_ssid, MAC_GetWMM_State(), current_channel);

                    // Kick off the Join BSS State Machine
                    JoinBSS_FSM_TransmitRequest();
                }
            }
            else
            {
                UartPrintf(CONSOLE_PRINT, "Couldn't find  %s in scan list. Try running the scan command.\n", bss_ssid);
            }
        }
        else
        {
            UartPrintf(CONSOLE_PRINT, "No SSID specified. Can't attempt association. Please run the scan command and make sure your ssid is in the scanned list.\n");
        }
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "Already associated with %s\n", bss_ssid);
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Routine is executed when an ad-hoc connection is established to another
ad-hoc device.

\return Nothing.
*/

void app_adhoc_connect_callback(void)
{
    UartPrintf(REPORTING_LEVEL_INFO, "Connected via ad-hoc on %s\n\n> ", GetIBSS_SSID());

    if (NVM_ConfigRead(nvm_g2lib_ip_address) != 0)
    {
        // Configure a static IP address
        struct ip_addr ipaddr;
        struct ip_addr netmask;
        struct ip_addr gw;
        struct ip_addr dnsserver;

        ipaddr.addr = NVM_ConfigRead(nvm_g2lib_ip_address);
        netmask.addr = NVM_ConfigRead(nvm_g2lib_netmask);
        gw.addr = NVM_ConfigRead(nvm_g2lib_gw_ip_address);
        dnsserver.addr = NVM_ConfigRead(nvm_app_dns_address);

        netif_set_addr(&wifi_if, &ipaddr, &netmask, &gw);
        dns_setserver(0, &dnsserver);
        netif_set_up(&wifi_if);

        adhoc_autoip_status_callback(&wifi_if);
    }
    else
    {
        if (wifi_if.autoip != NULL)
        {
            // Prevent the IP address from incrementing each time we connect using AutoIP.
            wifi_if.autoip->tried_llipaddr--;
        }
        autoip_start(&wifi_if);
    }
}


/*!
******************************************************************************
Routine is executed when we see no other ad-hoc device on our network. We are
still active, but alone.

\return Nothing.

\param[in] reason Ignored.
\param[in] data Ignored.
*/

void app_adhoc_disconnect_callback(uint32 reason, uint32 data)
{
    UartPrintf(REPORTING_LEVEL_INFO, "Ad-Hoc connection lost\n\n> ");
}


/*!
******************************************************************************
Routine is executed when AutoIP finishes its operations.

\return Nothing.

\param[in] netif Ignored.
*/

void adhoc_autoip_status_callback(struct netif *netif)
{
    if (netif_is_up(&wifi_if))
    {
        // Adhoc mode scans all channels so we might be on a different channel to what we started with
        current_channel = MAC_GetChannelNum();
        UartPrintf(REPORTING_LEVEL_INFO, "AutoIP Completed IP: %u.%u.%u.%u  NM: %u.%u.%u.%u  GW: %u.%u.%u.%u\n\n> ",
                   ip4_addr1(&wifi_if.ip_addr),
                   ip4_addr2(&wifi_if.ip_addr),
                   ip4_addr3(&wifi_if.ip_addr),
                   ip4_addr4(&wifi_if.ip_addr),

                   ip4_addr1(&wifi_if.netmask),
                   ip4_addr2(&wifi_if.netmask),
                   ip4_addr3(&wifi_if.netmask),
                   ip4_addr4(&wifi_if.netmask),

                   ip4_addr1(&wifi_if.gw),
                   ip4_addr2(&wifi_if.gw),
                   ip4_addr3(&wifi_if.gw),
                   ip4_addr4(&wifi_if.gw));
    }
}

MAC_addr_t adhoc_random_bssid = {0x02, 0x12, 0xb8, 0xff, 0xff, 0xff}; // The random BSSID we choose to use


/*!
******************************************************************************
Associate with a given infrastructure BSS.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t adhoc_command(uint32 argc, char** argv)
{
    #define ADHOC_BEACON_TX_RATE_ms         500
    #define ADHOC_PROBE_REQUEST_TX_RATE_s   0

    uint16 rates = (uint16)NVM_ConfigRead(nvm_g2lib_mac_supported_rates);
    // turn off rate shifting for adhoc mode
    NVM_ConfigWrite(nvm_g2lib_mac_auto_rate_selection, 0);
    // and set the rates up sensibly.
    NVM_ConfigWrite(nvm_g2lib_mac_preferred_rate, SUPPORTED_RATE_24_MBIT_PER_SEC_MASK);

    NVM_ConfigWrite(nvm_g2lib_mac_retries_per_rate, 4);
    NVM_ConfigWrite(nvm_g2lib_mac_total_retries, 12);
    NVM_ConfigWrite(nvm_g2lib_mac_tx_rate_1, 10);    // 12Mbit/s
    NVM_ConfigWrite(nvm_g2lib_mac_tx_rate_2, 8);      // 6Mbit/s
    NVM_ConfigWrite(nvm_g2lib_mac_tx_rate_3, 0);      // 1Mbit/s

    if (argc > 2)
    {
        rates = axtoi(argv[2]);
    }

    if (!MAC_GetAssociated())
    {
        // Reset the AutoIP module
        netif_set_down(&wifi_if);
        netif_set_status_callback(&wifi_if, adhoc_autoip_status_callback);

        if (argc > 1)
        {
            strncpy(bss_ssid, argv[1], MAX_SSID_LEN + 1);
        }

        if (strlen(bss_ssid) != 0)
        {
            // Use the default channel if channel is not already set.
            if (current_channel == 0)
            {
                MAC_SetChannelNum(NVM_ConfigRead(nvm_app_channel));
                current_channel = NVM_ConfigRead(nvm_app_channel);
            }

            // restore defaults before checking AP's capabilities.
            MAC_HW_RestoreAppTxRates();

            // Enable the application receive handler with the required ad-hoc handler.
            EnableAppReceiveHandler(AdHocAppReceiveHandler);

            // Set a random BSSID to be used if our device is the first on the ad-hoc network.
            uint32 random_number;
            CryptoGetRandNum(0x00, 0xff, &random_number);
            adhoc_random_bssid[3] = random_number;
            CryptoGetRandNum(0x00, 0xff, &random_number);
            adhoc_random_bssid[4] = random_number;
            CryptoGetRandNum(0x00, 0xff, &random_number);
            adhoc_random_bssid[5] = random_number;
            MAC_SetBSSID(*(MAC_addr_t*)adhoc_random_bssid);

            // Join/create the ad-hoc network.
            dot11_mode_t mode = BG_MODE; // Default to a BG mode for the rates. Basic: 1,2,5.5,11 Supported:6,9,12,18,24,36,48, and 54 mbps.
            JoinIBSS(mode, bss_ssid, ADHOC_BEACON_TX_RATE_ms, ADHOC_PROBE_REQUEST_TX_RATE_s, app_adhoc_connect_callback, app_adhoc_disconnect_callback);

            UartPrintf(CONSOLE_PRINT, "Attempting to associate with %s (WMM = %d) on channel %d...\n", bss_ssid, MAC_GetWMM_State(), current_channel);
        }
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Disassociate and deauthenticate from the current infrastructure BSS, or
stop the ad-hoc IBSS if we're in ad-hoc mode.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t deauth_command(uint32 argc, char** argv)
{
    byte nvm_mac_bssid[6] = {0};
    byte default_bssid[6] = {0};

    if (IsIBSS_Active())
    {
        StopIBSS();
        DisableAppReceiveHandler();
        // turn rate shifiting back on
        NVM_ConfigWrite(nvm_g2lib_mac_auto_rate_selection, 1);
        NVM_ConfigWrite(nvm_g2lib_mac_preferred_rate, SUPPORTED_RATE_54_MBIT_PER_SEC_MASK);
    }
    else
    {
        if (MAC_GetAssociated())
        {
            UartPrintf(CONSOLE_PRINT, "Disassociating/Deauthenticating from %s on channel %d...\n\n", bss_ssid, current_channel);
            MAC_SendDeauthentication(*MAC_GetBSSID(), 0x0001);
        }
        else
        {
            if (join_bss_timeout_count == 0)
            {
                if (MAC_GetAuthenticated())
                {
                    MAC_SendDeauthentication(*MAC_GetBSSID(), 0x0001);
                }
                else
                {
                    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Not associated with a BSS\n");
                }
            }
            else
            {
                UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\nAborting attempt to authenticate/associate with %s\n", bss_ssid);
            }
        }
    }

    if (join_bss_alarm_handle != 0)
    {
        cyg_alarm_disable(join_bss_alarm_handle);
    }
    join_bss_timeout_count = 0;

    NVM_ConfigReadMAC(nvm_g2lib_mac_bss_id, nvm_mac_bssid);

    wifi_if.ip_addr.addr = 0;
    wifi_if.gw.addr = 0;
    wifi_if.netmask.addr = 0;

    if (wifi_if.autoip != NULL)
    {
        autoip_stop(&wifi_if);
        netif_set_status_callback(&wifi_if, NULL);
    }
    dhcp_stop(&wifi_if);
    netif_set_down(&wifi_if);

    if (!strcmp(nvm_mac_bssid, default_bssid))
        MAC_SetBSSID(default_bssid);

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Indicate to the AP that we're entering PS mode.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t sleep_command(uint32 argc, char** argv)
{
    if (MAC_GetAssociated())
    {
        UartPrintf(CONSOLE_PRINT, "Sending power-down frame to %s...\n\n", bss_ssid);
        MAC_SendNullFunctionDataFrame(MAC_GetBSSID(), TRUE);
    }
    else
    {
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Not associated with a BSS\n");
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Read or change the 802.11 channel for scanning and association.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t channel_command(uint32 argc, char** argv)
{
    cmd_err_t result = ERR_CMD_OK;

    if (argc < 2)
    {
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Current channel is %d\n", current_channel);
    }
    else
    {
        uint32 channel = argtoi(argv[1]);

        int32 err = MAC_SetChannelNum(channel);
        if (err != MAC_CHANNEL_STATUS_OK)
        {
            UartPrintf(REPORTING_LEVEL_ERROR | CONSOLE_PRINT, "Failed to set channel frequency (%d)\n", err);
            result = ERR_UNKNOWN;
        }
        else
        {
            current_channel = channel;
            UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Set current channel to %d\n", current_channel);
        }
    }

    return result;
}


/*!
******************************************************************************
Read or change the 802.11 transmit rate.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t rate_command(uint32 argc, char** argv)
{
    cmd_err_t result = ERR_CMD_OK;

    if (argc < 2)
    {
        uint32 rate = MAC_HW_GetTransmitRate();
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Current rate is %d (%sMbit/s)\n", rate, rate_strings[rate]);
    }
    else
    {
        uint32 rate = argtoi(argv[1]);

        if ((rate <= MAC_HW_RATE_11MBPS) || ((rate >= MAC_HW_RATE_6MBPS) && (rate <= MAC_HW_RATE_54MBPS)))
        {
            MAC_HW_SetTransmitRate(rate);
            UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Set transmit rate to %d (%sMbit/s)\n", rate, rate_strings[rate]);
        }
        else
        {
            UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Invalid rate. Use 0-3, or 8-15\n");
            rate = MAC_HW_GetTransmitRate();
            UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Current rate is %d (%sMbit/s)\n", rate, rate_strings[rate]);
        }
    }

    return result;
}




/*!
******************************************************************************
Print out the current channel, SSID and association state.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t state_command(uint32 argc, char** argv)
{
    MAC_addr_t*     device_mac;

    device_mac = MAC_GetMyMACAddress();

    UartPrintf(CONSOLE_PRINT, "===================================================\n");
    UartPrintf(CONSOLE_PRINT, "SSID: %s  Channel:%d - %sAuth\'ed, %sAssoc\'ed\n", bss_ssid, current_channel, MAC_GetAuthenticated() ? "" : "Not ", MAC_GetAssociated() ? "" : "Not ");

    char bssid_str_buf[MAC_STRING_BUFFER_SIZE];
    UartPrintf(REPORTING_LEVEL_INFO, "BSSID is %s\n", MAC_FormatAddressString((byte*)MAC_GetBSSID(), bssid_str_buf));

    UartPrintf(CONSOLE_PRINT, "DSR Count = %d ISR Count %d/%d\n", rx_dsr_count, rx_isr_count, isr_event_count);

    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "%d transmits %d retries\n", MAC_GetStatsCumulativeTransmitCount(), MAC_GetStatsCumulativeRetryCount());
    UartPrintf(CONSOLE_PRINT, "Tx rate is %sMbit/s. Autorate %d\n", rate_strings[MAC_HW_GetTransmitRate()], MAC_HW_GetTransmitAutoRate());
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Retries per rate: %d Retry limit %d\n", MAC_HW_GetRetriesPerRate(), MAC_GetRetriesPerRate());

    MAC_ClearRxStats();
    MAC_ClearTxStats();

    UartPrintf(REPORTING_LEVEL_INFO | STARTUP_PRINT, "MAC Address: %s\n", MAC_FormatAddressString((byte*)device_mac, bssid_str_buf));
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "802.11 interface is %s\nIP: %u.%u.%u.%u  NM: %u.%u.%u.%u GW: %u.%u.%u.%u Port: %d\n\n",
               netif_is_up(&wifi_if) ? "UP" : "DOWN",
               ip4_addr1(&wifi_if.ip_addr),
               ip4_addr2(&wifi_if.ip_addr),
               ip4_addr3(&wifi_if.ip_addr),
               ip4_addr4(&wifi_if.ip_addr),

               ip4_addr1(&wifi_if.netmask),
               ip4_addr2(&wifi_if.netmask),
               ip4_addr3(&wifi_if.netmask),
               ip4_addr4(&wifi_if.netmask),

               ip4_addr1(&wifi_if.gw),
               ip4_addr2(&wifi_if.gw),
               ip4_addr3(&wifi_if.gw),
               ip4_addr4(&wifi_if.gw),

               NVM_ConfigRead(nvm_app_server_port));

    UartPrintf(CONSOLE_PRINT, "Available Rx Buffers:\n");
    UartPrintf(CONSOLE_PRINT, "---------------------------------------------------\n");
    MAC_PrintRxBuffers();
    UartPrintf(CONSOLE_PRINT, "---------------------------------------------------\n\n");

    uint64 current_time_millis;
    RealTimeClockGetMilliseconds(&current_time_millis);
    uint64 uptime = MetricsGetCumulativePoweredUpTime();
    uptime += GetUpTime();

    uint64 real_time;
    RealTimeClockGetMilliseconds(&real_time);

    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Current Time %8lldms\n", real_time);
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Time since power-up %8lldms\n", current_time_millis);
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "Total up time       %8lldms (%lldms))\n\n", uptime, real_time);

    UartPrintf(CONSOLE_PRINT, "LWIP Memory Usage:   |       Created      |           Used            |       Sizes       \n");
    UartPrintf(CONSOLE_PRINT, "------------------------------------------------------------------------------------------\n");
    UartPrintf(CONSOLE_PRINT, "Name                 |  lwip topup total  |  avail  used   max   err  |  each  lwip  topup\n");
    for (int i = 0; i < MEMP_MAX; i++)
    {
        lwip_mem_stats_t stat;
        lwip_get_mem_stats(i, &stat);
        UartPrintf(CONSOLE_PRINT, "MEMP_%-15s | %5d %5d %5d  |  %5d %5d %5d %5d  | %5d %5d  %5d\n", stat.name, stat.lwip, stat.topup, stat.total, stat.avail, stat.used, stat.max, stat.err, stat.size, stat.size * stat.lwip, stat.size * stat.topup);
    }
    UartPrintf(CONSOLE_PRINT, "------------------------------------------------------------------------------------------\n");
#ifdef PATCH_INCREASE_AVAILABLE_NETWORK_CONNECTIONS
    UartPrintf(CONSOLE_PRINT, "Name               totalmem  freemem  size  blocksize  maxfree\n");

    cyg_mempool_info info;
    extern cyg_handle_t *lwip_var_mempool_h;
    cyg_mempool_var_get_info(*lwip_var_mempool_h, &info);
    UartPrintf(CONSOLE_PRINT, "lwip_var_mempool     %6d  %6d   %4d  %7d  %6d\n", info.totalmem, info.freemem, info.size, info.blocksize, info.maxfree);

    extern cyg_handle_t topup_var_mempool_h;
    cyg_mempool_var_get_info(topup_var_mempool_h, &info);
    UartPrintf(CONSOLE_PRINT, "topup_var_mempool    %6d  %6d   %4d  %7d  %6d\n", info.totalmem, info.freemem, info.size, info.blocksize, info.maxfree);
    UartPrintf(CONSOLE_PRINT, "------------------------------------------------------------------------------------------\n");
#endif

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Enable sniffer

\return void
*/

void SnifferEnable(void)
{
    sniffing = TRUE;
    SnifferClearStats();

    sniff_ctrl_store = MAC_SetCtrlFilter(sniff_ctrl_filter);
    sniff_mgmt_store = MAC_SetMgmtFilter(sniff_mgmt_filter << 16);
    sniff_data_store = MAC_SetDataFilter(sniff_data_filter);

    RealTimeClockGetMilliseconds(&sniff_start_time);

    EnableAppReceiveHandler(SnifferReceiveHandler);

    original_discard = PatchTableGetPatchPointer(MAC_DiscardUnwantedFrameInDSR_PATCH_INDEX);
    PatchTableInsertPatch(MAC_DiscardUnwantedFrameInDSR_PATCH_INDEX, Patched_MAC_DiscardUnwantedFrameInDSR);

    previous_addr_mode = MAC_HW_EnablePromiscuousAddressMode();
    if (!sniff_prom_mode)
    {
        MAC_HW_RestorePromiscuousAddressMode(previous_addr_mode);
    }
}


/*!
******************************************************************************
Disable sniffer

\return void
*/

void SnifferDisable(void)
{
    uint64 sniff_end_time = 0;

    MAC_SetCtrlFilter(sniff_ctrl_store);
    MAC_SetMgmtFilter(sniff_mgmt_store);
    MAC_SetDataFilter(sniff_data_store);

    MAC_HW_RestorePromiscuousAddressMode(previous_addr_mode);  // restore the previous address mode

    sniffing = FALSE;
    DisableAppReceiveHandler();
    PatchTableInsertPatch(MAC_DiscardUnwantedFrameInDSR_PATCH_INDEX, original_discard);

    RealTimeClockGetMilliseconds(&sniff_end_time);

    cyg_thread_delay(500);
    UartPrintf(CONSOLE_PRINT, "\n\nSniffer Disabled\n\n");

    UartPrintf(CONSOLE_PRINT, "Software Stats:\n");
    UartPrintf(CONSOLE_PRINT, "  time             : %12lldms\n", sniff_end_time - sniff_start_time);
    UartPrintf(CONSOLE_PRINT, "  received         : %12d\n", sniff_stats.received_total);
    UartPrintf(CONSOLE_PRINT, "  filtered         : %12d\n", sniff_stats.filtered);

    UartPrintf(CONSOLE_PRINT, "\nReceived by rate :\n");

    for (int i = 0; i < 16; i++)
    {
        if (sniff_stats.success[i].count > 0)
        {
            UartPrintf(CONSOLE_PRINT, "                    %s: %5d frame%s rssi: %d/%d,  rssi mean: %d\n",
                       rate_strings[i], sniff_stats.success[i].count,
                       (sniff_stats.success[i].count==1 ? ", " : "s,"),
                       sniff_stats.success[i].rssi_max, sniff_stats.success[i].rssi_min,
                       (int32) (sniff_stats.success[i].rssi_total /  (int32) sniff_stats.success[i].count)
                       );
        }

        if (i == 3)
        {
            i=7; // Jump past 4-7 which have no rates.
        }
    }

    mac_hw_rx_stats_t *rx_stats = MAC_HW_GetRxStats();

    UartPrintf(CONSOLE_PRINT, "\nHardware Stats:\n");
    UartPrintf(CONSOLE_PRINT, "  rx up            : %12lldms\n", (rx_stats->rx_up/44000));
    UartPrintf(CONSOLE_PRINT, "  rx active        : %12lldms\n", rx_stats->rx_active/44000);
    UartPrintf(CONSOLE_PRINT, "  sops             : %12lld\n", rx_stats->rx_sop);
    UartPrintf(CONSOLE_PRINT, "  sop aborts       : %12lld\n", rx_stats->rx_abort);
    UartPrintf(CONSOLE_PRINT, "  rcvd .. for_us   : %12lld\n", rx_stats->mrx_rcvd);
    UartPrintf(CONSOLE_PRINT, "  rcvd_filtered    : %12lld\n", rx_stats->mrx_rcvd_filtered);
    UartPrintf(CONSOLE_PRINT, "  rcvd_not_for_us  : %12lld\n", rx_stats->mrx_rcvd_not_for_us);
    UartPrintf(CONSOLE_PRINT, "  rcvd_fcs_error   : %12lld\n", rx_stats->mrx_rcvd_fcs_error);

    UartPrintf(CONSOLE_PRINT, "\n%s", ConsolePromptString);
}


/*!
******************************************************************************
Configure the filter used for sniffing

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t filter_command(uint32 argc, char** argv)
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "control") == 0)
        {
            sniff_ctrl_filter = argtoi(argv[2]);
        }
        else if (strcmp(argv[1], "management") == 0)
        {
            sniff_mgmt_filter = argtoi(argv[2]);
        }
        else if (strcmp(argv[1], "data") == 0)
        {
            sniff_data_filter = argtoi(argv[2]);
        }
        else if (strcmp(argv[1], "prom") == 0)
        {
            sniff_prom_mode = argtoi(argv[2]);
        }
        else if (strcmp(argv[1], "mac") == 0)
        {
            for (int i = 0; i < MAC_ADDR_LEN; i++)
            {
                if(strlen(argv[i+2]) < 2)
                {
                    UartPrintf(CONSOLE_PRINT, "expected format XX:XX:XX:XX:XX:XX\n");
                    return ERR_CMD_OK;
                }
                sniff_mac_filter[i] = axtoi(argv[i+2]);
            }
            sniff_mac_filter_en = TRUE;

        }
        else if (strcmp(argv[1], "clear") == 0)
        {
            for (int i = 0; i < MAC_ADDR_LEN; i++)
            {
                sniff_mac_filter[i] = 0xff;
            }
            sniff_mac_filter_en = FALSE;
            sniff_ctrl_filter = 0xffff;
            sniff_mgmt_filter = 0xffff;
            sniff_data_filter = 0xffff;
        }
    }

    char            bssid_str_buf[MAC_STRING_BUFFER_SIZE];

    UartPrintf(CONSOLE_PRINT, "\nFilters:\n");
    UartPrintf(CONSOLE_PRINT, "    control   :  0x%04x\n", sniff_ctrl_filter & 0xffff);
    UartPrintf(CONSOLE_PRINT, "    management:  0x%04x\n", sniff_mgmt_filter & 0xffff);
    UartPrintf(CONSOLE_PRINT, "    data      :  0x%04x\n", sniff_data_filter & 0xffff);
    UartPrintf(CONSOLE_PRINT, "    mac       :  %s\n", sniff_mac_filter_en ? MAC_FormatAddressString(sniff_mac_filter, bssid_str_buf) : "disabled");
    UartPrintf(CONSOLE_PRINT, "    prom      :  %d\n", sniff_prom_mode);

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Sniff the air.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t sniff_command(uint32 argc, char** argv)
{
    if (!IsIBSS_Active())
    {
        SnifferEnable();
        UartPrintf(CONSOLE_PRINT, "Sniffer Enabled\n");
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: Can not sniff in ad-hoc mode\n");
    }
    return ERR_CMD_OK;
}

char* arp_state_string[] = {"EMPTY  ", "PENDING", "STABLE ", "EXPIRED"};


/*!
******************************************************************************
Print out the contents of the arp table.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t arp_table_command(uint32 argc, char** argv)
{
    int i;
    byte arp_table_entries = 0;
    UartPrintf(CONSOLE_PRINT, "\nARP Table:\n");
    for (i = 0; i < ARP_TABLE_SIZE; i++)
    {
        if (arp_table[i].state != ETHARP_STATE_EMPTY)
        {
            arp_table_entries++;

            char mac_str_buf[MAC_STRING_BUFFER_SIZE];

            char addr_string[16];
            diag_sprintf(addr_string, "%u.%u.%u.%u      ",
                       ip4_addr1(&arp_table[i].ipaddr),
                       ip4_addr2(&arp_table[i].ipaddr),
                       ip4_addr3(&arp_table[i].ipaddr),
                       ip4_addr4(&arp_table[i].ipaddr));
            addr_string[15] = 0;

            UartPrintf(CONSOLE_PRINT, "%s     %s     %s    %d\n",
                       addr_string,
                       MAC_FormatAddressString((byte*)&arp_table[i].ethaddr, mac_str_buf),
                       arp_state_string[arp_table[i].state],
                       arp_table[i].ctime);
        }
        else
        {
            if (arp_table[i].state != ETHARP_STATE_EMPTY)
            {
                UartPrintf(CONSOLE_PRINT, "Uh/ State for entry %d = %d\n", i, arp_table[i].state);

            }

        }

    }
    UartPrintf(CONSOLE_PRINT, "%d ARP table entries\n\n", arp_table_entries);

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Removes any old pending ping requests.

\return void
*/

static void cleanup_ping_pending(void)
{
    uint64 current_time;
    RealTimeClockGetMilliseconds(&current_time);
    for (int32 i = 0; i < MAX_PENDING_PING_REQUESTS; i++)
    {
        if (ping_seq[i] != 0)
        {
            uint64 ping_age = current_time - (ping_time[i] / MilliDivisor);

            if (ping_age > MAX_PENDING_PING_TIME)
            {
                ping_seq[i] = 0;
            }
        }
    }
}


/*!
******************************************************************************
Receive an ICMP Echo Response.

\return void
*/

void handle_ping_response(struct pbuf* pbufptr)
{
    struct ip_hdr* iphdrptr;
    u16_t hlen;
    struct icmp_echo_hdr* iechoptr;

    iphdrptr = pbufptr->payload;
    hlen = IPH_HL(iphdrptr) * 4;
    pbuf_header(pbufptr, (int16)(-hlen));
    iechoptr = pbufptr->payload;

    int32 ping_index = 0;
    for (int32 i = 0; i < MAX_PENDING_PING_REQUESTS; i++)
    {
        if ((ping_seq[i] - 1) == iechoptr->seqno)
        {
            ping_index = i;
            ping_seq[i] = 0;
            break;
        }
    }

    if (ping_index != 0)
    {
        uint64 rxtime = ping_time[ping_index];
        rx_meta_data_t* mdptr = pbuf_getmetadataptr(pbufptr);
        if (mdptr != NULL)
        {
            rxtime = mdptr->toa;
        }

        uint32 tick_diff =  rxtime - ping_time[ping_index];
        float temp_float1 = tick_diff;
        float temp_float2 = MilliDivisor;
        float time_diff = temp_float1 / temp_float2;

        uint32 payload_len = IPH_LEN(iphdrptr) - hlen - sizeof(struct icmp_echo_hdr);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n%d bytes from %u.%u.%u.%u: icmp_seq=%d ttl=%d time=%.2f ms\n\n%s", payload_len, ip4_addr1(&iphdrptr->src), ip4_addr2(&iphdrptr->src), ip4_addr3(&iphdrptr->src), ip4_addr4(&iphdrptr->src), iechoptr->seqno, IPH_TTL(iphdrptr), time_diff, ConsolePromptString);
    }

    cleanup_ping_pending();
}


/*!
******************************************************************************
Send an ICMP Echo Request (Ping) to the specified address.

\return error_val Always returns ERR_CMD_OK.
*/

cmd_err_t ping_command(uint32 argc, char** argv)
{
    if (netif_is_up(&wifi_if) && MAC_GetAssociated())
    {
        bool do_ping = TRUE;
        struct ip_addr loopback;

        loopback.addr = INADDR_LOOPBACK;

        // Ping the gateway if no arguments are provided.
        ping_ip_address = wifi_if.gw;

        pbufptr_t ed = pbuf_alloc(PBUF_RAW, ECHO_DATA_LEN, PBUF_POOL);

        if (ed == NULL)
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Could not allocate ping payload\n");
            do_ping = FALSE;
        }

        if (argc == 2)
        {
            err_t err = netconn_gethostbyname(argv[1], &ping_ip_address);
            if (err != ERR_OK)
            {
                UartPrintf(CONSOLE_PRINT, "ERROR: %s (%d)\n", lwip_strerr(err), err);
                do_ping = FALSE;
            }
        }

        if (ip_addr_cmp(&ping_ip_address, &loopback))
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: loopback interface is not supported\n");
            do_ping = FALSE;
        }

        cleanup_ping_pending();

        int32 ping_index = 0;
        for (int32 i = 0; i < MAX_PENDING_PING_REQUESTS; i++)
        {
            if (ping_seq[i] == 0)
            {
                ping_index = i;
            }
        }

        if (ping_index == 0)
        {
            UartPrintf(CONSOLE_PRINT, "ERROR: Maximum pending ping requests reached; wait %ds and try again.\n", MAX_PENDING_PING_TIME/1000);
            do_ping = FALSE;
        }

        if (do_ping == TRUE)
        {
            LastPingTime = icmp_echo_req(&ping_ip_address, &wifi_if, 0x1234, ed->payload, ECHO_DATA_LEN, handle_ping_response);
            ping_time[ping_index] = LastPingTime;
            ping_seq[ping_index] = ping_sequence_number;

            UartPrintf(CONSOLE_PRINT, "PING %u.%u.%u.%u (%u.%u.%u.%u) %d bytes of data.\n\n",
                       ip4_addr1(&ping_ip_address), ip4_addr2(&ping_ip_address), ip4_addr3(&ping_ip_address), ip4_addr4(&ping_ip_address),
                       ip4_addr1(&ping_ip_address), ip4_addr2(&ping_ip_address), ip4_addr3(&ping_ip_address), ip4_addr4(&ping_ip_address),
                       ECHO_DATA_LEN);
        }

        pbuf_free(ed);
    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "ERROR: Network interface is down\n\n");
    }

    return ERR_CMD_OK;
}


/*!
******************************************************************************
Display RSSI scan results

\return void Nothing
*/

static void DisplayRSSI_Scan(wifi_scan_info_t* rssi_bufptr, uint32 rssi_buf_len, uint32 scan_count)
{
    /*UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\nRSSI Scan Results: %d\n", scan_count);
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "  Time          SSID         Ch Ad-Hoc     Sec WPS    MAC Address     ERP WMM  RSSI Supported Rates (Mbit/s, *Mandatory)         Crypto Suites        CW Max/Min \n");

    char buf[MAC_STRING_BUFFER_SIZE]; // buffer for MAC address string
    for (int i = 0; i < scan_count; i++)
    {
        char* auth_type = "   Open";
        char suites[21] = "";
        switch (rssi_bufptr[i].security_mode)
        {
        case SECURITY_MODE_WEP:
            auth_type = "WEP";
            strcat(suites, "RC4");
            break;
        case SECURITY_MODE_WPA1:
            strcat(suites, "U-");
            auth_type = "WPAv1";
            break;
        case SECURITY_MODE_WPA_MIXED:
            strcat(suites, "U-");
            auth_type = "WPA_Mix";
            break;
        case SECURITY_MODE_WPA2:
            strcat(suites, "U-");
            auth_type = "WPA2PSK";
            break;
        case SECURITY_MODE_OPEN:
        default:
            auth_type = "   Open";
            strcat(suites, "-");
            break;
        }
        bool put_slash = FALSE;
        if (rssi_bufptr[i].wpa_config & WPA_UNICAST_AES_CCMP)
        {
            strcat(suites, "AES");
            put_slash = TRUE;
        }
        if (rssi_bufptr[i].wpa_config & WPA_UNICAST_TKIP)
        {
            if (put_slash == TRUE)
            {
                strcat(suites, "/");
            }
            strcat(suites, "TKIP");
        }
        if (rssi_bufptr[i].wpa_config & WPA_BROADCAST_AES_CCMP)
        {
            strcat(suites, " M-AES");
        }
        if (rssi_bufptr[i].wpa_config & WPA_BROADCAST_TKIP)
        {
            strcat(suites, " M-TKIP");
        }
        uint32 len = strlen(suites);
        for (uint32 i = len; i < 19; i++)
        {
            suites[i] = ' ';
        }
        suites[20] = 0;


        char rates_str[46] = "";

        uint32 rate_bit = 0x01;

        for (uint32 j = 0; j <= MAC_HW_RATE_54MBPS; j++)
        {
            if ((rssi_bufptr[i].supported_rates & rate_bit) != 0)
            {
                if (strlen(rates_str) != 0)
                {
                    strcat(rates_str, ",");
                }
                strcat(rates_str, rate_strings[j]);
                if ((rssi_bufptr[i].supported_rates & (rate_bit << 16)) != 0)
                {
                    strcat(rates_str, "*");
                }
            }
            if (j == MAC_HW_RATE_11MBPS)
            {
                j = MAC_HW_RATE_6MBPS - 1;
            }
            rate_bit <<= 1;
        }
        len = strlen(rates_str);
        for (uint32 i = len; i < 45; i++)
        {
            rates_str[i] = ' ';
        }
        rates_str[45] = 0;

        char acm_string[2] = " ";
        if ((RSSI_ScanBuffer[i].wmm_enabled & WMM_QOS_INFO_U_APSD_ENABLED_MASK) != 0)
        {
            diag_sprintf(acm_string, "%x", RSSI_ScanBuffer[i].wmm_enabled & WMM_QOS_INFO_AC_APSD_ENABLED_MASK);
        }
        char cw_string[24] = " ";
        if (rssi_bufptr[i].wmm_enabled)
        {
            diag_sprintf(cw_string, "  %d/%d %d/%d %d/%d %d/%d", rssi_bufptr[i].cw_max_min[0] >> 4,
                                                                 rssi_bufptr[i].cw_max_min[0] & 0x0f,
                                                                 rssi_bufptr[i].cw_max_min[1] >> 4,
                                                                 rssi_bufptr[i].cw_max_min[1] & 0x0f,
                                                                 rssi_bufptr[i].cw_max_min[2] >> 4,
                                                                 rssi_bufptr[i].cw_max_min[2] & 0x0f,
                                                                 rssi_bufptr[i].cw_max_min[3] >> 4,
                                                                 rssi_bufptr[i].cw_max_min[3] & 0x0f);
        }

        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "%6d %20s  %02d %6s %7s %s%s  %s  %c%c  %s%s%s %4d  %s%s%s\n", 
                    rssi_bufptr[i].time / MicroDivisor,
                    rssi_bufptr[i].ssid,
                    rssi_bufptr[i].channel,
                    (rssi_bufptr[i].capabilities & FRAME_CAPABILITIES_IBSS) ? "Y  " : "N  ",
                    auth_type,
                    (rssi_bufptr[i].wpa_config & WPS_SUPPORTED) ? "Y" : "N",
                    (rssi_bufptr[i].wpa_config & WPS_PBC_SUPPORTED) ? "P" : " ",
                    MAC_FormatAddressString(rssi_bufptr[i].addr, buf),
                    (rssi_bufptr[i].erp_config & ERP_IE_USE_PROTECTION) ? 'Y' : 'N',
                    (rssi_bufptr[i].erp_config & ERP_IE_BARKER_PREAMBLE_MODE) ? 'B' : ' ',
                    (rssi_bufptr[i].wmm_enabled) ? "Y" : "N",
                    ((RSSI_ScanBuffer[i].wmm_enabled & WMM_QOS_INFO_U_APSD_ENABLED_MASK) != 0) ? "P" : " ",
                    acm_string,
                    rssi_bufptr[i].phy_rssi,
                    rates_str,
                    suites,
                    cw_string
                  );
    }*/
    
    char buf[MAC_STRING_BUFFER_SIZE]; // buffer for MAC address string
    
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n\"wifi_towers\": [");
    for (int i = 0; i < scan_count; i++) {
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t{\n");
        
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t\"mac_address\": \"%s\",\n", MAC_FormatAddressString(rssi_bufptr[i].addr, buf));
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t\"signal_strength\": %d,\n", rssi_bufptr[i].phy_rssi);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t\"age\": %d,\n", rssi_bufptr[i].time / MilliDivisor);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t\"channel\": %d,\n", rssi_bufptr[i].channel);
        //UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t\"signal_to_noise\": %d,\n", rssi_bufptr[i].rssi_gain); //No idea what to include here for google
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t\"ssid\": \"%s\",\n", rssi_bufptr[i].ssid);

        //Debug stuff
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t//rssi_db %d\n", rssi_bufptr[i].rssi_db);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t//rssi_gain %d\n", rssi_bufptr[i].rssi_gain);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t\t//phy_rssi %d\n", rssi_bufptr[i].phy_rssi);
        
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\t},\n");
    }
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "]");
    
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n%s", ConsolePromptString);
}


/*!
******************************************************************************
UART Rx DSR - post a received character to the main thread.

\return void
*/

static void RxCharDSR(cyg_vector_t vector, cyg_ucount32 count, cyg_addrword_t isr_data)
{
    EventPost(RX_CHAR_EVENT, 0);
}


// ******************************************************************************
// Console help functions.
// ******************************************************************************

/* Help examples were removed due increasing application size
cmd_err_t help_help(char* command_name, uint32 eg_select)
{
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n  Example %d of 3:\n\n", (eg_select == 0) ? 1 : eg_select);
    switch (eg_select)
    {
    case 0:
    case 1:
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "  > %s\n", command_name);
        HelpCommand(0, NULL);
        break;
    case 2:
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "  > %s send\n", command_name);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n    Example 1 of 2\n\n");
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "    > send Hi there!\n\n");
        break;
    case 3:
    default:
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "  > %s send 2\n", command_name);
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n    Example 2 of 2\n\n");
        UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "    > send \"Hi there!\"\n\n");
        break;
    }
    return ERR_CMD_OK;
}

cmd_err_t exit_help(char* command_name, uint32 eg_select)
{
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "\n  Example %d of 1:\n\n", (eg_select == 0) ? 1 : eg_select);
    UartPrintf(REPORTING_LEVEL_INFO | CONSOLE_PRINT, "  > %s\n\n", command_name);
    return ERR_CMD_OK;
}

cmd_err_t ls_help(char* command_name, uint32 eg_select)
{
        UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
        UartPrintf(CONSOLE_PRINT, "        - list all files in flash\n\n");
    return ERR_CMD_OK;
}

cmd_err_t send_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <message string>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Send <message> to the report server.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t scatter_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [n [length] [delay]]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Scatter out a probe request frame padded out with rubbish to the defined length n times.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t vbatt_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Measure vbatt input in volts.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t tx_vbatt_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [length]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Measure vbatt input voltage before, during, and at end of Wi-Fi transmit\n");
    UartPrintf(CONSOLE_PRINT, "        - Optional [length] argument sets length of Tx in bytes\n");
    UartPrintf(CONSOLE_PRINT, "        - Tx rate is determined from last sent packet, or from rate command\n\n");
    return ERR_CMD_OK;
}

cmd_err_t rxon_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    rxon\n");
    UartPrintf(CONSOLE_PRINT, "        - Enable printing of messages received from the report server.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t rxoff_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    rxoff\n");
    UartPrintf(CONSOLE_PRINT, "        - Disable printing of messages received from the report server.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t ifdown_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    ifdown\n");
    UartPrintf(CONSOLE_PRINT, "        - Disable the network interface and clear its IP address.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t ifup_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    ifup\n");
    UartPrintf(CONSOLE_PRINT, "        - Attempt to get an IP address for the network interface.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t assoc_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [<ssid>]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Associate with an infrastructure BSS.\n\n");
    return ERR_CMD_OK;
}


cmd_err_t adhoc_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [<ssid>]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Associate with (or create) an ad-hoc IBSS.\n\n");
    return ERR_CMD_OK;
}


cmd_err_t scan_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [<ssid>]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Scan for infrastructure BSSs to join.\n");
    UartPrintf(CONSOLE_PRINT, "        - Alternatives include:\n");
    UartPrintf(CONSOLE_PRINT, "           qscan - passive scan, does not send a probe request\n");
    UartPrintf(CONSOLE_PRINT, "           fscan - filtered passive scan, removes duplicates from the list of responses\n\n");
    return ERR_CMD_OK;
}


cmd_err_t probe_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [<ssid>]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Probe for infrastructure BSSs to join.\n\n");
    return ERR_CMD_OK;
}


cmd_err_t chan_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <channel number>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Set the 802.11 channel.\n\n");
    return ERR_CMD_OK;
}


cmd_err_t rate_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [<rate number>]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Set or read the 802.11 transmit rate.\n\n");
    return ERR_CMD_OK;
}


cmd_err_t ssid_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s [<ssid_string>]\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Read/Set the SSID of the BSSID with which we'll associate.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t state_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Print out current channel, SSID and association state.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t arp_table_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    sharp\n");
    UartPrintf(CONSOLE_PRINT, "        - Print out current contents of ARP table.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t deauth_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Disassociate and deauthenticate from an infrastructure BSS.\n\n");
    return ERR_CMD_OK;
}


cmd_err_t ping_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <ping_IP_address>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Send an ICMP echo request to the specified IP address.\n");
    return ERR_CMD_OK;
}

cmd_err_t dig_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <domain>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Resolve a domain to an IP address.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t thread_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Display information on current threads.  Stack size includes in\n");
    UartPrintf(CONSOLE_PRINT, "          parenthesis the high water mark of the stack usage.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t tcp_connect_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Create a TCP connection to the IP and port specified in NVM.\n");
    return ERR_CMD_OK;
}

cmd_err_t tcp_close_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Deletes and closes a TCP connection to the IP and port specified in NVM.\n");
    return ERR_CMD_OK;
}

cmd_err_t tcp_send_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Send a packet to the server IP and port specified in NVM.\n");
    return ERR_CMD_OK;
}

cmd_err_t tcp_recv_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Receive a packet from the server IP and port specified in NVM.\n");
    return ERR_CMD_OK;
}

cmd_err_t tcp_tx_test_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <size> <count>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Start a TCP throughput transmit test.  Takes two required parameters.\n");
    UartPrintf(CONSOLE_PRINT, "        <size>  - The size of the data stream to write using netconn_write (default: %d)\n", tcp_send_length);
    UartPrintf(CONSOLE_PRINT, "        <count> - The number of times to call netconn_write (default: %d)\n\n", tcp_send_count);
    return ERR_CMD_OK;
}

cmd_err_t tcp_rx_test_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Start a TCP receive test.  Waits forever for a connection to occur from a remote host.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t sniff_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Start an 802.11 sniffer.  Will place the system into a promiscous mode and\n");
    UartPrintf(CONSOLE_PRINT, "          display a list of received frames.  Press any key to stop.  Displays statistics\n");
    UartPrintf(CONSOLE_PRINT, "          on completion.\n\n");
    return ERR_CMD_OK;
}

cmd_err_t filter_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <type> <value>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Configure a filter for the 802.11 sniffer.  Display current settings if no arguments are provided.\n");
    UartPrintf(CONSOLE_PRINT, "        <type>  - One of 'control', 'management', 'data', 'mac', 'prom', or 'clear'.  Clear will reset the filters.\n");
    UartPrintf(CONSOLE_PRINT, "        <value> - Value to configure for the type\n");
   return ERR_CMD_OK;
}

cmd_err_t http_get_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <url>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Retrieve data from a URL.  Display a portion of the data that was received.\n");
    UartPrintf(CONSOLE_PRINT, "        <url> - URL to retrieve.  For example 'http://www.g2microsystems.com/'\n\n");
    return ERR_CMD_OK;
}

cmd_err_t passwd_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <mode> [key] <password>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Configure the security keys used during association\n");
    UartPrintf(CONSOLE_PRINT, "        <mode>     - Security suite to change password. Can be 'wpa', 'wep40' or 'wep104'\n");
    UartPrintf(CONSOLE_PRINT, "        [key]      - Only required for 'wep40' or 'wep104' modes.  Selects the key to set.\n");
    UartPrintf(CONSOLE_PRINT, "        <password> - Password to set.  Should be a password for 'wpa' or a series of hex numbers for 'wep40' and 'wep104'\n");
    return ERR_CMD_OK;
}

cmd_err_t ant_select_help(char* command_name, uint32 eg_select)
{
    UartPrintf(CONSOLE_PRINT, "    %s <antenna>\n", command_name);
    UartPrintf(CONSOLE_PRINT, "        - Select the antenna configuration to use.\n");
    UartPrintf(CONSOLE_PRINT, "        <antenna> - Integer of antenna configuration found in the board configuration\n");
    return ERR_CMD_OK;
}
*/


/*!
******************************************************************************
Transmit a buffer using the MAC hardware transmit function.

The packet is contained in a single pbuf that is passed to the function. The
transmit sequence control is written and incremented in this function.

This function should not be called directly; it should be installed in the patch
table (using \#define #PATCH_MAC_TRANSMIT), and the function MAC_Output() used.

\return status Always returns ERR_OK
\param[in] netifptr Not used
\param[in] p Pointer to the pbuf being transmitted
*/

err_t Patched_MAC_OutputScatter(byte* payloadptr, uint32 length, uint32 frame_type, tx_meta_data_t* mdptr)
{
    dot11_hdr_t* mac_hdr_ptr = (dot11_hdr_t*)payloadptr;
    if (scatter_length == 0)
    {
        scatter_length = length;
    }

    uint16 temp = TxSequenceControl++;
    temp = (temp << 4) & 0xfff0;   // move higher than fragment index
    temp = SwapBytes_uint16(temp); // and make little endian
    mac_hdr_ptr->seq_ctrl = temp;

    if ((mac_hdr_ptr->frame_control & FRAME_TYPE_802_DOT_11_MASK) == FRAME_TYPE_802_DOT_11_DATA)
    {
        mac_hdr_ptr->frame_control |= FRAME_FLAG_TO_DS;
    }

    bool ack_required = TRUE;
    if (MAC_Compare(mac_hdr_ptr->address1, broadcast_id))
    {
        ack_required = FALSE;
    }

    MAC_HW_SetAckRequired(FALSE);

    // hack!! make dest address bytes not all the same
    memcpy(mac_hdr_ptr->address1, mac_hdr_ptr->address2, MAC_ADDR_LEN); // src_address -> dest_address

    MAC_HW_TransmitFrame((uint32*)payloadptr, scatter_length, mdptr);
    return ERR_OK;
}


/*!
******************************************************************************


*/

char *frame_type[] = {"Management", "Control", "Data", "Reserved"};

char *management_subtype[] = {
    "Assocation Request",
    "Association Response",
    "Reassociation Request",
    "Reassociation Response",
    "Probe Request",
    "Probe Response",
    "Reserved",
    "Reserved",
    "Beacon",
    "ATIM",
    "Disassociation",
    "Deauthentication",
    "Action",
    "Reserved",
    "Reserved"};

char *control_subtype[] = {
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "BlockAckReq",
    "BlockAck",
    "PS-Poll",
    "RTS",
    "CTS",
    "Ack",
    "CF-End",
    "CF-End + Ack"};

char *data_subtype[] = {
    "Data",
    "Data+CF-Ack",
    "Data+CF-Poll",
    "Data+CF-Ack+CF-Poll",
    "Null Data",
    "CF-Ack",
    "CF-Poll",
    "CF-Ack+CF-Poll",
    "QoS Data",
    "QoS Data+CF-Ack",
    "QoS Data+CF-Poll",
    "QoS Data+CF-Ack+CF-Poll",
    "QoS Null Data",
    "Reserved",
    "QoS CF-Poll",
    "QoS CF-Poll+CF-Ack"};


void DumpRxFrame(pbufptr_t pbufptr)
{
    static uint32 frame_count = 0;
    dot11_hdr_t* mac_hdr_ptr = (dot11_hdr_t*)pbufptr->payload;
    uint16 frame_control = mac_hdr_ptr->frame_control;
    char *ft = "";
    char *fs = "";

    uint8 type = (frame_control & FRAME_TYPE_802_DOT_11_MASK) >> 10;
    uint8 subtype = (frame_control & FRAME_SUBTYPE_802_DOT_11_MASK) >> 12;

    byte *source_addr = NULL;
    byte *dest_addr = NULL;

    char info[256];
    int32 iloc = 0;

    info[iloc] = 0;

    switch (frame_control & FRAME_TYPE_802_DOT_11_MASK)
    {
    case FRAME_TYPE_802_DOT_11_DATA:
        ft = frame_type[type];
        fs = data_subtype[subtype];
        dest_addr = mac_hdr_ptr->address3;
        source_addr = mac_hdr_ptr->address1;

        switch (frame_control & FRAME_SUBTYPE_802_DOT_11_MASK)
        {
        case FRAME_SUBTYPE_802_DOT_11_DATA:
        {
            struct eth_hdr* ethhdrptr;
            pbuf_header(pbufptr, -DOT11_EXTRA_HEADER_SPACE);
            ethhdrptr = pbufptr->payload;
            switch (htons(ethhdrptr->type))
            {
            case ETHTYPE_IP:
                iloc += diag_sprintf(info + iloc, ", IP Frame");
                break;

            case ETHTYPE_ARP:
                iloc += diag_sprintf(info + iloc, ", ARP Frame");
                break;

            case ETHTYPE_EAPOL:
                iloc += diag_sprintf(info + iloc, ", EAPOL Frame");
                break;
            default:
                iloc += diag_sprintf(info + iloc, ", Unknown Frame");
            }
            pbuf_header(pbufptr, DOT11_EXTRA_HEADER_SPACE);
        }
        }

        iloc += diag_sprintf(info + iloc, ", SN=%d", SwapBytes_uint16(mac_hdr_ptr->seq_ctrl) >> 4);

        break;

    case FRAME_TYPE_802_DOT_11_MGMT:
        ft = frame_type[type];
        fs = management_subtype[subtype];

        dot11_mgmt_frame_t* mgmt_frame_ptr = (dot11_mgmt_frame_t*)pbufptr->payload;
        source_addr = mgmt_frame_ptr->source_address;
        dest_addr = mgmt_frame_ptr->destination_address;

        switch (frame_control & FRAME_SUBTYPE_802_DOT_11_MASK)
        {
        case FRAME_SUBTYPE_802_DOT_11_BEACON:
        case FRAME_SUBTYPE_802_DOT_11_PROBE_RESPONSE:
        case FRAME_SUBTYPE_802_DOT_11_PROBE_REQUEST:
        {
            byte* ie_bufptr = (byte*)mgmt_frame_ptr->mgmt_body.probe_response.variable;
            uint32 ie_buflen = ((byte*)pbufptr->payload + pbufptr->len) - mgmt_frame_ptr->mgmt_body.probe_response.variable - DOT11_FCS_LENGTH;
            ie_t ie_ssid;
            if (GetIE(IE_ID_SSID, ie_bufptr, ie_buflen, &ie_ssid))
            {
                char ssid[MAX_SSID_LEN + 1];
                if (ie_ssid.length != 0)
                {
                    memcpy(ssid, ie_ssid.info, ie_ssid.length);
                    ssid[ie_ssid.length] = 0;
                    iloc += diag_sprintf(info + iloc, ", SSID: '%s'", ssid);
                }
                else
                {
                    iloc += diag_sprintf(info + iloc, ", SSID: '%s'", "Broadcast");
                }
            }
        }
        }

        iloc += diag_sprintf(info + iloc, ", SN=%d", SwapBytes_uint16(mgmt_frame_ptr->sequence) >> 4);

        break;

    case FRAME_TYPE_802_DOT_11_CONTROL:
        ft = frame_type[type];
        fs = control_subtype[subtype];
        dest_addr = mac_hdr_ptr->address1;
        break;
    }

    char source[MAC_STRING_BUFFER_SIZE] = "";
    char dest[MAC_STRING_BUFFER_SIZE] = "";

    if (source_addr)
    {
        MAC_FormatAddressString((byte*)source_addr, source);
    }

    if (dest_addr)
    {
        MAC_FormatAddressString((byte*)dest_addr, dest);
    }

    frame_count++;

    rx_meta_data_t* mdptr = GetRxMetaDataPtr(pbufptr);
    if (mdptr != NULL)
    {
        int32 rssi = MAC_HW_GetRSSIdBm(mdptr->phy_rssi);
        UartPrintf(CONSOLE_PRINT, "%-5d  %-17s %-17s  %2ddBm %3sMbps %4dbytes  %s%s\n", frame_count, source, dest, rssi, rate_strings[mdptr->rate], pbufptr->len, fs, info);

        if ((rssi > sniff_stats.success[mdptr->rate].rssi_max) || (sniff_stats.success[mdptr->rate].rssi_max == 0))
        {
            sniff_stats.success[mdptr->rate].rssi_max = rssi;
        }

        if ((rssi < sniff_stats.success[mdptr->rate].rssi_min) || (sniff_stats.success[mdptr->rate].rssi_min == 0))
        {
            sniff_stats.success[mdptr->rate].rssi_min = rssi;
        }
        sniff_stats.success[mdptr->rate].rssi_total = sniff_stats.success[mdptr->rate].rssi_total + rssi; // Fragile: can overflow.

    }
    else
    {
        UartPrintf(CONSOLE_PRINT, "<%p>\n", pbufptr);
    }
    pbuf_free(pbufptr);
}


/*!
******************************************************************************
This is a JoinBSS Call back function. Mainly used when we associate with an
Open AP.

\return bool TRUE If we were able to configure Open successfully, FALSE otherwise.
*/

bool ConsoleOpen_Init(void)
{
    bool result = TRUE;

    return result;
}



/*!
******************************************************************************
This is a JoinBSS Call back function. Mainly used when we associate with a
WPA(2/1) AP.

\return bool TRUE If we were able to configure WPAv(2/1) successfully, FALSE otherwise.
*/

bool ConsoleWPA_Init(void)
{
    bool result = TRUE;

    wpa_config.WPA_4WayHS_Timeout = 250; // milliseconds

    if (WPA_Init(&wpa_config, HANDSHAKE_NOTIFY_ENABLE))
    {
        UartPrintf(REPORTING_LEVEL_INFO, "WPA Version %d configured successfully\n", wpa_config.WPA_version & WPA_VERSION_NUMBER_MASK);
    }
    else
    {
        result = FALSE;
        UartPrintf(REPORTING_LEVEL_INFO, "WPA Version %d FAILED configuration\n", wpa_config.WPA_version & WPA_VERSION_NUMBER_MASK);
    }
    return result;
}


/*!
******************************************************************************
Kick the watchdog. This is done by writing the tick source and count values
with the special key codes in the upper bits. The values are read from the
NVM configuration.

This function is used to kick the watchdog from within eCos.

\return    void
*/

void Patched_eCos_WatchdogKick(void)
{
    if (AppIsWaitingOnNextEvent == FALSE)
    {
        WatchdogKick();
    }
}


/*!
******************************************************************************
Setup the discard function so no frames will be filtered.

\return    bool
*/

bool Patched_MAC_DiscardUnwantedFrameInDSR(byte* frameptr, uint32 framelen)
{
    bool discard = FALSE;

    if (sniff_mac_filter_en)
    {
        dot11_hdr_t* mac_hdr_ptr = (dot11_hdr_t*)isr_rx_address;
        if ((memcmp(mac_hdr_ptr->address1, sniff_mac_filter, MAC_ADDR_LEN) == 0) ||
            (memcmp(mac_hdr_ptr->address2, sniff_mac_filter, MAC_ADDR_LEN) == 0) ||
            (memcmp(mac_hdr_ptr->address3, sniff_mac_filter, MAC_ADDR_LEN) == 0))
        {
            discard = FALSE;
        }
        else
        {
            sniff_stats.filtered++;
            discard = TRUE;
        }
    }

    return discard;
}


/*!
******************************************************************************
Clear the culmulative totals stored by software and also any other sniffer
stats.

\return    bool
*/

void SnifferClearStats(void)
{
    MAC_HW_ResetRxStats();

    sniff_stats.received_total = 0;
    sniff_stats.filtered       = 0;
    for (int i = 0; i < 16; i++)
    {
        sniff_stats.success[i].count = 0;
        sniff_stats.success[i].rssi_min = 0;
        sniff_stats.success[i].rssi_max = 0;
        sniff_stats.success[i].rssi_total = 0;

        sniff_stats.failure[i].count = 0;
        sniff_stats.failure[i].rssi_min = 0;
        sniff_stats.failure[i].rssi_max = 0;
        sniff_stats.failure[i].rssi_total = 0;
    }

    MAC_HW_ClearStatsRx();
}

