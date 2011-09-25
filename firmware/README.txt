                      -- Console-controlled 802.11 Example Application --

-- Description of Program:

This program is a threaded console application with DHCP functionality.

If configured to do so, the application attempts, on booting, to locate an AP
with an SSID and channel specified in application configuration. It does this
by sending Probe Requests and looking at the responses. When the correct AP
is found, it tries to join the BSS using Open Authentication.

During initialisation, the application also sets up the UART interrupts for
use by the console.

In the absence of the SSID/channel information, the application simply
presents a console prompt via the serial port and waits for the user to
either provide channel information explicitly, or request an RSSI scan. The
user can then request authentication/association for a given SSID.

Once the device has joined the BSS, it obtains an IP Address, Netmask and
Gateway address using DHCP. These addresses are bound to the network interface
and it is subsequently enabled. When the interface is enabled the application
is able to exchange data with the report server.

The console provides a few basic commands to control scanning, authentication/association,
data exchange and querying of the current state.

Most importantly, the console implements a "send" command, which takes the
remainder of the command line, packages it into a UDP frame and sends it to
the report server. The console can optionally display the echoed UDP packets
from the report server. The "rxon" and "rxoff" commands control this feature.

The example application will also send a report immediately on a push button
sensor event. Reports will only be sent once the device has moved into the
Associated state and the network interface has been configured via DHCP.

NOTE: The Epsilon_console802dot11_User_Guide provides in depth explanation of
the console802dot11 application's usage, behaviour, and implementation.

-- Using the Ad Hoc capability:
Using this application, one can establish an Ad-Hoc network or join an existing Ad-Hoc network.
To establish an Ad-Hoc network, simply type 'adhoc <Your-AdHoc-ssid>' into the command prompt. This
will establish an Ad-Hoc network with SSID set to '<Your-AdHoc-ssid>'. Now other devices can
detect and join this Ad-Hoc network.

To search for Ad-Hoc networks, simply use the scan command and look for SSIDs in the output
with a 'Y' in the Ad-Hoc column. One can also attempt to associate to these Ad-Hoc networks
after a scan either by using 'assoc <Your-AdHoc-ssid>' or 'adhoc <Your-AdHoc-ssid>'.

After joining an Ad-Hoc network, allow sometime for AutoIP to complete and provide an IP
address. After this point, one can ping between these Ad-Hoc devices to test their connectivity.

-- How to Configure:

This example requires some external components to be configured for it to
operate correctly.

1. Configure an Access Point to allow Open Authentication.
2. Configure a DHCP server on the network that the Access Point is connected 
   to, or alternatively, configure the Access Point as a DHCP server.
3. Run report_server.py on a machine visible to the Access Point.
4. Set the server_ip_address NVM configuration item, in console802dot11.app_config.c
   to the IP address of the machine running report_server.py
5. Set the SSID and channel of the Access Point in the NVM config, in
   console802dot11.app_config.c

Please read the relevant README.<board_configuration_name>.txt file in the
$G2_SDK_DIR/include/board_config directory for information on configuring a
board for the sensor switch/push button.


-- Example UDP Based Server (report_server.py):

Included under the apps/scripts directory is an example "report server" 
used for receiving UDP packets transmitted by the udp_app.  When a packet
arrives, it displays a time stamp, IP address and contents.  The report server
then echoes the contents back to the udp_app. It requires python to be
installed on the system running it.


-- Hardware Platform

By default, this application has been configured to run on the Bronte v1.0
(see board_conf.h and make output), such setting utilises the internal PA
To change the hardware platform, do the following command:

$ make boardconf
