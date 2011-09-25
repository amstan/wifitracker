/*!
******************************************************************************
\file console802dot11.h
\date 2006-12-20
\author hoges, tbriers
\brief Application main thread prototype declaration.

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

#ifndef MODEM_802_11__H
#define MODEM_802_11__H

#define RX_CHAR_EVENT                50 // Received a char through the UART


/* a prototype for the procedure which is the thread */
cyg_thread_entry_t Console802dot11AppMainThread;

#endif // MODEM_802_11_APP__H
