###########################################################################
# \file Makefile
# \date 2006-12-20
# \author hoges
# \brief Makefile for the Console-controlled 802.11 Application Example.
#
# This Makefile builds the Console-controlled 802.11 application.
#
# \par Copyright
# Information contained herein is proprietary to and constitutes valuable
# confidential trade secrets of G2 Microsystems Pty. Ltd., or its licensors, and
# is subject to restrictions on use and disclosure.
#
# \par
# Copyright (c) 2004, 2005, 2006, 2007 G2 Microsystems Pty. Ltd. All rights reserved.
#
# \par
# The copyright notices above do not evidence any actual or
# intended publication of this material.
###########################################################################

#
# Check for required global environment variables
#

ifndef G2_SDK_DIR
$(error "Error! G2_SDK_DIR environment variable not set. Please source examples.bashrc before building")
endif

#
# Variables that are specific to this application.
#

APP_NAME            := console802dot11
APP_OBJS            := $(APP_NAME)_appstart.o $(APP_NAME).o
APP_CONFIG_SCRIPT   := $(APP_NAME).app_config.py
APP_CONFIG_HEADER   := $(APP_NAME).app_config.h
APP_CONFIG_CODE     := $(APP_NAME).app_config.c
APP_CONFIG_EXE      := create_$(APP_NAME).app_config.exe

APP_PATCHES_SPEC_FILE := $(APP_NAME).app_patches.mk

NVM_IMAGE           := $(APP_NAME).app_nvm.bin
APP_FILE_NAME       := $(APP_NAME)

# Configure the build process for the application to use the board configuration tool.
APP_USE_BOARD_CONFIG  := 1

# This application has some application configuration items and there are
# initial values for those application configuration items, so we need to
# tell the ROM boot code to load those initial values for us. Setting the
# NVM sector list to 0 will tell the build process to copy the first NVM
# sector which is where the application configuration is stored.
NVM_SECTOR_LIST     := 0

#
# Build targets
#

# Include the common examples Makefile which contains all of the common build
# targets for creating the application and flash image.
include $(G2_SDK_DIR)/Makefile.common
