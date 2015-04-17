#
# Copyright (C) 2015 Asura Liu
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=afc
PKG_RELEASE:=1

PKG_BUILD_DIR := $(KERNEL_BUILD_DIR)/$(PKG_NAME)
STAMP_PREPARED := $(STAMP_PREPARED)_$(call confvar,CONFIG_MTD_REDBOOT_PARTS)

PKG_LICENSE:=GPLv2 GPLv2+
PKG_LICENSE_FILES:=

include $(INCLUDE_DIR)/package.mk

define Package/afc
  SECTION:=utils
  CATEGORY:=Base system
  DEPENDS:=+libopenssl
  TITLE:=Asura's firmware check
endef

define Package/afc/description
 This package contains an utility to download and validate the firmware images.
 copyright (C) 2015 Asura Liu
#
## This is free 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

target=$(firstword $(subst -, ,$(BOARD)))

MAKE_FLAGS += TARGET="$(target)"
TARGET_CFLAGS := $(TARGET_CFLAGS) -Dtarget_$(target)=1 -Wall

define Package/afc/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/afc $(1)/sbin/
endef

$(eval $(call BuildPackage,afc))
