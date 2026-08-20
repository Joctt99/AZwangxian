# Makefile for AZwangxian tweak
TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = wangxian

ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AZwangxian

AZwangxian_FILES = Tweak.x
AZwangxian_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
AZwangxian_FRAMEWORKS = UIKit Foundation Security CoreGraphics
AZwangxian_PRIVATE_FRAMEWORKS =

include $(THEOS_MAKE_PATH)/tweak.mk
