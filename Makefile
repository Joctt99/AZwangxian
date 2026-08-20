# Makefile for AZwangxian tweak
TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = wangxian

ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AZwangxian

AZwangxian_FILES = Tweak.x
AZwangxian_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-nullability-completeness -Wno-unguarded-availability-new -Wno-shadow-uncaptured-local -Wno-c++20-extensions
AZwangxian_CCFLAGS = -std=c++17 -stdlib=libc++
AZwangxian_FRAMEWORKS = UIKit Foundation Security CoreGraphics
AZwangxian_PRIVATE_FRAMEWORKS =
AZwangxian_LDFLAGS = -framework CydiaSubstrate -lc++

include $(THEOS_MAKE_PATH)/tweak.mk
