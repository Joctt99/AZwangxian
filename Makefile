# Makefile for AZwangxian tweak (基于 WangXianHook.m FIX53S-AZ2 架构)
# 重要：WangXianHook.m 是纯 Objective-C（非Objective-C++）
#   Theos 按扩展名决定编译器：.m → clang -ObjC, .mm/.xm → clang -ObjC++
#   所以不要加 -std=gnu++17 / -fcxx-exceptions（会导致 "-std=gnu++17 not allowed with Objective-C"）
TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = wangxian

ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AZwangxian

# 核心源码
AZwangxian_FILES = WangXianHook.m ProtocolPatcher.m fishhook.c

# CFLAGS：
#   -fobjc-arc：ARC内存管理（WangXianHook.m使用大量属性/weak/strong）
#   -fblocks：GCD/block语法
#   -Wno-*：禁用海量-Werror触发的警告（WangXianHook.m代码量巨大、历史兼容代码多）
AZwangxian_CFLAGS = -fobjc-arc -fblocks \
    -Wno-deprecated-declarations \
    -Wno-unused-function \
    -Wno-unused-variable \
    -Wno-unused-but-set-variable \
    -Wno-unused-parameter \
    -Wno-nullability-completeness \
    -Wno-unguarded-availability-new \
    -Wno-shadow-uncaptured-local \
    -Wno-constant-logical-operand \
    -Wno-ambiguous-macro \
    -Wno-gnu-empty-initializer \
    -Wno-cstring-format-directive \
    -Wno-format \
    -Wno-gnu \
    -Wno-multichar \
    -Wno-overlength-strings \
    -Wno-parentheses \
    -Wno-shorten-64-to-32 \
    -Wno-sign-compare \
    -Wno-switch \
    -Wno-unused-label \
    -Wno-unused-value \
    -Wno-comma \
    -Wno-unknown-warning-option

# Frameworks
AZwangxian_FRAMEWORKS = UIKit Foundation Security CoreGraphics CFNetwork SystemConfiguration QuartzCore

# PrivateFrameworks：WangXianHook不直接依赖，保持空
AZwangxian_PRIVATE_FRAMEWORKS =

# LDFLAGS：链接CydiaSubstrate（MSHookFunction/MSHookMessageEx）
AZwangxian_LDFLAGS = -framework CydiaSubstrate

# fishhook.c 是纯C代码，不使用ARC，单独通过per-file CFLAGS禁用ARC
fishhook_CFLAGS = -fno-objc-arc -fblocks

include $(THEOS_MAKE_PATH)/tweak.mk
