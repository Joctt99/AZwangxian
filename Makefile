# Makefile for AZwangxian tweak (基于 WangXianHook.mm FIX53S-AZ2 架构)
# 重要：WangXianHook.m 包含 C++ 代码 (extern "C"/<exception>/std::set_terminate/C++ catch(...))
#   → 必须重命名为 WangXianHook.mm (.mm → Objective-C++ 编译)
#   Theos 按扩展名决定编译器：.m → clang -ObjC (不允许C++) / .mm → clang -ObjC++
TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = wangxian

ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AZwangxian

# 核心源码：WangXianHook.mm（ObjC++）+ ProtocolPatcher.m + fishhook.c
AZwangxian_FILES = WangXianHook.mm ProtocolPatcher.m fishhook.c

# CFLAGS：
#   只对 .mm 目标文件传 -std=gnu++17 -stdlib=libc++ -fcxx-exceptions
#   Theos 支持 per-extension flags: <tweak>_<extension>_CFLAGS
#   .m / .c 继续走 ObjC / C 默认，不污染
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
    -Wno-unknown-warning-option \
    -Wno-pointer-bool-conversion \
    -Wno-arc-performSelector-leaks \
    -Wno-strict-prototypes \
    -Wno-gnu-folding-constant \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-empty-translation-unit \
    -Wno-incompatible-pointer-types-discards-qualifiers \
    -Wno-objc-literal-conversion \
    -Wno-objc-messaging-id \
    -Wno-int-to-void-pointer-cast \
    -Wno-sentinel \
    -Wno-missing-field-initializers \
    -Wno-covered-switch-default \
    -Wno-typedef-redefinition \
    -Wno-cast-align \
    -Wno-unused-macros \
    -Wno-c++11-narrowing \
    -Wno-null-dereference \
    -Wno-dangling-else \
    -Wno-logical-op-parentheses \
    -Wno-bitwise-op-parentheses \
    -Wno-header-hygiene

# .mm (ObjC++) 专用 flags：开启 C++17 + libc++ + ObjC++ exceptions + C++ exceptions
AZwangxian_MM_CFLAGS = -std=gnu++17 -stdlib=libc++ -fcxx-exceptions -fexceptions -fobjc-arc -fblocks

# Frameworks
AZwangxian_FRAMEWORKS = UIKit Foundation Security CoreGraphics CFNetwork SystemConfiguration QuartzCore

AZwangxian_PRIVATE_FRAMEWORKS =

# LDFLAGS：链接 CydiaSubstrate + libc++（WangXianHook 需要 C++ runtime：std::set_terminate 等）
AZwangxian_LDFLAGS = -framework CydiaSubstrate -lc++

# fishhook.c 是纯C代码，不使用ARC
fishhook_CFLAGS = -fno-objc-arc -fblocks

include $(THEOS_MAKE_PATH)/tweak.mk
