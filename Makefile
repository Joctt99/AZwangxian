# Makefile for AZwangxian tweak (基于 WangXianHook.m FIX53S-AZ2 架构)
TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = wangxian

ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AZwangxian

# 核心源码：WangXianHook.m（完整9层通道+EE007重建+EE121 hash1/3修复+悬浮窗日志）
# + ProtocolPatcher.m（协议级patch，供WangXianHook.m调用）
# + fishhook.c（dyld绑定重绑，穿透systemhook rebind表）
AZwangxian_FILES = WangXianHook.m ProtocolPatcher.m fishhook.c

# CFLAGS：
#   -fobjc-arc：ARC内存管理
#   -fno-objc-arc：对特定文件禁用ARC（如果ProtocolPatcher.m使用MRC，在单个文件上单独设置）
#   -Wno-*：禁用所有潜在-Werror触发的警告（WangXianHook.m代码量巨大，含有历史兼容代码）
#   -std=gnu++17 -stdlib=libc++：WangXianHook.m可能混入C++特性（如__sync_add_and_fetch等不需要，这里保险起见保留）
AZwangxian_CFLAGS = -fobjc-arc -fblocks -fcxx-exceptions -fexceptions -std=gnu++17 -stdlib=libc++ \
    -Wno-deprecated-declarations \
    -Wno-unused-function \
    -Wno-unused-variable \
    -Wno-unused-but-set-variable \
    -Wno-unused-parameter \
    -Wno-nullability-completeness \
    -Wno-unguarded-availability-new \
    -Wno-shadow-uncaptured-local \
    -Wno-c++20-extensions \
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
    -Wno-unused-value

# Frameworks：WangXianHook.m使用到以下系统framework
#   UIKit: 悬浮窗、label、window操作
#   Foundation: 字符串、日志、文件、timer
#   Security: 证书、密钥、随机数
#   CoreGraphics: CGRect、绘图
#   CFNetwork: HTTP请求、URLSession
#   SystemConfiguration: 网络可达性(SCNetworkReachability)
#   QuartzCore: CATransaction、CALayer
AZwangxian_FRAMEWORKS = UIKit Foundation Security CoreGraphics CFNetwork SystemConfiguration QuartzCore

# PrivateFrameworks：WangXianHook不直接依赖，保持空
AZwangxian_PRIVATE_FRAMEWORKS =

# LDFLAGS：链接CydiaSubstrate（MSHookFunction/MSHookMessageEx）和libc++
AZwangxian_LDFLAGS = -framework CydiaSubstrate -lc++

# fishhook.c是C代码且不使用ARC；单独通过per-file标志禁用ARC（如果ProtocolPatcher.m需要也追加）
# WangXianHook.m本身使用ARC（大量__weak/strong/属性property声明）
fishhook_CFLAGS = -fno-objc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
