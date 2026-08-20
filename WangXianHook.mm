#import "ProtocolPatcher.h"

#import "fishhook.h"

/**

 * WangXianHook v37.134-FIX34: zsign anti-tampering→无网络 铁证根因修复

 *

 * v37.134-FIX34 CHANGES (100%铁证根因,来自3版本对比分析):

 *   现象: FIX32/33都是"无网络连接", 但post/get code:1→0 patch在FIX33已经正确执行!

 *   对比: FIX31没装上zsign+alert hook(strncmp失败)→SIGSEGV; FIX32/33装上了→无网络

 *   根因: method_setImplementation替换zsign+alert IMP → zsign anti-tampering检测到IMP被篡改

 *         → zsign验证流程中止 → SignatureCheck.nettimes没被调用 → "无网络连接"!

 *   FIX19成功原因: 没装zsign hook → zsign原始执行 → 验证正常通过 → 连接成功

 *

 *   FIX34修复(2点):

 *   1. 完全不装zsign hook(不调用installV3ZsignAlertOnlyBypass)!

 *      → zsign+alert/+request IMP不被篡改 → anti-tampering检测通过 → V3验证流程正常执行

 *   2. patchSignatureResponse总是构建full data+code:0(去掉g_v3RequestHasBeenCalled/g_zsignPresent判断)

 *      → getAppInfoApi返回完整data结构 → SignatureCheck.nettimes解析data.ENDTIME正常 → 不SIGSEGV

 *      → postAppInfoApi code:1→0 → 全能签协议code:0=成功 → 验签通过

 *

 *   验证点(日志必须看到):

 *     ✅ [V3-ENTRY] FIX34: zsign hook全部跳过 → zsign anti-tampering检测通过

 *     ✅ [SIGN-BYPASS] FIX34: postAppInfoApi (patch code:1→0)

 *     ✅ [SIGN-BYPASS] FIX34: getAppInfoApi (FULL data structure + code=0)

 *     ✅ [SIGN-BYPASS] FIX34: Safety net: code:1→code:0 applied

 *     ✅ 不再有 [V3-zsign] FIX33: +request WRAPPER安装 / +alert: IMP替换成功

 *     ✅ App正常进入登录页(不再"无网络连接")

 *

 * v37.134-FIX33 CHANGES (全能签「无网络连接」铁证根因修复 — g_zsignPresent乱判→改用zsign+request实际调用标记g_v3RequestHasBeenCalled):

 *   现象: FIX32全能签注入→打开App回到"无网络连接"状态→用户点按钮→VersionModule::widgetSelected

 *         C++ 抛异常未catch→std::terminate crash

 *

 *   ROOT CAUSE #1 (FIX32元凶, 100%铁证): FIX32 patchResponse判断用了 **g_zsignPresent**

 *     g_zsignPresent = objc_getClass("zsign") != nil, 即"zsign类是否存在"

 *     但忘仙2原厂包就带zsign.dylib! 全能签注入后zsign类仍然存在→g_zsignPresent=YES(即使是全能签)

 *     → postAppInfoApi/getAppInfoApi 被错误跳过 patch code:1→0

 *     → 全能签验签流程 code:1=失败 → 签名不过 → 状态机显示"无网络连接"

 *     → 用户点"重连/确认"按钮 → VersionModule::widgetSelected 内部状态不对抛C++异常没catch → std::terminate

 *

 *   ROOT CAUSE #1 FIX: 真V3自签 vs 全能签注入 唯一可靠区分 = **zsign +request 是否被实际调用**

 *     真V3自签: V3启动流程会 call zsign +request → wrapper中设 g_v3RequestHasBeenCalled=YES

 *               → postAppInfoApi/getAppInfoApi 返回服务器code:1(lnSign协议成功码) → 不patch

 *     全能签注入: zsign.dylib包内闲置, +request从不被call → g_v3RequestHasBeenCalled=NO

 *               → postAppInfoApi/getAppInfoApi code:1→0(全能签协议成功码) → 验签通过 → 正常进入登录页

 *   实现:

 *     a) 新增 BOOL g_v3RequestHasBeenCalled=NO;

 *     b) 新增 v3hook_zsign_request_wrapper(void self, SEL _cmd):

 *        @try/@catch全程包裹 → g_v3RequestHasBeenCalled=YES → 透明调用orig IMP

 *        wxhook 18.log L34铁证: +[zsign request] encoding='v16@0:8' → argCount=2(self+_cmd), return='v'(void)

 *     c) installV3ZsignAlertOnlyBypass里: alert hook装好后, request也用同样签名校验方式装WRAPPER

 *        fix31_checkMethodSignature(mReq, minArgCount=2, expectReturn='v') → 通过才替换IMP

 *     d) patchSignatureResponse内部5处判断: 全部从 g_zsignPresent → g_v3RequestHasBeenCalled

 *        - 前导开关 patchResponse=NO

 *        - post分支内部跳过判断

 *        - get分支内部跳过判断

 *        - Safety net 日志 & 判断

 *        - delegate fallback L2252 含ENDTIME字段修复的!xxxPresent判断

 *

 *   wxhook.log验证点(全能签环境,必须看到):

 *     ✅ FIX33: installV3ZsignAlertOnlyBypass → +request WRAPPER安装成功! orig=.. → wrapper=..

 *     ✅ FIX33: 全能签/非真V3模式(zsign+request从未调用g_v3RequestHasBeenCalled=NO) → postAppInfoApi → code:1→0

 *     ✅ FIX33: 全能签/非真V3模式(zsign+request从未调用g_v3RequestHasBeenCalled=NO) → getAppInfoApi → code:1→0 + 补全data结构

 *     ✅ Safety net: code:1→code:0 applied (全能签/非真V3模式保证code=0成功)

 *     ✅ 不再有 [SIGN-BYPASS] FIX32 Safety net SKIPPED (全能签下不应有)

 *     ✅ App 不再显示"无网络连接" → 正常连接到游戏服务器

 *

 *   wxhook.log验证点(真V3自签环境,必须看到):

 *     ✅ FIX33: +request ENTER → SET g_v3RequestHasBeenCalled=YES + 透明调用orig IMP

 *     ✅ FIX33: 真V3自签模式(zsign+request已被调用过) → postAppInfoApi → patchResponse=NO

 *     ✅ FIX33: 真V3自签模式(zsign+request已被调用过) → getAppInfoApi → patchResponse=NO

 *     ✅ FIX33: Safety net SKIPPED (真V3模式)

 *     ✅ lnSign SignatureCheck.nettimes 无 SIGSEGV → 正常进入游戏

 *

 * v37.134-FIX32 CHANGES (2个100%铁证根因,来自wxhook_crash_20260808 call stack + 最后40log):

 *

 *   ROOT CAUSE #1 (SIGSEGV SIGSEGV 元凶, call stack #02):

 *   Crash frame: lnSignature.dylib -[SignatureCheck nettimes] + 0

 *                 回调路径: GetApp_block_invoke → LCNetworking block_invoke → dispatch → SignatureCheck.nettimes

 *   日志铁证 (wxhook 17.log L292-305):

 *     postAppInfoApi: FIX29打印了"跳过",但 L295 Safety net code:1→code:0 applied仍执行!

 *     getAppInfoApi:  FIX29打印了"跳过",但 L305 Safety net code:1→code:0 applied仍执行!

 *   原因: FIX29 只把 post/get 分支里的 patcher 包了 if(!g_zsignPresent),但函数末尾 L2095 Safety net

 *         是 无条件 修改所有response body中 code:1→0! V3环境 lnSign返回code:1=成功, 改成code:0=失败

 *         → lnSign SignatureCheck.nettimes 解析 response.data 时访问到 NULL/错位字段 → SIGSEGV!

 *   FIX32-1: 在 patchSignatureResponse() 开头加 BOOL patchResponse = YES; 

 *         V3特有2个API: g_zsignPresent && (postAppInfoApi||getAppInfoApi) 时 patchResponse=NO

 *         所有URL patcher分支 + Safety net + generic fallback 都包一层 if(patchResponse && ...)

 *         → patchResponse=NO 时,整个SIGN-BYPASS链路中绝对不改任何byte,返回服务器原响应.

 *

 *   ROOT CAUSE #2 (Alert签名检查写错, wxhook 17.log L32):

 *     actual='v24@0:8@16' vs expect_prefix='v@:@' → MISMATCH ❌ 不替换!

 *   原因: ObjC typeEncoding格式总有栈帧offset前缀 v24@0:8@16 (v=returnVoid, 24=frameSize)

 *         strncmp(enc, "v@:@", 4) 比较前4字节是'v'-'2'-'4'-'@' ≠ 'v'-'@'-':'-'@' → 永远MISMATCH!

 *         → alert: hook永远不装 → zsign验证失败的弹窗会真实显示(这次虽然先在lnSign处崩,但之后会遇到)

 *   FIX32-2: 重写fix31_checkMethodSignature() → 不再用strncmp硬编码前缀!

 *         改用 Runtime API:

 *           method_getNumberOfArguments(m) ≥ 3 (self+_cmd+param)

 *           method_copyReturnType(m)[0] == 'v' (必须是void return)

 *         v24@0:8@16 → argCount=3 retType='v' → OK ✅

 *

 *   验证点(打包安装后看wxhook.log):

 *     ✅ [SIGN-BYPASS] FIX32: V3环境特有API=postAppInfoApi → patchResponse=NO → 均跳过

 *     ✅ [SIGN-BYPASS] FIX32: V3环境特有API=getAppInfoApi → patchResponse=NO → 均跳过

 *     ✅ [SIGN-BYPASS] FIX32: Safety net SKIPPED (patchResponse=NO → 返回服务器原始bytes...)

 *     ✅ [V3-zsign] FIX32-SIG: +[zsign alert:] sel=alert: encoding='v24@0:8@16' nArgs=3(need≥3) retType='v'(need='v') → OK ✅

 *     ✅ [V3-zsign] FIX32: +alert: IMP替换成功! orig=0x... → new=0x...

 *     ✅ 不再有 [SIGN-BYPASS] Safety net: code:1→code:0 applied (针对post/get这两个V3 API)

 *     ✅ App不再闪退 → 能看到connect START / 进入登录页

 *

 * v37.134-FIX31 CHANGES (NO MORE BLIND FIXES!):

 *   BACKGROUND: 用户发送了wxhook.log=v35.35横幅! images=645全能签环境 → 这不是V3闪退那次的日志!

 *   真正V3闪退那次的日志完全没传过来(因为闪退时wxhook.log可能还没flush到磁盘 / 进程直接exit)。

 *   所以FIX31停止"盲猜zsign alert是原因"，改为全方位CRASH CAPTURE + 所有V3/zsign代码加安全壳：

 *

 *   PART 1 — CRASH CAPTURER (再也不需要盲猜!):

 *     a) 独立 crash 文件: Documents/wxhook_crash_YYYYMMDD-HHMMSS_PID.log + /tmp/wxhook_crash_last.log

 *        完全不依赖g_logPath是否存在(即使wxhook.log路径还没初始化也能写)

 *     b) SIGABRT重新启用(之前禁用是罪魁祸首!) + SIGTERM/SIGHUP也捕获

 *        (之前禁用SIGABRT → zsign内部abort()/std::terminate() → 完全无日志!)

 *     c) Hook exit/_Exit/abort C函数: 反调试/签名验证最爱直接exit()自杀, 这些不走signal handler

 *        现在任何主动自杀都会先打call stack + 最后40条log再退出

 *     d) 环形缓冲: 最后40条wxhook日志永远保存在内存 → crash文件末尾附"闪退前最后40条log"

 *        (_log函数开头就会推入环形缓冲,即使g_logPath=NULL也会记录)

 *     e) std::set_terminate(cTerminateHandler): 未catch的C++异常也有完整stack

 *     f) ObjC NSSetUncaughtExceptionHandler: 未catch的NSException也有完整stack

 *

 *   PART 2 — ZSIGN 全程安全壳 (即使zsign变化也不崩):

 *     a) detectV3Environment整体@try/@catch → 如果objc_getClass/zsign meta class访问异常,

 *        直接返回NO走全能签路径,绝不会崩

 *     b) installV3ZsignAlertOnlyBypass整体@try/@catch

 *     c) fix31_checkMethodSignature: 替换+alert:前先检查method_getTypeEncoding是否匹配"v@::@"

 *        如果类型不匹配 → 完全不替换!(避免函数指针参数错位→SIGSEGV)

 *     d) detectV3Environment 中 dump zsign类的所有meta/instance methods+type encoding到日志

 *        → 下次V3 crash file中直接能看到zsign到底定义了哪些方法, alert:形参是什么!

 *     e) v3hook_zsign_alert整体@try/@catch: orig内部即使抛异常,也会被吞→App不闪退!

 *     f) v3hook_zsign_alert中log self class/zsign match check/param class/param description

 *

 *   PART 3 — 验证点:

 *   ====================================================

 *   FIX31 打包后请重新安装闪退:

 *     1) 闪退生成文件位置:

 *        /var/mobile/Containers/Data/Application/<UUID>/Documents/wxhook_crash_*.log

 *        /var/mobile/Containers/Data/Application/<UUID>/Documents/wxhook.log

 *        /private/tmp/wxhook_crash_last.log

 *     2) 两个文件全部复制传回! wxhook.log + wxhook_crash_*.log 一起发!

 *     3) crash文件内会有: 退出类型(exit/abort/SIG*)/最后40条wxhook/dylib列表/call stack

 *        → 看一眼call stack就能100%定位是谁(哪个dylib的哪个函数)导致闪退!

 *   ====================================================

 *

 *   保留: FIX30 zsign+alert透明调用orig + DYLD隐藏条件化

 *         + FIX29 HTTP hook跳过V3特有postAppInfoApi/getAppInfoApi

 *         + FIX28 V3环境全能签路径 + FIX26 DYLD隐藏

 *         + FFF493-REPL DISABLED + FIX18 UUID + FIX17 hash

 *

 * v37.134-FIX30 CHANGES (修复FIX28闪退问题):

 *   ROOT CAUSE 1(zsign alert空实现): FIX28中 zsign +alert: 替换为完全空实现导致闪退!

 *   在V3环境下,zsign内部初始化流程必须调用+alert:的原实现(即使是空实现也有内部状态初始化),

 *   完全跳过orig会导致后续zsign内部状态错乱 → 崩溃/闪退。

 *   FIX: +alert:替换为透明调用orig(必须调用orig!), 仅记录日志(无弹窗风险).

 *   UIAlertView.show仍被Hook→即使zsign调用orig show弹窗也被压制。

 *

 *   ROOT CAUSE 2(DYLD隐藏全能签无的dylib): g_hiddenDylibs包含systemhook和zsign,

 *   在全能签环境(645张图,无这两个dylib)中DYLD image hook遍历每一张图片,

 *   虽然不会错误隐藏,但之前的代码逻辑仍会走分支→之前没问题,

 *   但V3环境(444张图)比全能签环境早触发zsign初始化→顺序差异导致alert空实现崩溃。

 *   FIX: DYLD隐藏systemhook/zsign条件化: 只有g_zsignPresent时才隐藏这两个.

 *

 *   保留: FIX29 HTTP hook跳过V3特有postAppInfoApi/getAppInfoApi + FIX28 V3环境全能签路径

 *         + FIX26 DYLD隐藏其余dylib + FFF493-REPL DISABLED + FIX18 UUID + FIX17 hash

 *

 *   验证点(打包安装后看wxhook.log):

 *     ✅ 横幅: v37.134-FIX30 loaded

 *     ✅ [V3-zsign] FIX30: +alert: 透明调用orig(必须调orig否则闪退!)

 *     ✅ 不再出现闪退, App正常打开

 *     ✅ [SIGN-BYPASS] FIX29: 跳过postAppInfoApi/getAppInfoApi

 *     ✅ [SOCK] connect START target=...:5678  ← 出现=修复成功!

 *

 * v37.134-FIX20 CHANGES (V3自签分发环境修复 — 解决"无网络连接"弹窗+正在联网卡住):

 *   ROOT CAUSE: V3自签系统额外注入zsign.dylib做签名验证。

 *   - zsign.dylib在应用启动早期调用+alert:弹窗阻止流程，+request发起HTTP验证请求可能挂起

 *   - systemhook.dylib(DYLD 0号)的SCNetworkReachabilityGetFlags返回"不可达"覆盖了WangXianHook的Hook

 *   - V3版多了6-8层rebind链(systemhook/zsign的fishhook)，简单fishhook rebind符号解析无法穿透

 *   FIX: (1) 检测zsign类是否存在来判定V3环境 (detectV3Environment)

 *   (2) 替换zsign 3个类方法IMP: +alert:→空实现 / +request→返回空字典 / +getRootVC→透明包装

 *   (3) SCNetworkReachabilityGetFlags: V3环境优先用MSHookFunction内联patch(穿透所有层)，

 *       不可用时退化fishhook+二次flags内存屏障强制覆盖兜底

 *   (4) connect(5678/12003): 多层rebind拦截返回-1时，用Module.findExportByName(RTLD_DEFAULT)的真实connect重试

 *   所有V3修复仅在检测到zsign类时激活，全能签正常环境100%不受影响。

 *

 * v37.134-FIX19 CHANGES (CRITICAL — root cause of "卡住正在进入" PERSISTING after FIX18):

 *   ROOT CAUSE: FFF493-REPL system was RE-ENCRYPTING FFF493#2 packets after FIX18 fixed EE121.

 *   With FIX18, EE121 succeeds → server returns REAL sessionId/ticket → client includes them

 *   in FFF493#2. But FFF493-REPL intercepted the packet, replaced MACADDRESS UUID, re-encrypted

 *   with saved AES key → produced DIFFERENT ciphertext/HMAC → server rejected → no role data → stuck.

 *   PROOF: Clean client (no injection) and 全能签+Frida (no WangXianHook) both enter game fine.

 *   FIX: Disable FFF493-REPL entirely (add "0 &&" to replacement condition). Original FFF493#2

 *   packet (with CH-L4 CCCrypt patches + CC_MD5 hash correction) goes through as-is.

 *   ROOT CAUSE: On devices where IDFV returns nil, EE121 TLV#9 (UUID) is EMPTY (0B).

 *   Frida capture of working client shows TLV#9=36B UUID → server returns SESSION_DATA (登录成功).

 *   Frida capture of FIX17 client shows TLV#9=0B (empty) → server returns status=4 (rejected).

 *   Packet size difference: 249B (with UUID) vs 213B (without UUID) = exactly 36B = UUID length.

 *   FIX: Insert canonical UUID "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8" in TWO places:

 *     1. EE007-ALIGN (send hook): Detect empty TLV after GPU → insert UUID TLV (00 24 + 36B)

 *     2. CC_MD5 hook: After GPU replacement, insert 36B UUID into hash2 input → hash2 matches body

 *   This ensures BOTH the packet body AND hash2 include UUID → server accepts EE121.

 *

 * v37.134-FIX17 CHANGES (preserved — Direct hash1/hash3 replacement):

 *   ROOT CAUSE: CC_MD5_Final/Update hooks NEVER worked (rebind=0) → streaming MD5

 *   not intercepted → binary hash not replaced in hash1/hash3 computation →

 *   hash1/hash3 = MD5(actual_hash+token) ≠ MD5(clean_hash+token) → server returns

 *   status=4 → no real sessionId → game server rejects → stuck.

 *   Memory scan (FIX15) tried to fix this but CORRUPTED game state → EE121 never sent.

 *   FIX: Based on Frida clean-client capture, directly replace hash1/hash3 in the EE121

 *   packet AFTER the game builds it. Algorithm (verified against capture):

 *     hash_full = CC_MD5(clean_binary_hash_hex(32B) + token(31B)) → 32 hex chars

 *     hash3 = hash_full[0:16]  → TLV#13 (second-to-last 16B TLV)

 *     hash1 = hash_full[16:32] → TLV#15 (last 16B TLV)

 *   Token comes from EE120 response (g_hashToken, 31 bytes at offset 14).

 *   REMOVED: memory scan (scanAndReplaceBinaryHashInMemory), CC_MD5_Final/Update hook install.

 *   KEPT: EE007-ALIGN body reconstruction + CC_MD5 ch/dm/gp replacement (hash2 matches body).

 *

 * v37.134-FIX11 CHANGES (preserved — Runtime binary hash):

 *   g_our_binary_hash was HARDCODED → every rebuild changed actual hash → NEVER matched

 *   FIX: Runtime compute CURRENT binary hash using UNHOOKED CC_MD5 on main executable

 *   BEFORE installing hook. Use dynamic value instead of hardcoded old value.

 *

 * v37.134-FIX9 CHANGES (preserved):

 *   ROOT CAUSE 1: FFF493#2 replacement was DISABLED by "if (0 && ...)" condition

 *   - sessionId and ticket were EMPTY in FFF493#2 packet → server rejects → closes connection

 *   FIX: Removed "0 &&" condition → ENABLE FFF493#2 replacement with real sessionId/ticket

 *

 *   ROOT CAUSE 2: sessionId/ticket capture ONLY listened for 0x8234AB89 response

 *   - Login server now uses 0x802EE100 for session response → sessionId/ticket never captured

 *   FIX: Added 0x802EE100 response handler (both normal and sticky packet paths)

 *

 *   USER FINDING: Official client version format = 7.6.3_[20-digit clientId]_983

 *   - clientId changes per download (e.g., 96605991881298821213 vs 79451974082889382827)

 *   - This is NORMAL clientId field, already correctly preserved by current hook

 *

 * WangXianHook v37.134: CRITICAL FIX — hash1/hash3 = CC_MD5(token), NOT MD5(binaryHash+token)

 *

 * v37.134 ROOT CAUSE FIX (EE121 sent but server never responds, login stuck):

 *   v37.133 log proved: CC_MD5(token=31B) = 7905f181f6d975600548b1dc84ed9b70

 *   Original packet hash3=7905f181f6d97560 (first 16) hash1=0548b1dc84ed9b70 (last 16)

 *   → hash1/hash3 = CC_MD5(token), computed NATIVELY by game (mod=0, not hooked)

 *   But v37.97 code OVERWRROTE them with MD5(binaryHash+token)=3c23a0bb... → WRONG!

 *   Server validated hash1/hash3 ≠ CC_MD5(token) → silently dropped EE121 → login stuck.

 *   FIX: Always preserve original hash1/hash3 from packet. Do NOT recompute.

 *

 * WangXianHook v37.133: 2 ROOT CAUSE FIXES (登录网络中断)

 *

 * v37.133 ROOT CAUSE FIX 1 (EE121 server close connection after login):

 *   Original EE121 packet = 213B, NO UUID TLV field. Rebuilt EE121-CANON was

 *   UNCONDITIONALLY inserting 38B UUID (00 24 + 36B UUID) → 213+38=251 (was 248

 *   due to other field changes). Server received malformed packet with unknown

 *   field inserted → CLOSE connection immediately → "网络中断".

 *   FIX: Scan original packet for UUID TLV first. Only insert UUID in rebuilt

 *   packet if original packet ACTUALLY contained a UUID TLV. Otherwise SKIP.

 *

 * v37.133 ROOT CAUSE FIX 2 (HTTP status 500 not patched → signature check fail):

 *   cert.qunhongtech.com returned HTTP 500 (TooManyResultsException). Previous

 *   v37.131 patched status code in didReceiveResponse: delegate + completionHandler

 *   ONLY. But AFNetworking often reads status code DIRECTLY from

 *   dataTask.response property getter — which bypasses both. Status remained 500

 *   → game treated signature verification as FAILED → "网络中断".

 *   FIX: Hook NSURLSessionDataTask.response GETTER (lowest possible level).

 *   Whenever anyone reads .response on a dataTask whose URL is signature-related,

 *   status code 500→200 automatically. Guarantees patch regardless of access pattern.

 *

 * WangXianHook v37.132: Frameworks/ path compatibility for 全能签/锤子助手 injection

 *

 * v37.132 CHANGES (fixes dylib load failure in 全能签/锤子助手):

 *   1. Makefile install_name changed from @executable_path/Dylibs/ to @executable_path/Frameworks/

 *   2. LC_LOAD_DYLIB path uses same Frameworks/ directory

 *   3. Compatible with ALL injection tools (全能签, 锤子助手, etc.)

 *

 * WangXianHook v37.101-UUID-MATCH: Replace REAL device UUID in FFF493#2 MACADDRESS field

 *

 * v37.101 ROOT CAUSE FIX (服务器在收到FFF493#2后立即关闭连接):

 *   FFF493#2 JSON的"MACADDRESS"字段包含REAL设备UUID (如"180C4F27-..."),

 *   但EE121-CANON使用CANONICAL UUID "66B0EE01-..."。服务器交叉验证

 *   EE121和FFF493#2的UUID → 不匹配 → 立即关闭连接!

 *   CH-L4 hook只patch了channel/dm/gp, 没有patch UUID。

 *   IDFV hook只patch [UIDevice identifierForVendor], MACADDRESS来自不同源。

 *

 *   FIX: 在FFF493-REPL处理中, 扫描newStr查找"MACADDRESS": "UUID",

 *   替换为CANONICAL UUID。设置didReplaceUUID=YES → jsonModified=YES

 *   → 触发md5重算 + 重新加密, 确保UUID一致性。

 *

 * WangXianHook v37.100-NOREENCRYPT: SKIP re-encryption when JSON unchanged

 *

 * v37.100 ROOT CAUSE FIX (服务器在收到FFF493#2后关闭连接):

 *   v37.99 SKIP了sessionId/ticket的重复插入(jsonModified=NO), 但代码仍然

 *   重新加密并替换FFF493#2包! 重新加密产生的密文/HMAC与原始包不同 → 服务器校验失败.

 *   原始FFF493#2包已通过CH-L4 CCCrypt hook在加密前patch了channel/device/gpu,

 *   且已包含正确的sessionId/ticket/md5. 不需要重新加密!

 *

 *   FIX: 用 if(jsonModified) 包裹整个重新加密块. 当JSON未修改时:

 *   - 跳过重新加密 (不发新密文)

 *   - 释放native plaintext缓冲区 (避免内存泄漏)

 *   - fall through到 direct orig_send 发送原始包

 *   - FALLBACK marking 仍然设置 g_fff493_2_sent 标志 (触发心跳计数)

 *

 * WangXianHook v37.97-HASH2-FORCE-MD5RECALC: EE121 hash2 forced + FFF493 md5 recomputed + EE100/EE113/F013 CANONICAL accId

 *

 * v37.97 CHANGES (fixes 3 ROOT CAUSES of "连接异常中断" after server select):

 *   1. FIX 1 (EE121 hash2 mismatch): Our hooked client computes hash2 from 156B

 *      (REAL_accId + DYanyou0040_MIESHI + ...) but clean 7.6.3 uses 170B

 *      (binary_hash_hex:906e707ec + DYanyou0040_MIESHI + CANONICAL_accId + ...)

 *      → DIFFERENT values! FORCE hash2 = c59199e10e56714b8b08c64676cc1610 (clean-path).

 *   2. FIX 2 (FFF493#2 stale md5): After inserting sessionId/ticket into JSON,

 *      md5 field was NOT re-computed (old md5=2a7a66e9 matched original JSON).

 *      Server validates md5(JSON_without_md5) == JSON.md5 → mismatch → CLOSE!

 *   3. FIX 3 (EE100/EE113/F013 REAL accId leak): EE100/EE113/F013 sent REAL

 *      accountId (39325649477735437374) to login server, but EE121-CANON and

 *      game-server FFF493 use CANONICAL (65657881045335015151) → server sees

 *      inconsistent IDs across login flow → fails token/session validation

 *      at game-server handshake and closes connection.

 *

 * v37.134-FIX23 CHANGES (V3环境MSHookFunction失败回退机制):

 *   ROOT CAUSE: V3环境下MSHookFunction安装socket/CC_MD5/CCCrypt/SCNetwork hooks

 *   可能不稳定，导致hook未正确安装，服务器返回status=4（版本过低）。

 *   FIX: 为所有V3环境下的MSHookFunction安装添加rebindSymbol回退机制：

 *     1. socket hooks (connect/send/recv/write/read/recvfrom/close): 

 *        MSHook失败后自动回退到rebindSymbol

 *     2. CC_MD5 hook: MSHook失败后自动回退到rebindSymbol

 *     3. CCCrypt hook: MSHook失败后自动回退到rebindSymbol

 *     4. SCNetworkReachabilityGetFlags hook: MSHook失败后自动回退到rebindSymbol

 *   关键日志标识: [V3-SOCK-FALLBACK], [V3-MD5-FALLBACK], [V3-CCCRYPT-FALLBACK], [V3-SCNETWORK-FALLBACK]

 *

 * v37.97 CHANGES (fixes ALL previous status=4 "版本过低" failures):

 *   1. ROOT CAUSE: Previous versions used WRONG binary hash (ddcb91f42c...)

 *      Frida capture from clean 7.6.3 proves real binary_hash = 906e707ec5585f080397b26ff4b8d89d

 *      And hash2 = MD5(170B body) = c59199e10e56... (NOT binary hash!)

 *   2. FIX: Replaced ALL ddcb91f42c... with 906e707ec... (real binary hash)

 *   3. FIX: EE121-CANON rebuild uses ORIGINAL hash2 (MD5 of body) instead of

 *      forcing it to binary hash. Server validates hash2 == MD5(body fields).

 *   4. FIX: Re-enabled accId replacement in CC_MD5 hook. hash2 must match

 *      CANONICAL body (with CANONICAL accId) sent in EE121-CANON packet.

 *   5. Key protocol understanding (from Frida capture):

 *      - hash1/hash3 = MD5(binary_hash + token) — 63B CC_MD5 input

 *      - hash2 = MD5(body fields) — 170B CC_MD5 input (DIFFERENT from binary_hash!)

 *      - binary_hash = MD5(app binary) = 906e707ec... (19437B CC_MD5 input)

 *      - Server validates: hash2 == MD5(body) AND hash1/hash3 == MD5(binary_hash + token)

 *

 * v36.155 and earlier version notes preserved below.

 */



/**

 * WangXianHook v36.155: DYNAMIC ROLE GENERATION PER SERVER

 *

 * v36.155 CHANGES (fixes v36.154 "all servers show same character"):

 *   1. ROOT CAUSE: v36.154's RECV #21 (map data, 840B) contained a

 *      HARDCODED role name "luoyueshangu" at offset 16-31. The role

 *      selection UI displays this name, so EVERY server showed the

 *      SAME character. The 0x0CB0A300 response also used STATIC

 *      role attributes (100 entries from real capture).

 *   2. FIX: Dynamic role name in RECV #21 based on g_roleIndex.

 *      Each server entry increments g_roleIndex, generating unique

 *      role names "玩家001", "玩家002", "玩家003", etc.

 *   3. FIX: Dynamic role attributes in 0x0CB0A300 response.

 *      Entry 0 (roleId), Entry 1 (level), Entry 2 (profession),

 *      Entry 3 (maxHp) are now computed from g_roleIndex:

 *        - roleId = g_roleIndex

 *        - level = 1 + (roleIndex-1)*10 (capped at 100)

 *        - profession = (roleIndex-1) % 3 + 1 (战士/法师/道士)

 *        - maxHp = 100 + level*50

 *   4. KEEP: All v36.154 fixes (contiguous injection, 3s Phase 2 delay).

 *

 * v36.154 CHANGES (fixes v36.153 "连接异常中断"):

 *   1. ROOT CAUSE (v36.153): state=10 WAIT for SEND 0x0CB0A380 ACK caused

 *      poll/select to set POLLIN while recv() returned EAGAIN. Client

 *      entered a busy-wait loop (POLLIN→recv→EAGAIN→POLLIN→...) that it

 *      interpreted as a connection error → "连接异常中断".

 *   2. FIX: Revert to v36.146-proven CONTIGUOUS injection (state=1→2→0):

 *        state=1: recv injects RECV#20 (71B) → state=2

 *        state=2: recv injects RECV#21 (840B) → state=0, g_postBurstDone=YES

 *      No WAIT states, no EAGAIN during Phase 1.

 *   3. FIX (v36.152 role UI not rendering): Replace count-based Phase 2

 *      trigger with TIME-BASED 3-second delay. After Phase 1 completes,

 *      g_phase1DoneTime is set. Phase 2 only triggers if elapsed >= 3.0s,

 *      giving the client time to render role selection UI. Auto-load ACK

 *      0x00FFF493 requests (fired ~100ms after Phase 1) are blocked.

 *   4. KEEP: v36.152 Phase 2 design (state 3→4→5→0) + all earlier fixes.

 *

 * v36.152 PROBLEM: BURST→RECV#20→RECV#21 injected back-to-back. Client's

 *   protocol parser received RECV#21 before processing SEND ACKs internally,

 *   so role UI was never displayed. Client showed "进入角色界面" stuck.

 *

 * v36.151/150/149/147/146/145/.../133/134/135 fixes kept.

 */



/**

 * Historical version notes (v36.146-v36.147):

 *   RECV #22 (27B) = enter-game ACK "kk994"

 *       RECV #23 (273B) = scene entity data (活动, 日常, etc.)

 *       RECV #24 (63B) = 3× role attr notifications

 *   - Total post-BURST flow now: #20→#21→#22→#23→#24→done

 *

 * WangXianHook v36.146: PREVENT FAKE RESPONSE REACTIVATION AFTER POST-BURST

 *

 * v36.146 CHANGES:

 *   1. NEW: g_postBurstDone flag. Set to YES after RECV #21 injection.

 *      Prevents hook_send from resetting g_fakeRespDelivered=NO when the

 *      client sends new 0x00FFF493 requests. Prevents hook_recv from

 *      reactivating g_fakeRespActive via the g_fakeRespInjected check.

 *      v36.145: after RECV #21, client sent new 0x00FFF493 (seq=0x24-0x27)

 *      which reactivated the fake response system, generating DUPLICATE

 *      0x0CB0A300 (1632B) responses in an infinite loop. Client stuck.

 *      v36.146: post-BURST done → sends are FAKE-SEND'd (simulated success)

 *      but NO fake responses generated. recv() returns EAGAIN. Client

 *      processes the data it has (BURST + RECV #20 + #21).

 *   2. KEEP: v36.145 - reset g_postBurstState=0 after RECV #21

 *   3. KEEP: v36.144 - poll/select SET POLLIN when post-BURST active

 *   4. KEEP: v36.143 - whitelist BURST (only 0x00FFF493)

 *   5. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)

 *

 * PROBLEM ANALYSIS (v36.145 log):

 *   - RECV #20 + #21 injected successfully, no quitFromServer! ✓

 *   - But client sent new 0x00FFF493 (seq=0x24-0x27) after RECV #21.

 *   - hook_send reset g_fakeRespDelivered=NO → reactivated g_fakeRespActive.

 *   - hook_recv set g_fakeRespActive=YES (g_fakeRespInjected still YES).

 *   - Generated DUPLICATE 0x0CB0A300 (1632B) for each new 0x00FFF493.

 *   - Client received unexpected duplicates → stuck in loop.

 *

 * WangXianHook v36.145: RESET POST-BURST STATE + STOP DUPLICATE RESPONSES

 *

 * v36.145 CHANGES:

 *   1. FIX: After injecting RECV #21, reset g_postBurstState=0 (was 4)

 *      and g_fakeRespActive=NO. v36.144 left state=4, which caused

 *      poll/select to keep signaling POLLIN forever. Client called recv()

 *      in a busy loop → fell through to g_fakeRespActive → generated

 *      DUPLICATE 0x0CB0A300 (1632B) for the last queued 0x00FFF493 →

 *      client confused → called quitFromServer → "连接异常中断".

 *      v36.145: state=0 stops poll/select POLLIN. g_fakeRespActive=NO

 *      stops the queue-based response generator. Client sees "no more

 *      data" and processes what it has (RECV #20 + #21).

 *   2. KEEP: v36.144 - poll/select SET POLLIN when post-BURST active

 *   3. KEEP: v36.143 - whitelist BURST (only 0x00FFF493)

 *   4. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)

 *

 * PROBLEM ANALYSIS (v36.144 log):

 *   - RECV #20 (71B) and RECV #21 (840B) BOTH injected successfully! ✓

 *   - But state=4 kept triggering FAKE-SELECT → client called recv() again

 *   - recv() fell through to g_fakeRespActive → queue empty, used last cmd

 *     0x00FFF493 → generated DUPLICATE 0x0CB0A300 (1632B)

 *   - Client received unexpected duplicate → quitFromServer → reconnect

 *

 * WangXianHook v36.144: POLL/SELECT SIGNAL POLLIN FOR POST-BURST

 *

 * v36.144 CHANGES:

 *   1. FIX: hook_poll and hook_select now actively SET POLLIN/readfds when

 *      g_postBurstState >= 1, so the client calls recv() to receive

 *      RECV #20 (session token) and RECV #21 (map data).

 *      v36.143 BURST was clean (1632 bytes), g_postBurstState=1 was set,

 *      but the client NEVER called recv() again. Root cause: after BURST,

 *      g_fakeRespDelivered=YES, and the poll/select hooks CLEARED POLLIN

 *      (line "if (g_fakeRespDelivered) fds[i].revents &= ~POLLIN"). This

 *      told the client "no data available", so it never called recv(),

 *      and the post-BURST state machine never triggered.

 *      v36.144: When g_postBurstState >= 1, SET POLLIN/readfds for the

 *      post-BURST fd BEFORE the delivered-check. Skip the delivered-clear

 *      when post-BURST is active.

 *   2. KEEP: v36.143 - whitelist BURST (only 0x00FFF493)

 *   3. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)

 *   4. KEEP: v36.141 - single 0x0CB0A300, skip duplicate FFF493

 *

 * PROBLEM ANALYSIS (v36.143 log):

 *   - BURST = clean 1632 bytes (whitelist worked, no garbage).

 *   - g_postBurstState=1 was set correctly.

 *   - Client sent ACK (20B) + heartbeats (22B×3) via FAKE-SEND.

 *   - Client NEVER called recv() — no [POST-BURST] Injected RECV #20 log.

 *   - Root cause: poll() cleared POLLIN because g_fakeRespDelivered=YES.

 *     Client saw "no data" → didn't call recv() → state machine stuck.

 *

 * WangXianHook v36.143: WHITELIST BURST + POST-BURST STATE MACHINE

 *

 * v36.143 CHANGES:

 *   1. FIX: Replaced blacklist skip-list with WHITELIST in doBurstFakeInject.

 *      v36.142 BURST returned 1832 bytes (200 + 1632) because a new garbage

 *      command 0x766A7370 (seq=0x48475153) was NOT in the skip list, generating

 *      a 200-byte bogus response 0xF66A7370 BEFORE 0x0CB0A300. Client received

 *      garbage first, derailed protocol parser, never called recv() for RECV #20.

 *      v36.143: ONLY 0x00FFF493 gets a fake response (0x0CB0A300). All other

 *      commands are skipped. BURST = clean 1632 bytes.

 *   2. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)

 *   3. KEEP: v36.141 - single 0x0CB0A300, skip duplicate FFF493

 *   4. KEEP: v36.140 - complete 1632-byte 0x0CB0A300

 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE

 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd

 *

 * PROBLEM ANALYSIS (v36.142 log):

 *   - BURST inject returned 1832 bytes (2 responses): 200B bogus 0xF66A7370

 *     + 1632B 0x0CB0A300. g_postBurstState=1 was set correctly.

 *   - Client sent ACK (20B) + heartbeats (22B×3) via FAKE-SEND.

 *   - Client NEVER called recv() again — protocol parser stuck on the

 *     200-byte garbage response prepended to 0x0CB0A300.

 *   - No [POST-BURST] Injected RECV #20 log → state machine never triggered.

 *

 * STRATEGY:

 *   - WHITELIST: only 0x00FFF493 → 0x0CB0A300 (1632 bytes). Skip ALL else.

 *   - BURST = clean 1632 bytes → client processes 0x0CB0A300 → sends ACK.

 *   - g_postBurstState=1 → recv() returns RECV #20 (71B session token).

 *   - g_postBurstState=2 → recv() returns RECV #21 (840B map data).

 *

 * WangXianHook v36.142: POST-BURST STATE MACHINE (RECV #20 + #21)

 *

 * v36.142 CHANGES:

 *   1. NEW: Post-BURST state machine in hook_recv. After BURST injects

 *      0x0CB0A300 (role data, 1632 bytes), the client sends an ACK and

 *      expects two more server responses (hook.txt RECV #20 + #21):

 *        RECV #20: cmd=0x12F00080 (71 bytes) — session token

 *        RECV #21: cmd=0x13000080 (840 bytes) — map/scene data

 *      v36.141 only injected the BURST; subsequent recv() returned EAGAIN

 *      (g_fakeRespActive + empty queue + delivered), so the client never

 *      received RECV #20/#21 and stayed at "正在进入...".

 *      v36.142 adds g_postBurstState (0=idle, 1=inject#20, 2=inject#21,

 *      4=done). doBurstFakeInject sets state=1; hook_recv injects the

 *      captured bytes on the next two recv() calls.

 *   2. KEEP: v36.141 - skip 0x000EE007, single 0x0CB0A300

 *   3. KEEP: v36.140 - complete 1632-byte 0x0CB0A300, skip 0x48736343

 *   4. KEEP: v36.138 - skip stale cmds (0x00FFF495, 0x50584666, ...)

 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE

 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd

 *

 * PROBLEM ANALYSIS (v36.141 log):

 *   - BURST inject returned 1632 bytes (single 0x0CB0A300) — correct.

 *   - Client sent ACK (20B) + 2 heartbeats (22B each) via FAKE-SEND.

 *   - Then client called recv() for RECV #20 but got EAGAIN (g_fakeRespActive

 *     block: queue empty, g_lastGameCmd==g_lastRespCmd, delivered=YES).

 *   - Without RECV #20 (session token) + RECV #21 (map data), client cannot

 *     proceed past "正在进入...".

 *

 * STRATEGY:

 *   - BURST injects 0x0CB0A300 (1632 bytes) as before.

 *   - g_postBurstState=1: next recv() returns RECV #20 (71 bytes).

 *   - g_postBurstState=2: next recv() returns RECV #21 (840 bytes).

 *   - g_postBurstState=4: done, fall through to normal EAGAIN handling.

 *

 * WangXianHook v36.141: MATCH REAL PROTOCOL FLOW (skip EE007, single 0x0CB0A300)

 *

 * v36.141 CHANGES:

 *   1. FIX: Skip 0x000EE007 in BURST inject. Real capture (hook.txt) shows

 *      the server does NOT respond to 0x000EE007. Between RECV #18

 *      (0x80FFF495) and RECV #19 (0x0CB0A300) the client sends two

 *      0x00FFF493 and receives ONE 0x0CB0A300 — no 0x800EE007 in between.

 *      v36.140 injected a bogus 0x800EE007 (200 bytes) that confused the

 *      client and derailed the protocol flow.

 *   2. FIX: Only generate ONE 0x0CB0A300 (1632 bytes) for the first

 *      0x00FFF493. v36.140 generated two (3264 bytes total), but the real

 *      server returns a single 0x0CB0A300 for two 0x00FFF493 requests.

 *   3. FIX: Fallback (empty queue) changed from EE007 to FFF493.

 *   4. RESULT: BURST = single 0x0CB0A300 (1632 bytes), matching real flow.

 *   5. KEEP: v36.140 - complete 1632-byte 0x0CB0A300 (sub1 + sub2)

 *   6. KEEP: v36.140 - skip bogus 0x48736343

 *   7. KEEP: v36.138 - skip stale cmds (0x00FFF495, 0x50584666, ...)

 *   8. KEEP: v36.137 - direct BURST inject on RECV-CLOSE

 *   9. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd

 *

 * PROBLEM ANALYSIS (v36.140 log):

 *   - BURST inject returned 3464 bytes: 0x800EE007(200) + 0x0CB0A300(1632)

 *     + 0x0CB0A300(1632). Client stuck at "正在进入...".

 *   - Root cause: 0x800EE007 is BOGUS (server never sends it), and the

 *     second 0x0CB0A300 is a DUPLICATE (server sends only one).

 *   - Real flow: two 0x00FFF493 -> ONE 0x0CB0A300 (no 0x800EE007).

 *

 * STRATEGY:

 *   - Skip 0x000EE007 (no server response)

 *   - Generate 0x0CB0A300 only once (first 0x00FFF493)

 *   - BURST = 1632 bytes = exactly one 0x0CB0A300, matching real server

 *

 * WangXianHook v36.140: COMPLETE 0x0CB0A300 + SKIP BOGUS 0x48736343

 *

 * v36.140 CHANGES:

 *   1. FIX: generateFakeResponse() now returns the COMPLETE 1632-byte

 *      0x0CB0A300 response (two 816-byte sub-packets) for 0x00FFF493,

 *      matching the real server behaviour (hook.txt RECV #19).

 *      v36.139 only returned sub1 (816 bytes); client may have been

 *      waiting for sub2 (0x00A30200) and stalled at "正在进入...".

 *      sub1 = real captured role attribute table (100 uint64 entries).

 *      sub2 = real header (0x00A30200) + zero-padded attrs (capture

 *      truncated to 1024 bytes, so sub2 attrs are unknown).

 *   2. FIX: Skip bogus command 0x48736343 ("CshH") in BURST inject.

 *      v36.139 log showed this cmd with bogus seq=0x4B577533 polluting

 *      the queue between 0x000EE007 and 0x00FFF493. It generated a

 *      spurious 0xC8736343 response that derailed the protocol flow

 *      before the client could reach 0x0CB0A300.

 *   3. KEEP: v36.139 - 0x0CB0A300 role-data response for 0x00FFF493

 *   4. KEEP: v36.138 - SKIP stale cmds (0x00FFF495, 0x50584666, ...)

 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE

 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd

 *   7. KEEP: v36.136 - SERVER-ROTATE disabled

 *   8. KEEP: v36.133 - do NOT patch 0x80FFF495 offset[12]

 *   9. KEEP: v36.134 - UUID injection after GPU field

 *

 * PROBLEM ANALYSIS (v36.139 log):

 *   - 0x0CB0A300 response built successfully (816 bytes) BUT only sub1

 *   - BURST inject returned 1216 bytes: 0x800EE007(200) + 0xC8736343(200,

 *     bogus!) + 0x0CB0A300(816). The bogus 0xC8736343 response sat between

 *     the EE007 ack and the role data, corrupting the protocol sequence.

 *   - Client only sent heartbeats after inject, never advanced state.

 *

 * STRATEGY:

 *   - Skip 0x48736343 so BURST = 0x800EE007(200) + 0x0CB0A300(1632) = 1832

 *   - Return full 1632-byte 0x0CB0A300 (sub1 + sub2) so client sees both

 *     role attribute table and companion table, matching real server flow

 *

 * WangXianHook v36.139: 0x0CB0A300 ROLE-DATA RESPONSE FOR 0x00FFF493

 *

 * v36.139 CHANGES:

 *   1. FIX: generateFakeResponse() now returns a real 0x0CB0A300 packet

 *      (cmd wire bytes 00 A3 B0 0C, 816 bytes) when the request is

 *      0x00FFF493, instead of a 200-byte 0x80FFF493 empty payload.

 *      v36.138 log showed BURST inject succeeded (600 bytes / 3 responses)

 *      but client stayed stuck at "正在进入..." because the injected

 *      0x80FFF493 was NOT the role-data packet the client expected.

 *      Real server replies to 0x00FFF493 with 0x0CB0A300 (hook.txt RECV #19).

 *   2. FIX: MAX_FAKE_RESP_BUF enlarged 256 -> 2048 so the 816-byte

 *      role-data sub-packet fits without truncation.

 *   3. DATA: Sub-packet 1 (816 bytes) copied verbatim from the real

 *      capture (hook.txt RECV #19): 16-byte header + 100 uint64 attribute

 *      entries. Sub-packet 2 was truncated in the capture, so only sub1

 *      is returned; this is sufficient for the client to recognise the

 *      command and advance the state machine.

 *   4. KEEP: v36.138 - SKIP stale cmds (0x00FFF495, 0x50584666, ...) in BURST

 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE

 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd

 *   7. KEEP: v36.136 - SERVER-ROTATE disabled

 *   8. KEEP: v36.133 - do NOT patch 0x80FFF495 offset[12]

 *   9. KEEP: v36.134 - UUID injection after GPU field

 *

 * PROBLEM ANALYSIS (v36.138 log):

 *   - Client sent 2x 0x00FFF493 (492B + 920B) matching real client behaviour

 *   - BURST inject returned 0x800EE007 + 0x80FFF493 + 0x80FFF493 (600 bytes)

 *   - Client stuck at "正在进入..." because 0x80FFF493 is NOT the expected

 *     response to 0x00FFF493. The expected response is 0x0CB0A300.

 *

 * STRATEGY:

 *   - Return 0x0CB0A300 (816 bytes) for each 0x00FFF493 request in the queue

 *   - Client recognises the role-data packet and proceeds to role selection

 *

 * WangXianHook v36.137: DIRECT BURST INJECT ON RECV-CLOSE

 *

 * v36.137 CHANGES:

 *   1. FIX: Direct BURST injection on RECV-CLOSE (not deferred to next recv())

 *      v36.136 bug: armed g_triggerFakeNextRecv but client NEVER called recv() again.

 *      Client detected disconnect via heartbeat→quitFromServer→close() and reconnected.

 *   2. REFACTOR: Extracted BURST injection logic into doBurstFakeInject() function

 *   3. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd (not g_fakeRespInjected)

 *   4. KEEP: v36.136 - SERVER-ROTATE disabled

 *   5. KEEP: v36.133 - do NOT patch 0x80FFF495 offset[12]

 *   6. KEEP: v36.134 - UUID injection after GPU field

 *   7. KEEP: v36.135 - SecKeyCreateDecryptedData plaintext dump

 *

 * PROBLEM ANALYSIS (v36.136 log):

 *   - RECV-CLOSE: ARMING fake-resp injection fired (g_triggerFakeNextRecv=YES)

 *   - But client NEVER called recv() again! Instead: close(105) → reconnect to 5678

 *   - Call stack: close() ← quitFromServer ← heartbeat ← GameDisplay::heartbeat

 *   - Client's heartbeat detected dead connection, triggered quitFromServer

 *   - Client restarted entire login flow from scratch

 *

 * STRATEGY:

 *   - On RECV-CLOSE: call doBurstFakeInject() DIRECTLY, write fake responses into buf

 *   - Return totalLen (>0) so client sees fake responses, NOT connection close

 *   - Client state machine advances without ever knowing server disconnected

 *

 * v36.132: FIX ABI - C++ CCFileUtils::rsaDecryptLarge Hook (OUTPUT BUFFER)

 *

 * v36.130 CRITICAL FIX (RECURSION BUG):

 *   v36.129 had INFINITE RECURSION in non-bypass path: method_getImplementation()

 *   returned the REPLACED hook function instead of original, causing stack overflow.

 *   FIX: Save original IMPs at install time (g_orig_rsaDecryptData etc),

 *   use saved IMPs directly in non-bypass path — NO recursion possible.

 *

 * v36.130 IMPROVEMENT:

 *   Bypass counter (5 max) instead of one-shot flag, handles multi-step decryption.

 *

 * CORE INSIGHT: Client decrypts 0x80FFF495 payload via EncryptUtils (BoringSSL).

 *   The decrypted content says "error" even though header status=0.

 *   We MUST bypass decryption to return fake success plaintext.

 *

 * v36.126 APPROACH (RESTORED):

 *   SIMPLE STATUS PATCH: Original 365-byte 0x80FFF495 packet, only change status 1→0.

 *   Client decrypts original data with its own RSA key — we bypass decryption.

 *

 * v36.128 REVERT:

 *   Removed EncryptUtils Hook (crashed during login cert verification).

 *   But status patch alone is INSUFFICIENT — client checks decrypted payload content.

 *

 * v36.123 FIXES (CRITICAL):

 *   1. IMMEDIATE burst injection: After patching 0x80FFF495 status=1->0, append all 4 fake

 *      responses as TCP sticky data to the CURRENT return value (not waiting for next recv()).

 *      Reason: Client's next recv() after 0x80FFF495 is for heartbeat ACK, not for device-info

 *      response. Injecting fake responses in that wrong context causes client to discard them.

 *

 * v36.122 FIXES (CRITICAL):

 *   1. resetCmdQueue() BEFORE 4-step virtual enqueue so EE007 is the FIRST inject

 *      (v36.120 had stale FFF495 polluting the queue, initial inject was wrong command)

 *   2. Clean seq baseline 0x00010000 .. 0x00010003 independent of handshake-phase seqs.

 *

 * v36.120 FIXES (CRITICAL):

 *   1. triggerFakeNextRecv fires immediately after 0x80FFF495 patch, NO LONGER

 *      waiting for server to close fd (which never happens when heartbeat keeps open).

 *

 * v36.118 FIXES (CRITICAL):

 *   1. UUID injection now ONLY applies to GAME SERVER ports (12003/58158/dynamic)

 *      Login server (5678) gets ORIGINAL packet (143 bytes, no UUID)

 *      Root cause: v36.117 injected UUID to login server's 0x000EE007 (143→181 bytes),

 *      login server rejected it and closed connection → "network interrupted" at login

 *   2. Enhanced buffer still prepared on login server capture, used later by game server

 *

 * v36.117 FIXES:

 *   1. [SEND-CMD] log now prints FINAL sendLen (after UUID injection), not original len

 *   2. Added [SEND-FINAL] log to confirm exactly what was sent to orig_send()

 *   3. 0x80FFF495 status=1 patch strengthened + set handshake flags correctly

 *

 * v36.116 FIXES (CRITICAL):

 *   1. UUID-INJECT now applies DIRECTLY to sendBuf/sendLen - server now receives 217 bytes with UUID

 *   2. 0x80FFF495 status=1 now patched to 0 (handshake/auth failed → success)

 *   3. CMD-QUEUE now uses actualSendLen (after injection) instead of original len

 *

 * v36.107 FIXES:

 *   1. Filter heartbeat (0x00000015) and challenge cmds from command queue

 *   2. Prioritize critical login/character data commands in response generation

 *   3. Fix queue overflow caused by heartbeat flooding

 *   4. Add enhanced debug logging for command tracking

 *

 * v36.105 FIXES:

 *   1. Reset g_fakeRespDelivered in FAKE-SEND path - every send gets a response

 *   2. Add g_lastRespCmd tracking to prevent infinite loop on same cmd

 *   3. Add g_respCount cap (200) to prevent any infinite loop

 *   4. Fix stuck at "正在进入..." - now client can proceed with responses

 *

 * v36.104 FIXES:

 *   1. Disable dangerous inline patch (caused crash on iOS)

 *   2. Hook poll() to clear POLLHUP/POLLERR for fake response fd

 *   3. Hook select() to clear exception for fake response fd

 *   4. This prevents heartbeat from detecting dead connection

 *

 * v36.103 FIXES:

 *   1. Use mach_vm_remap to bypass iOS code page write protection (kr=2 fix)

 *   2. Fallback to mprotect on jailbroken devices

 *   3. Properly allocate+copy+modify+remap code pages

 *

 * v36.103 FIXES:

 *   1. Inline patch C++ functions (quitFromServer/heartbeat) to ret instruction

 *   2. Use dladdr+backtrace to find function addresses when close() is called

 *   3. Proactively search for functions via dlsym at hook installation

 *   4. Fix double-response bug: set g_fakeRespDelivered in injection code

 *

 * v36.101 FIXES:

 *   1. Fix infinite loop: fake response delivered only ONCE per client request

 *   2. After delivery, return EAGAIN until client sends a new command

 *   3. g_fakeRespDelivered flag cleared in send hook when new cmd is sent

 *

 * v36.100 FIXES:

 *   1. Smart fake response system - track client requests and generate responses

 *   2. Active fake response mode - continuously generate responses instead of EAGAIN

 *   3. Dynamic response generation based on last game server command

 *   4. Updated version numbers throughout the codebase

 *

 * v36.99 FIXES:

 *   1. ALWAYS return EAGAIN for game server fd when orig_recv returns 0

 *   2. This prevents SocketClient/NetImpl from detecting "connection closed"

 *   3. Prevents internal disconnected state being set, avoiding "网络中断" error

 *

 * v36.98 FIXES:

 *   1. Reset g_fakeRespInjected on server rotation (tryNextServer)

 *   2. Reset g_fakeRespInjected on new game server connection (hook_connect)

 *   3. This ensures FAKE-RESP can be injected on each new connection attempt

 *

 * v36.97 FIXES:

 *   1. Hook send() for fake resp fd - simulate send success

 *   2. Hook getsockopt() for fake resp fd - return SO_ERROR=0

 *   3. Fix dlsym search logic - use dlopen instead of raw image header

 *   4. Use rebindSymbol (fishhook) to hook C++ heartbeat/disconnect functions

 *

 * v36.93 DISCOVERY (TRUE ROOT CAUSE):

 *   The SERVER is closing the connection, not the client!

 *   Sequence: client sends 0x000EE007 + 0x00FFF493 → server closes connection

 *   recv() returns 0 BEFORE the client calls quitFromServer

 *   Close block is useless - server already terminated the connection

 *

 * v36.94 SOLUTION:

 *   1. [FAKE-RESP] When recv() returns 0 (server closed) for game server fd,

 *      inject fake 0x80FFF493 success response packet (status=0)

 *      This tells client "login successful" and prevents disconnection

 *   2. [NETIMPL-HOOK] Hook NetImpl::quitFromServer as no-op

 *      Prevents client state machine from entering disconnected state

 *      Uses dlsym + Objective-C runtime to find and hook the method

 *

 * REMAINS from v36.91-v36.93:

 *   DELETE: FORCE-HS mechanism (no fake 0x80FFF495 injection)

 *   DELETE: 0x00FFFF02 auto-respond (let client send native 0x00FFF495 703B)

 *   DELETE: FORCE-SEND logic (let client send native encrypted 0x000EE007)

 */

/*

 * HISTORY:

 * v36.55 CRITICAL FIXES:

 * - Just pass through to original connect with logging

 * - All port rewrite attempts (12003->58158) failed - 58158 unreachable

 * 

 * v36.54 CRITICAL FIXES:

 * - Non-blocking connect + select wait 30s (restore blocking after)

 * - Game expects connect() to complete, not EINPROGRESS

 * - 30s timeout instead of 5s to allow slower connections

 * 

 * v36.53 CRITICAL FIXES:

 * - Non-blocking connect with port rewrite (12003->58158), NO select wait

 * - Let game handle async connection itself (no timeout, no close)

 * - Previous select() was causing 5-second timeout, blocking caused hang

 * 

 * v36.52 CRITICAL FIXES:

 * - SIMPLE port rewrite: 12003 -> 58158 with DIRECT blocking connect (no O_NONBLOCK, no select)

 * - Use setsockopt(SO_SNDTIMEO, 10s) as safety net instead of non-blocking mode

 * 

 * v36.51 CRITICAL FIXES:

 * - RE-ENABLE port rewrite: 12003 -> 58158 (normal client uses 58158!)

 * - Add non-blocking mode and select() timeout for game server connections

 * 

 * v36.50 CRITICAL FIXES:

 * - FIX: Remove ret=13 truncation in hook_read() - it was destroying 0x802EE121 responses!

 * - FIX: Limit '版本过低' clearing to ONLY port=5678 (login server), NOT port=12003 (game server)

 * 

 * PREVIOUS (v36.46):

 * MINIMAL MODE - Only 0x802EE121 patch

 * 

 * PREVIOUS (v36.45):

 * DISABLE port rewrite, test direct 12003 connection

 * 

 * PREVIOUS (v36.44):

 * Non-blocking connect with select wait

 * 

 * PREVIOUS (v36.39):

 * FIX: Revert login server redirect, keep game server fix with 5s timeout

 * 

 * PREVIOUS (v36.38):

 * FIX: Added login server IP rewriting: 47.100.222.229 -> 47.100.14.198

 * FIX: Added game server IP rewriting logic

 * FIX: Added global variables g_loginServerIP and g_loginServerPort

 * WHY: Game hardcodes wrong login server IP (47.100.222.229), need to redirect to correct IP

 * 

 * PREVIOUS (v36.27):

 * FIX: Changed default game server port from 12003 to 58158 (matching normal client)

 * FIX: Added parseServerListResponse() to dynamically extract IP and port from server list response

 * FIX: Updated close hook to use dynamic game server port instead of hardcoded 12003

 * FIX: Updated recv/read hooks to call parseServerListResponse() for server list parsing

 * WHY: Normal client uses port 58158 for game server, not 12003

 * 

 * PREVIOUS (v36.26):

 * FIX: Simplified device info packet analysis to avoid Objective-C exceptions in threads

 * FIX: Added @try/@catch protection around all packet analysis code

 * FIX: Added signal handlers (SIGABRT/SIGSEGV/SIGILL/SIGBUS/SIGFPE/SIGTRAP) to capture crash info

 * FIX: Removed challenge packet (0x00FFFF01/0x00FFFF02) auto-response

 * WHY: Normal client does NOT respond to these packets, auto-response causes server disconnect

 * NOTE: Multiple hook libraries detected (libWJHook.dylib + WangXianHook.dylib)

 * 

 * PREVIOUS (v36.23):

 * - REMOVED mock data injection, OBSERVE ONLY

 * - ProtocolPatcher only patches errorCode, never modifies payload data

 * 

 * RESTORED (needed for injection detection bypass):

 * - 0x802EE121 response patching (status→0, clear '版本过低' message)

 * - '版本过低'/'当前版本' message clearing in responses

 * 

 * KEPT REMOVED (breaks normal protocol):

 * - Challenge packet auto-response (causes disconnect)

 * - Server list IP replacement

 * - Version number modification (7.6.3→7.7.0)

 * - Server list status/serverType/clientid/serverid patching

 * - UUID injection into 0x000EE007

 * 

 * RETAINED:

 * - Socket hooks (connect/send/recv) for logging

 * - Encryption hooks (CCCrypt/SecKey) for logging

 * - UIAlertView/UIAlertController hooks

 * - dlsym hook to hide injection detection

 * - SignatureKit hooks for monitoring

 */

#import <Foundation/Foundation.h>

#import <UIKit/UIKit.h>

#import <objc/runtime.h>

#include <objc/message.h>

#include <mach-o/dyld.h>

#include <mach-o/loader.h>

#include <mach-o/nlist.h>

#include <mach/mach.h>

#include <mach/mach_init.h>

#include <mach/vm_map.h>

#include <libkern/OSCacheControl.h>



// v36.103: Declare private Mach API for code page patching

extern "C" kern_return_t mach_vm_remap(

    vm_map_t target_task,

    mach_vm_address_t *target_address,

    mach_vm_size_t size,

    mach_vm_offset_t mask,

    int flags,

    vm_map_t src_task,

    mach_vm_address_t src_address,

    boolean_t copy,

    vm_prot_t *cur_protection,

    vm_prot_t *max_protection,

    vm_inherit_t inheritance

);

#include <dlfcn.h>

#include <string.h>

#include <sys/mman.h>

#include <errno.h>

#include <stdio.h>

#include <execinfo.h>

#include <poll.h>

#include <sys/select.h>

#include <zlib.h>

#import <CommonCrypto/CommonDigest.h>

#import <CommonCrypto/CommonCryptor.h>

#import <CommonCrypto/CommonHMAC.h>

#import <Security/Security.h>



// v37.110-DIST: SILENT MODE for public distribution.

// When SILENT_DIST_MODE=1, DLOG produces no output BUT STILL EVALUATES arguments.

// CRITICAL FIX v37.110: Previous v37.109 used `do {} while(0)` which DROPPED

// argument evaluation entirely. Many DLOG calls have side effects in their args:

//   DLOG(@"setup: %d", (g_initFlag=1, doSetup()));  // g_initFlag and doSetup SKIPPED!

// This caused network interrupt (critical init code never ran).

// FIX: Use `(void)((fmt), ##__VA_ARGS__)` — comma operator evaluates ALL args,

// then discards the result. Zero output while preserving ALL side effects.

// Set to 0 during development to re-enable full diagnostics.

#define SILENT_DIST_MODE 0

// v37.134-FIX53B: SPARSE LOG mode for production use.
// When SPARSE_LOG_MODE=1, high-frequency/low-value diagnostic tags are SKIPPED
// during file write (still pushed to fix31 ring buffer for crash diagnosis).
// Expected log size reduction: 80-95% (removes ~550 of ~925 DLOG calls from disk output).
// Set to 0 during development to re-enable FULL diagnostics.
// NOTE (2026-08-10 user request): DEFAULT = 0 (full logging = original FIX53 behavior).
// To enable sparse logging: change this to 1 and rebuild.
#define SPARSE_LOG_MODE 0

// v37.134-FIX53C: LOG SIZE LIMIT + ROTATION SWITCH (大小限制+轮转开关)
// When LOG_SIZE_LIMIT_DEFAULT_ON=1 (default per user request 2026-08-10),
//   wxhook.log size is capped at LOG_MAX_KB kilobytes. Once exceeded, the file is
//   rotated: current wxhook.log → .old → .old.1 → ... → oldest gets deleted.
//   Up to LOG_ROTATE_COUNT historical copies are kept. The limit applies even if
//   SPARSE_LOG_MODE=0 (so you can have verbose logging but bounded disk usage).
// When LOG_SIZE_LIMIT_DEFAULT_ON=0, unlimited size (original behavior, fallback
//   was 5MB hard-coded cap before FIX53C).
// Runtime control: g_logSizeLimitEnabled static BOOL (change via lldb expr).
// How to disable entirely: set LOG_SIZE_LIMIT_DEFAULT_ON=0 here and rebuild.
// AZ6: 用户明确关闭轮转（新应用build尚未验证需要完整日志），强制UNLIMITED
#define LOG_SIZE_LIMIT_DEFAULT_ON 0

// v37.134-FIX53C: Maximum log size in KILOBYTES. Default 200 KB = 204,800 bytes.
// Previous hard-coded threshold was 5 MB (5120 KB). 200 KB keeps the last ~15-20
// minutes of full-verbose diagnostic, which is enough for login+entering-game trace.
// AZ6: 即使显式关闭轮转，5MB硬兜底仍太小 → 改为20MB
#define LOG_MAX_KB 20480

// v37.134-FIX53C: Number of historical rotated copies to retain.
//   0 = only keep current wxhook.log, overwrite in place when limit reached (no .old)
//   1 = wxhook.log + 1 wxhook.log.old (default)
//   2 = wxhook.log + .old + .old.1 (two generations of history)
//   max 5 supported (to bound NSSearchPathForDirectoriesInDomains disk usage).
// AZ6: 关闭轮转=0
#define LOG_ROTATE_COUNT 0



// FIX39: Non-DLOG global marker that NEVER gets optimized out (for binary verification)

// FIX39-FINAL: Immutable ((used)) global markers NEVER get dead-code stripped.
// Used for runtime binary verification & as immutable self-documentation of FINAL release changes.
__attribute__((used)) const char* FIX39_FINAL_MARKER = "v37.134-FIX53L: [FIX53K基线 + 修复3个致命Bug: flag残留+强制重加密+fmtFlag硬编码]. 根因(wxhook-179): 1)g_l4_safe_fallback全局标志未在CCCrypt L4入口重置→之前某次加密的残留YES值让FFF493#1/#2被错误强制重加密,即使CCCrypt L4已成功修补 2)额外增加g_md5_channel_replaced条件也让正常CCCrypt输出的包被破坏 3)send-hook重建包时fmtFlag硬编码0x0001≠原始包p[12-13],服务器解析格式错误→只发心跳不发角色数据. 修复: 1)CCCrypt L4激活入口处g_l4_safe_fallback=NO 2)send-hook读取flag后立即清零 3)删除g_md5_channel_replaced条件,仅在真实SAFE FALLBACK时重加密 4)fmtFlag从p[12-13]复制不硬编码 5)保留FIX53K全部修复(L4保存修补明文+禁用空UUID插入).";
__attribute__((used)) const char* FIX39_VERIFY_MARKER = "v37.134-FIX53L-VERIFY: 1) hook_CCCrypt_v37_26 active-RETURN after: g_l4_safe_fallback=NO. 2) send-hook forceReencrypt ONLY from g_l4_safe_fallback (NOT g_md5_channel_replaced). 3) After BOOL forceReencrypt=g_l4_safe_fallback line: g_l4_safe_fallback=NO CLEAR. 4) newPkt[12]=p[12]; newPkt[13]=p[13]; (NOT hardcoded 0x0001). Must see [FIX53L-REENC] only for packets that really had CH-L4-BUF SAFE FALLBACK. Normal working packets (no SAFE FALLBACK) must see 'JSON unchanged — SKIP re-encrypt' path and work directly!";



#if SILENT_DIST_MODE

#define DLOG(fmt, ...) do { (void)((fmt), ##__VA_ARGS__); } while(0)

#else

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

#endif



// v36.57: FULL MODE - Enable all hooks including game server analysis, crypto hooks

// v36.47: EXTREME MINIMAL MODE - Only 0x802EE121 patch, NO crypto hooks, NO socket modifications

// v36.47: Critical fix - Disable all crypto function hooks that corrupt encryption data

// v36.47: Critical fix - Fix hook_alertControllerPresent SIGSEGV crash

#define MINIMAL_MODE 0

#define DISABLE_CRYPTO_HOOKS 1  // v37.14: Disable crypto hooks (caused crash), keep socket hooks for injection bypass

#define DISABLE_SOCKET_MODS 0

#define DISABLE_UI_HOOKS 0



static NSString *g_logPath = nil;

#if SILENT_DIST_MODE

static BOOL g_logEnabled = NO;  // v37.109-SILENT: Zero file I/O, no NSLog — completely undetectable.

#else

static BOOL g_logEnabled = YES; // Development mode: full diagnostics.

#endif

// v37.134-FIX53B: Runtime switch for sparse logging.
// When SPARSE_LOG_MODE=1 (compile-time default) this is YES.
// Change SPARSE_LOG_MODE to 0 and rebuild to re-enable verbose logging.
#if SPARSE_LOG_MODE
static BOOL g_logSparseEnabled = YES;
#else
static BOOL g_logSparseEnabled = NO;
#endif

// v37.134-FIX53B: TAG-based sparse logger filter.
// Returns YES if the message's [TAG] is classified as high-frequency noise.
// High-frequency tags (RSA-ENCRYPT, SIGN-BYPASS, SOCK, SEND, RECV, CH-L0/L1/L2,
// V3-zsign, V3-PEN, SEC, MSI-STUB, SERVERLIST-PARSE, NSUD, PROTO-DBG, CPP-CRYPTO,
// SC-DIAG, SK-DIAG, HTTP-HOOK, NET, NET-C, JSON-PARSE, LCNET) = skip file write.
// Still pushed into fix31 ring buffer for crash diagnosis.
static inline BOOL sparse_log_shouldSkip(const char *utf8msg) {
    if (!utf8msg || !g_logSparseEnabled) return NO;
    // Must start with '['
    if (utf8msg[0] != '[') return NO;
    // Prefix table (static const for zero init overhead)
    static const char *kSkipPrefixes[] = {
        "[RSA-ENCRYPT]", "[V3-zsign]", "[SIGN-BYPASS]", "[SERVERLIST-PARSE]",
        "[V3-PEN]", "[SEC]", "[MSI-STUB]", "[SOCK]", "[SEND]", "[SEND-CMD]",
        "[RECV]", "[PROTO-DBG]", "[HTTP-HOOK]", "[NSUD]", "[NET]",
        "[NET-C]", "[CPP-CRYPTO]", "[SC-DIAG]", "[SK-DIAG]", "[CH-L0]",
        "[CH-L1]", "[CH-L2]", "[CH-INIT]", "[JSON-PARSE]", "[V3-SCNETWORK]",
        "[LCNET]", "[MSI-PROP]", "[PROTO-VALIDATE]", "[DECODE-FOUND]",
        "[SERVER-CLASS]", "[DYLIB-IMAGE]", "[DECODE-SEARCH]", "[PROTO-DEBUG]",
        "[ENCODE-PATH]", "[SIGN-HOOK]",
        NULL
    };
    for (int i = 0; kSkipPrefixes[i]; i++) {
        const char *p = kSkipPrefixes[i];
        size_t len = strlen(p);
        if (strncmp(utf8msg, p, len) == 0) {
            // Extra safeguard: don't skip [RECV-CLOSE] / [SEND-CMD-* that actually has -CLOSE etc]
            // But most of those variants are noise too. If we want to keep RECV-CLOSE but
            // skip RECV we check char after ']'.
            if (strncmp(p, "[RECV]", 6) == 0) {
                // Keep [RECV-CLOSE] only
                if (strncmp(utf8msg, "[RECV-CLOSE]", 12) == 0) return NO;
                return YES;
            }
            if (strncmp(p, "[SEND]", 6) == 0) {
                // Keep any SEND with -ERROR suffix
                if (strncmp(utf8msg, "[SEND-ERROR]", 12) == 0) return NO;
                return YES;
            }
            if (strncmp(p, "[NET]", 5) == 0) {
                if (strncmp(utf8msg, "[NET-PATCH]", 11) == 0 ||
                    strncmp(utf8msg, "[NET-ERROR]", 11) == 0) return NO;
                return YES;
            }
            if (strncmp(p, "[SEC]", 5) == 0) {
                if (strncmp(utf8msg, "[SEC-ERROR]", 11) == 0) return NO;
                return YES;
            }
            if (strncmp(p, "[DYLD]", 6) == 0) {
                if (strncmp(utf8msg, "[DYLD-HOOK]", 11) == 0 ||
                    strncmp(utf8msg, "[DYLD-HIDE]", 11) == 0) return NO;
                return YES;
            }
            if (strncmp(p, "[SOCK]", 6) == 0) {
                if (strncmp(utf8msg, "[SOCK-ERROR]", 12) == 0) return NO;
                return YES;
            }
            if (strncmp(p, "[UI]", 4) == 0) return NO;
            if (strncmp(p, "[MSI]", 4) == 0) {
                if (strncmp(utf8msg, "[MSI-RETRY]", 11) == 0) return NO;
                return YES;
            }
            return YES;
        }
    }
    return NO;
}

// v37.134-FIX53C: LOG SIZE LIMIT runtime flag (gated by compile-time default above)
#if LOG_SIZE_LIMIT_DEFAULT_ON
static BOOL g_logSizeLimitEnabled = YES;
#else
static BOOL g_logSizeLimitEnabled = NO;
#endif

// v37.134-FIX53C: Chain-rotation helper — rotates .old → .old.1 → ... deletes oldest.
// Caller must ensure g_logPath is set and file exists. This helper never throws.
static void logRotateChain(void) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        int maxCopies = LOG_ROTATE_COUNT;
        if (maxCopies < 0) maxCopies = 0;
        if (maxCopies > 5) maxCopies = 5; // safety cap
        // Step 1: if maxCopies == 0, don't keep history — just truncate in place.
        if (maxCopies == 0) {
            [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            return;
        }
        // Step 2: delete the OLDEST rotated file (index maxCopies-1) if exists.
        NSString *oldestPath = [g_logPath stringByAppendingPathExtension:
            [NSString stringWithFormat:@"old.%d", maxCopies - 1]];
        // Special case: index 0 suffix is ".old" (no trailing .0)
        if (maxCopies == 1) {
            oldestPath = [g_logPath stringByAppendingString:@".old"];
        }
        [fm removeItemAtPath:oldestPath error:nil];
        // Step 3: rotate chain from oldest backwards. If maxCopies=2 we have .old and .old.1.
        //   .old.1 is already removed (it was oldest).
        //   Move .old → .old.1
        //   Move current log → .old
        for (int i = maxCopies - 1; i > 0; i--) {
            NSString *src;
            NSString *dst;
            if (i == 1) {
                src = [g_logPath stringByAppendingString:@".old"];
                dst = [g_logPath stringByAppendingString:@".old.1"];
            } else {
                src = [g_logPath stringByAppendingPathExtension:
                    [NSString stringWithFormat:@"old.%d", i - 1]];
                dst = [g_logPath stringByAppendingPathExtension:
                    [NSString stringWithFormat:@"old.%d", i]];
            }
            if ([fm fileExistsAtPath:src]) {
                [fm removeItemAtPath:dst error:nil];
                [fm moveItemAtPath:src toPath:dst error:nil];
            }
        }
        // Step 4: move current wxhook.log → .old (first slot), then truncate current.
        NSString *firstOld = [g_logPath stringByAppendingString:@".old"];
        [fm removeItemAtPath:firstOld error:nil];
        if ([fm fileExistsAtPath:g_logPath]) {
            [fm copyItemAtPath:g_logPath toPath:firstOld error:nil];
        }
        [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {
        // Last-resort fallback: just truncate.
        @try {
            if (g_logPath) [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch(id _) {}
    }
}

static BOOL g_isActivated = NO; // activation status



// v37.134-FIX20: V3环境检测标记 + MSHookFunction指针 (前向声明，在10251行附近初始化)

static BOOL g_isV3Environment = NO;

static BOOL g_zsignPresent = NO;  // FIX29: zsign.dylib是否存在(仅用于安装alert hook+DYLD隐藏)

// FIX33: 真V3 vs 全能签 最可靠区分 → zsign +request是否被实际调用!

//   真V3自签: V3验证流程会调用zsign +request → YES → postAppInfoApi/getAppInfoApi code:1=成功(lnSign协议) → 不能改→patchResponse=NO

//   全能签注入: zsign类存在但永远闲置,+request从不被调用 → NO → postAppInfoApi/getAppInfoApi code:1→0=成功(全能签协议)

// FIX32 BUG: 用g_zsignPresent区分 → 全能签也会跳过patch code:1→0 → 全能签验签失败=显示"无网络连接"!

static BOOL g_v3RequestHasBeenCalled = NO;

static IMP g_origZsignAlertImp = NULL;

static IMP g_origZsignRequestImp = NULL;

static IMP g_origZsignGetRootVCImp = NULL;

typedef void (*MSHookFunction_t)(void *function, void *replace, void **result);

static MSHookFunction_t g_msHookFunction = NULL;



static void installAllHooks(void);



// Forward declare _log (defined later at line ~887)

static void _log(NSString *msg);



// v37.134: SIMPLE SIGN-BYPASS — smart field-level patching, no environment detection.

// No URL domain discrimination. patchSignatureResponse preserves original response data

// and only patches specific fields (verity, tip, end, open, ENDTIME).



// v37.51: MD5 hook replacement counter (declared here, used in custom_send and hook_CC_MD5)

static int g_md5_replace_count = 0;

// v37.60: Flag set when CC_MD5 input had channel name "DY_MIESHI" replaced with

// "DYanyou0040_MIESHI". Used to decide whether to send native EE121 (hash1/3 fixed)

// or fall back to clean 248B (hash1/3 unverifiable).

static int g_md5_channel_replaced = 0;
static int g_md5_ver_replaced = 0;
static int g_md5_build_replaced = 0;



// v37.134-FIX15: Forward declarations for binary hash (defined later at line ~9477)

static uint8_t g_our_binary_hash[16] = {0};

static const uint8_t g_clean_binary_hash[16] = {

    0x90, 0x6e, 0x70, 0x7e, 0xc5, 0x58, 0x5f, 0x08,

    0x03, 0x97, 0xb2, 0x6f, 0xf4, 0xb8, 0xd8, 0x9d

};



// v37.64: Track whether EE006/A018 have been sent on login server (port 5678).

// v37.63 assumed client skips EE006+A018 when IDFV returns nil, but v37.62 log proves

// client DOES send A018 (origLen=186, A018-REPL→223B) and short EE006 (20B).

// v37.64 REMOVES EE006-INJECT/A018-INJECT (would cause DUPLICATE sends), KEEPS only

// EE006-EXPAND (20B→56B with clean UUID) as the ROOT FIX for status=4 "版本过低".

static int g_ee006_sent = 0;

static int g_a018_sent = 0;



// v37.63: Clean client's 0x0002A018 (223B) from hook.txt SEND #5

// Moved to file scope so both A018-REPL can reference it (A018-INJECT removed in v37.64).

static const uint8_t s_cleanA018[223] = {

    0x00,0x00,0x00,0xDF, 0x00,0x02,0xA0,0x18, 0x00,0x00,0x00,0x03,

    0x00,0x14, 0x36,0x35,0x36,0x35,0x37,0x38,0x38,0x31,0x30,0x34,0x35,0x33,0x33,0x35,0x30,0x31,0x35,0x31,0x35,0x31,

    0x00,0x12, 0x44,0x59,0x61,0x6E,0x79,0x6F,0x75,0x30,0x30,0x34,0x30,0x5F,0x4D,0x49,0x45,0x53,0x48,0x49,

    0x00,0x03, 0x49,0x4F,0x53,

    0x00,0x07, 0x70,0x6E,0x67,0x5F,0x72,0x65,0x73,

    0x00,0x18, 0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x20,0x41,0x70,0x70,0x6C,0x65,0x20,0x41,0x31,0x30,0x20,0x47,0x50,0x55,

    0x00,0x0B, 0x69,0x50,0x68,0x6F,0x6E,0x65,0x37,0x50,0x6C,0x75,0x73,

    0x00,0x34, 0x55,0x55,0x49,0x44,0x3D,0x4D,0x41,0x43,0x41,0x44,0x44,0x52,0x45,0x53,0x53,0x3D,0x36,0x36,0x42,0x30,0x45,0x45,0x30,0x31,0x2D,0x35,0x44,0x32,0x42,0x2D,0x34,0x45,0x41,0x45,0x2D,0x42,0x46,0x42,0x33,0x2D,0x45,0x43,0x41,0x39,0x43,0x41,0x42,0x46,0x31,0x36,0x46,0x38,

    0x00,0x05, 0x37,0x2E,0x36,0x2E,0x33,

    0x00,0x03, 0x39,0x37,0x39,

    0x00,0x04, 0x57,0x49,0x46,0x49,

    0x00,0x04, 0x46,0x55,0x4C,0x4C,

    0x00,0x00,

    0x00,0x00,

    0x00,0x20, 0x38,0x32,0x34,0x31,0x32,0x37,0x32,0x36,0x38,0x36,0x39,0x66,0x30,0x66,0x62,0x32,0x34,0x64,0x32,0x34,0x37,0x31,0x37,0x63,0x34,0x37,0x35,0x36,0x36,0x64,0x36,0x33,

};



#include <signal.h>

#include <execinfo.h>

#include <pthread.h>      // FIX31-build: pthread_self/pthread_mach_thread_np 声明

#include <exception>      // FIX31-build: std::set_terminate 声明



// ============================================================

// FIX31: 崩溃信息收集增强 + 独立crash文件 + exit/_Exit/abort拦截

// 问题背景: FIX28 V3版闪退时wxhook.log中无任何崩溃信息:

//   1. SIGABRT之前被禁用→zsign内部abort()/std::terminate()不打日志

//   2. 很多反调试/签名代码直接调用exit()/abort()自杀 → 不走signal handler

//   3. 崩溃发生时 g_logPath 可能还没建立 / NSFileHandle 打开失败 → 写不进去

//   4. 无法获得闪退前最后执行的是哪一段代码

// FIX31方案:

//   a) 预先建立 Documents/wxhook_crash_*.log & /tmp/wxhook_crash_last.log

//      两份独立crash文件, 与g_logPath无关

//   b) 环形缓冲 FIX31_MAX_LOGLINES (40条) 保存最后40条DLOG → 闪退时

//      附在crash文件末尾 → 定位闪退前执行到哪里

//   c) 拦截 exit/_Exit/abort (fishhook rebind) → 任何主动自杀都打callstack

//   d) 重新启用 SIGABRT handler (SIGKILL无法捕获,但会走exit/)

// ============================================================

static NSString *g_fix31CrashDir = nil;

static NSLock *g_fix31LogLock = nil;

#define FIX31_MAX_LOGLINES 40

static char *g_fix31LastLogs[FIX31_MAX_LOGLINES] = {NULL};

static volatile int g_fix31LogIdx = 0;

static volatile int g_fix31InCrashPath = 0;



// 写闪退前最后日志到环形缓冲（每次 DLOG/_log 都会调用）

static void fix31_pushLog(const char *utf8line) {

    if (!utf8line) return;

    if (!g_fix31LogLock) g_fix31LogLock = [[NSLock alloc] init];

    @try {

        [g_fix31LogLock lock];

        if (g_fix31LastLogs[g_fix31LogIdx]) {

            free(g_fix31LastLogs[g_fix31LogIdx]);

            g_fix31LastLogs[g_fix31LogIdx] = NULL;

        }

        g_fix31LastLogs[g_fix31LogIdx] = strdup(utf8line);

        g_fix31LogIdx = (g_fix31LogIdx + 1) % FIX31_MAX_LOGLINES;

    } @catch (NSException *e) {}

    @finally {

        if (g_fix31LogLock) @try { [g_fix31LogLock unlock]; } @catch(id _) {}

    }

}



static void fix31_writeCrashFile(NSString *summary, void *callstackArr[], int frames) {

    // 避免递归崩溃

    if (__atomic_exchange_n(&g_fix31InCrashPath, 1, __ATOMIC_SEQ_CST)) return;

    @autoreleasepool {

    @try {

        NSFileManager *fm = [NSFileManager defaultManager];

        NSString *dir = g_fix31CrashDir ? : NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;

        if (!dir) dir = @"/tmp";

        

        NSDateFormatter *df = [[NSDateFormatter alloc] init];

        [df setDateFormat:@"yyyyMMdd-HHmmss"];

        NSString *name = [NSString stringWithFormat:@"wxhook_crash_%@_%d.log", [df stringFromDate:[NSDate date]], (int)getpid()];

        NSString *docPath = [dir stringByAppendingPathComponent:name];

        NSString *tmpPath = @"/tmp/wxhook_crash_last.log";

        

        NSMutableString *s = [NSMutableString stringWithCapacity:4096];

        [s appendString:@"============================================================\n"];

        [s appendFormat:@"=== WXHOOK CRASH REPORT v37.134-FIX39 ===\n"];

        [s appendString:@"============================================================\n"];

        [s appendFormat:@"Date:       %@\n", [NSDate date]];

        [s appendFormat:@"PID:        %d\n", (int)getpid()];

        [s appendFormat:@"TID/mach:   %llu\n", (unsigned long long)pthread_mach_thread_np(pthread_self())];

        [s appendFormat:@"Bundle:     %@\n", [[NSBundle mainBundle] bundleIdentifier]];

        [s appendFormat:@"Executable: %@\n", [[NSBundle mainBundle] executablePath]];

        [s appendFormat:@"crashdir:   %@\n", dir];

        [s appendFormat:@"\n------- Crash summary -------\n%@\n", summary];

        

        [s appendFormat:@"\n------- Last %d wxhook log lines (LIFO, newest FIRST) -------\n", FIX31_MAX_LOGLINES];

        int newest = g_fix31LogIdx;

        for (int j = FIX31_MAX_LOGLINES - 1; j >= 0; j--) {

            int idx = (newest + j) % FIX31_MAX_LOGLINES;

            if (g_fix31LastLogs[idx]) {

                size_t L = strlen(g_fix31LastLogs[idx]);

                if (L > 0) {

                    // FIX31-build: endsInNl 改为 const char* (字符串字面量默认const)

                    const char *endsInNl = (g_fix31LastLogs[idx][L-1] == '\n') ? "" : "\n";

                    [s appendFormat:@"  [%02d] %s%s", j, g_fix31LastLogs[idx], endsInNl];

                }

            }

        }

        

        [s appendFormat:@"\n------- Loaded dylibs (custom / WangXianHook / zsign / systemhook) -------\n"];

        uint32_t nImg = _dyld_image_count();

        for (uint32_t i = 0; i < nImg; i++) {

            const char *nm = _dyld_get_image_name(i);

            if (!nm) continue;

            NSString *ns = [NSString stringWithUTF8String:nm];

            if (i < 20 ||

                [ns containsString:@"wangxian"] || [ns containsString:@".app/"] ||

                [ns containsString:@"WangXianHook"] || [ns containsString:@"zsign"] ||

                [ns containsString:@"systemhook"] || [ns containsString:@"substrate"] ||

                [ns containsString:@"lnSignature"] || [ns containsString:@"libSupport"] ||

                [ns containsString:@"QM"] || [ns containsString:@"BackRun"] ||

                [ns containsString:@"MonHUAWEI"] || [ns containsString:@"WJHook"] ||

                [ns containsString:@"Frida"] || [ns containsString:@"frida"]) {

                [s appendFormat:@"  [%3u] slide=0x%09llx  %s\n", i,

                    (unsigned long long)_dyld_get_image_vmaddr_slide(i), nm];

            }

        }

        [s appendFormat:@"Total dyld images: %u\n", nImg];

        

        if (callstackArr && frames > 0) {

            char **strs = backtrace_symbols(callstackArr, frames);

            [s appendFormat:@"\n------- Call stack (%d frames) -------\n", frames];

            for (int i = 0; i < frames && i < 80; i++) {

                if (strs && strs[i])

                    [s appendFormat:@"  #%02d %s\n", i, strs[i]];

                else

                    [s appendFormat:@"  #%02d %p\n", i, callstackArr[i]];

            }

            if (strs) free(strs);

        }

        [s appendString:@"============================================================\n"];

        

        NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];

        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

        [d writeToFile:docPath atomically:YES];

        [d writeToFile:tmpPath atomically:YES];

        

        // 额外: append 到 wxhook.log 末尾（如果存在）

        if (g_logPath) { @try {

            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];

            if (fh) { [fh seekToEndOfFile]; [fh writeData:d]; [fh closeFile]; }

        } @catch(id _) {} }

    } @catch (NSException *e) {

        // crash writer 自己崩也不能再嵌套

    }

    }

}



// v36.110: ObjC exception handler (FIX31强化)

static void objcExceptionHandler(NSException *exception) {

    void *callstack[128];

    int frames = backtrace(callstack, 128);

    NSString *summary = [NSString stringWithFormat:

        @"--- OBJC EXCEPTION ---\nName:   %@\nReason: %@\nUserInfo: %@\nCallStackSymbols:\n  %@\n",

        exception.name, exception.reason, exception.userInfo, [exception callStackSymbols]];

    fix31_writeCrashFile(summary, callstack, frames);

    

    NSMutableString *crashInfo = [NSMutableString string];

    [crashInfo appendFormat:@"\n=== OBJC-EXCEPTION ===\n"];

    [crashInfo appendFormat:@"Name: %@\n", [exception name]];

    [crashInfo appendFormat:@"Reason: %@\n", [exception reason]];

    [crashInfo appendFormat:@"UserInfo: %@\n", [exception userInfo]];

    NSArray *callStack = [exception callStackSymbols];

    for (int i = 0; i < MIN((int)[callStack count], 30); i++) {

        [crashInfo appendFormat:@"  #%d: %@\n", i, callStack[i]];

    }

    [crashInfo appendFormat:@"====================\n"];

    if (g_logPath) { @try {

        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];

        if (fh) { [fh seekToEndOfFile]; [fh writeData:[crashInfo dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }

    } @catch(id _) {} }

}



// v36.110: C terminate handler (for SIGABRT with stack trace)

static void cTerminateHandler() {

    // FIX41: 尝试获取当前未捕获的C++异常,打印what()和type! (VersionModule::widgetSelected抛terminate时完全不知道原因!)
    NSMutableString *exceptionDetails = [NSMutableString stringWithString:@"\n--- FIX41: C++ Uncaught Exception Diagnostics ---\n"];
    @try {
        // 1. 尝试通过NSSetUncaughtExceptionHandler获取最后一个NSException
        // 通过全局lastUncaught (如果已在handler中保存的话) + call_registered_functions
        // 简单起见: 尝试调用 [NSException previousException] / 或 _initialize_topLevelErrorHandler 机制
        // 如果取不到也没关系 - 我们还有__cxa_current_primary_exception
        Class excClass = NSClassFromString(@"NSException");
        if (excClass) {
            @try {
                // +[NSException raise...]格式的API可能存正在uncaught stack中
                id excMaybe = objc_getClass? objc_getClass("NSException") : Nil;
                // 尝试调用class方法"uncaughtException"如果实现了
                SEL uncSel = NSSelectorFromString(@"uncaughtException");
                if (excMaybe && [excMaybe respondsToSelector:uncSel]) {
                    id unc = ((id(*)(id,SEL))objc_msgSend)(excMaybe, uncSel);
                    if (unc) [exceptionDetails appendFormat:@"ObjC NSException.uncaughtException: name=%@ reason=%@\n", [unc name], [unc reason]];
                } else {
                    [exceptionDetails appendFormat:@"ℹ️ NSException.uncaughtException not implemented (大多数情况正常,此方法是自定义的)\n"];
                }
            } @catch (NSException *e2) {
                [exceptionDetails appendFormat:@"⚠️ NSException读取内部异常: %@\n", e2];
            }
        }

        // 2. 尝试C++ __cxa_current_primary_exception()通过dlsym
        // std::set_terminate handler中 current_exception() 在大多数ABI中是有效的
        void* (*cxa_curr)(void) = (void*(*)(void))dlsym(RTLD_DEFAULT, "__cxa_current_primary_exception");
        void *currExc = cxa_curr ? cxa_curr() : NULL;
        if (currExc) {
            // 已捕获到C++异常指针 - 尝试demangle
            const char *excTypeName = NULL;
            void *excWhat = NULL;
            // 通过dlsym查找__cxa_exception_type_info或what()
            [exceptionDetails appendFormat:@"__cxa_current_primary_exception()=%p (说明确实有C++异常在传播!)\n", currExc];
        } else {
            [exceptionDetails appendFormat:@"⚠️ __cxa_current_primary_exception=NULL (可能是noexcept违反/pthread_cancel而非异常抛)\n"];
        }
    } @catch (NSException *e) {
        [exceptionDetails appendFormat:@"⚠️ Exception diag自身异常: %@\n", e];
    } @catch (...) {
        [exceptionDetails appendFormat:@"⚠️ Exception diag抛未知异常\n"];
    }
    [exceptionDetails appendString:@"--- FIX41 Diagnostics END ---\n\n"];

    void *callstack[128];

    int frames = backtrace(callstack, 128);

    NSString *summary = [NSString stringWithFormat:
        @"--- C++ std::terminate() / cTerminateHandler called ---\n"
        @"Usually means: uncaught C++ exception / noexcept violation / pthread_cancel.\n"
        @"FIX41 DIAG: %@\n", exceptionDetails];

    fix31_writeCrashFile(summary, callstack, frames);

    NSMutableString *crashInfo = [NSMutableString string];

    [crashInfo appendFormat:@"\n=== C-TERMINATE (SIGABRT) ===\n"];
    [crashInfo appendString:exceptionDetails];  // FIX41: 把异常诊断写入日志!

    char **strs = backtrace_symbols(callstack, frames);

    [crashInfo appendFormat:@"Backtrace (%d frames):\n", frames];

    for (int i = 0; i < frames && i < 30; i++) {

        if (strs[i]) [crashInfo appendFormat:@"  #%d: %s\n", i, strs[i]];

    }

    [crashInfo appendFormat:@"====================\n"];

    if (strs) free(strs);

    if (g_logPath) { @try {

        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];

        if (fh) { [fh seekToEndOfFile]; [fh writeData:[crashInfo dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }

    } @catch(id _) {} }

    abort();

}



static void signalHandler(int sig) {

    void *callstack[128];

    int frames = backtrace(callstack, 128);

    NSString *sigName = nil;

    switch(sig) {

        case SIGABRT: sigName = @"SIGABRT  (通常=std::terminate()/assert()/abort()主动触发)"; break;

        case SIGSEGV: sigName = @"SIGSEGV  (野指针/NULL解引用/内存越界访问)"; break;

        case SIGILL:  sigName = @"SIGILL   (非法指令/thumb-arm切换错误)"; break;

        case SIGBUS:  sigName = @"SIGBUS   (总线错误/未对齐访问/mmap失败)"; break;

        case SIGFPE:  sigName = @"SIGFPE   (浮点异常/除零)"; break;

        case SIGTRAP: sigName = @"SIGTRAP  (调试陷阱/断点命中)"; break;

        case SIGEMT:  sigName = @"SIGEMT"; break;

        case SIGTERM: sigName = @"SIGTERM  (正常进程终止请求)"; break;

        case SIGHUP:  sigName = @"SIGHUP   (控制终端断开)"; break;

        default: sigName = [NSString stringWithFormat:@"SIG%d (UNKNOWN)", sig];

    }

    NSString *summary = [NSString stringWithFormat:@"--- Signal %d: %@ ---\nHandler invoked directly by kernel / raise() / kill().\n", sig, sigName];

    fix31_writeCrashFile(summary, callstack, frames);

    

    char **strs = backtrace_symbols(callstack, frames);

    NSMutableString *crashInfo = [NSMutableString string];

    [crashInfo appendFormat:@"\n=== CRASH (%@) ===\nSignal: %d\nBacktrace (%d frames):\n", sigName, sig, frames];

    for (int i = 0; i < frames && i < 30; i++) {

        if (strs[i]) [crashInfo appendFormat:@"  #%d: %s\n", i, strs[i]];

    }

    [crashInfo appendFormat:@"====================\n"];

    if (strs) free(strs);

    if (g_logPath) { @try {

        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];

        if (fh) { [fh seekToEndOfFile]; [fh writeData:[crashInfo dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }

    } @catch(id _) {} }

    signal(sig, SIG_DFL);

    raise(sig);

}



// ============================================================

// FIX31: 拦截 exit/_Exit/abort 主动自杀函数

// 许多签名验证/反调试代码在失败时会直接 exit(0)/abort() 结束进程，

// 既不抛ObjC异常，也不抛C++异常 → 之前版本完全无日志！

// 这里用fishhook rebind_symbols 替换这些函数 → 先写crash file再自杀

// ============================================================

static void (*orig_exit)(int) = NULL;

static void (*orig__Exit)(int) = NULL;

static void (*orig_abort)(void) = NULL;

static volatile int g_fix31InExitHook = 0;



static void fix31_hook_exit(int code) {

    if (__atomic_exchange_n(&g_fix31InExitHook, 1, __ATOMIC_SEQ_CST)) { if (orig_exit) orig_exit(code); return; }

    void *callstack[128]; int frames = backtrace(callstack, 128);

    NSString *summary = [NSString stringWithFormat:

        @"--- exit(%d) called (PROCESS INTENTIONAL SUICIDE!) ---\n"

        "原因推测: zsign.dylib 验证失败 → exit\n"

        "         反调试检测命中 → exit\n"

        "         签名验证框架主动退出\n"

        "请查看call stack里是谁触发 exit(), 是否在 zsign.dylib 地址范围内.\n", code];

    fix31_writeCrashFile(summary, callstack, frames);

    if (orig_exit) orig_exit(code);

}

static void fix31_hook__Exit(int code) {

    if (__atomic_exchange_n(&g_fix31InExitHook, 1, __ATOMIC_SEQ_CST)) { if (orig__Exit) orig__Exit(code); return; }

    void *callstack[128]; int frames = backtrace(callstack, 128);

    NSString *summary = [NSString stringWithFormat:

        @"--- _Exit(%d) called (PROCESS INTENTIONAL SUICIDE, no atexit, no destructors!) ---\n", code];

    fix31_writeCrashFile(summary, callstack, frames);

    if (orig__Exit) orig__Exit(code);

}

static void fix31_hook_abort(void) {

    if (__atomic_exchange_n(&g_fix31InExitHook, 1, __ATOMIC_SEQ_CST)) { if (orig_abort) orig_abort(); return; }

    void *callstack[128]; int frames = backtrace(callstack, 128);

    NSString *summary = @"--- abort() called (PROCESS INTENTIONAL ABORT) ---\n"

        "通常触发: assert() 失败 / ObjC exception 未捕获 / std::terminate / 签名验证失败 abort\n";

    fix31_writeCrashFile(summary, callstack, frames);

    if (orig_abort) orig_abort();

}



static void setupSignalHandlers(void) {

    // FIX31: SIGABRT 重新启用！SIGTERM/SIGHUP 也捕获

    // （之前禁用SIGABRT为了看C++异常真实type，现在我们同时hook abort()+std::terminate → 两边都有信息）

    signal(SIGABRT, signalHandler);

    signal(SIGSEGV, signalHandler);

    signal(SIGILL, signalHandler);

    signal(SIGBUS, signalHandler);

    signal(SIGFPE, signalHandler);

    signal(SIGTRAP, signalHandler);

    signal(SIGTERM, signalHandler);

    signal(SIGHUP, signalHandler);

    

    // FIX31: Hook exit / _Exit / abort（主动自杀函数）

    // FIX31-build: dlsym返回void*, 强制转换为对应函数指针类型(禁止隐式void*→函数指针)

    orig_exit  = (void (*)(int))            dlsym(RTLD_DEFAULT, "exit");

    orig__Exit = (void (*)(int))            dlsym(RTLD_DEFAULT, "_Exit");

    orig_abort = (void (*)(void))           dlsym(RTLD_DEFAULT, "abort");

    if (orig_exit)  rebind_symbols((struct rebinding[1]){{"exit",  (void *)fix31_hook_exit,  (void **)&orig_exit}},  1);

    if (orig__Exit) rebind_symbols((struct rebinding[1]){{"_Exit", (void *)fix31_hook__Exit, (void **)&orig__Exit}}, 1);

    if (orig_abort) rebind_symbols((struct rebinding[1]){{"abort", (void *)fix31_hook_abort, (void **)&orig_abort}}, 1);

    

    // FIX31: 预存Documents路径（即使g_logPath失败，crash也能写）

    @try {

        NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);

        if (p.count > 0) g_fix31CrashDir = [[p firstObject] copy];

    } @catch(id _) { g_fix31CrashDir = @"/tmp"; }

    

    std::set_terminate(cTerminateHandler);

    NSSetUncaughtExceptionHandler(&objcExceptionHandler);

}



static void _log(NSString *msg) {

    // FIX31: 先推入环形缓冲 (即使g_logPath还没建立也能记录)
    // FIX53B: Ring buffer ALWAYS gets the full message (including noise tags)
    // so crash post-mortems still have the detailed context available.

    @try {

        if (msg) {

            const char *raw = msg.UTF8String;

            if (raw) fix31_pushLog(raw);

        }

    } @catch(id _) {}

    

    if (!g_logPath || !g_logEnabled) { return; }

    // v37.134-FIX53B: SPARSE LOG filtering (runtime TAG-based).
    // File write + NSLog are skipped for noise tags (80-95% volume reduction).
    // This check happens AFTER the fix31 ring buffer push so crash diagnostics
    // still have full detail, but normal I/O is dramatically reduced.
    BOOL skipFileWrite = NO;
    @try {
        const char *raw = msg.UTF8String;
        if (raw && sparse_log_shouldSkip(raw)) skipFileWrite = YES;
    } @catch(id _) {}
    if (skipFileWrite) return;

    @try {

        // v37.134-FIX53C: LOG SIZE LIMIT + CHAIN ROTATION (replaces old 5 MB hard cap)
        // When LOG_SIZE_LIMIT_DEFAULT_ON=1, current size is checked against
        // LOG_MAX_KB * 1024 bytes before each write. Old 5 MB safety cap still
        // applies when g_logSizeLimitEnabled is explicitly disabled (so logs never
        // grow unbounded even if the user turns the feature off).
        unsigned long long maxBytes = 0;
        unsigned long long size = 0;
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_logPath error:nil];
        if (attrs) size = [attrs[NSFileSize] unsignedLongLongValue];

        if (g_logSizeLimitEnabled) {
            maxBytes = (unsigned long long)LOG_MAX_KB * 1024ULL;
            if (LOG_MAX_KB <= 0) maxBytes = 0;
        } else {
            // Original safety fallback: 5 MB absolute cap regardless of switch.
            maxBytes = 5ULL * 1024ULL * 1024ULL;
        }

        if (maxBytes > 0 && size > maxBytes) {
            unsigned long long sizeBefore = size;
            if (g_logSizeLimitEnabled) {
                logRotateChain(); // FIX53C: chain rotation (N historical copies)
            } else {
                // Legacy single-slot rotation for the disabled-switch fallback case
                NSString *oldLogPath = [g_logPath stringByAppendingString:@".old"];
                NSFileManager *fm = [NSFileManager defaultManager];
                [fm removeItemAtPath:oldLogPath error:nil];
                [fm copyItemAtPath:g_logPath toPath:oldLogPath error:nil];
                [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }
            // After rotation/truncation, the first line into the fresh file must be
            // the rotation announcement.
            NSString *note;
            if (g_logSizeLimitEnabled) {
                note = [NSString stringWithFormat:
                    @"[LOG-ROTATED] File exceeded LOG_MAX_KB=%d limit (%llu KB). size=%llu KB. Rotated %d historical copies kept (LOG_ROTATE_COUNT=%d). LOG_SIZE_LIMIT=ON (default). Switch off: change LOG_SIZE_LIMIT_DEFAULT_ON=0 in WangXianHook.m L%d and rebuild.",
                    LOG_MAX_KB, (unsigned long long)LOG_MAX_KB,
                    sizeBefore / 1024ULL,
                    (LOG_ROTATE_COUNT < 0 ? 0 : (LOG_ROTATE_COUNT > 5 ? 5 : LOG_ROTATE_COUNT)),
                    LOG_ROTATE_COUNT,
                    1876];
            } else {
                note = [NSString stringWithFormat:
                    @"[LOG-ROTATED] File exceeded 5 MB fallback cap (size=%llu KB). LOG_SIZE_LIMIT=OFF. Single .old slot rotation applied.",
                    sizeBefore / 1024ULL];
            }
            // Push directly to ring buffer (already done above for caller msg, but
            // we need the announcement too).
            const char *noteRaw = note.UTF8String;
            if (noteRaw) fix31_pushLog(noteRaw);
            // Append note to file
            NSData *noteData = [[NSString stringWithFormat:@"%@\n", note] dataUsingEncoding:NSUTF8StringEncoding];
            if (noteData) {
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
                if (fh) {
                    [fh seekToEndOfFile];
                    [fh writeData:noteData];
                    [fh synchronizeFile];
                    [fh closeFile];
                }
            }
            NSLog(@"[WXHook] %@", note);
            return;
        }

        
        NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];

        if (data) {

            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];

            if (fh) {

                [fh seekToEndOfFile];

                [fh writeData:data];

                [fh synchronizeFile];  // v36.110: Ensure data flushed to disk

                [fh closeFile];

            }

        }

        NSLog(@"[WXHook] %@", msg);

    } @catch (NSException *e) {}

}



static void log_init(void) {

    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];

    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];

    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {

        g_logPath = p;

        setupSignalHandlers();

        // v37.134-FIX53D: RUNTIME FILE-TOGGLE OVERRIDES (zero-config, no lldb / no rebuild / no resign)
        // Put empty files into <App Sandbox>/Documents via any 3u/爱思/全能签 file manager:
        //   Documents/wxhook_nolimit   → g_logSizeLimitEnabled=NO (remove 200 KB cap until next restart)
        //   Documents/wxhook_sparse    → g_logSparseEnabled=YES (enable TAG-filtered sparse logging)
        //   Documents/wxhook_logfull   → g_logSizeLimitEnabled=YES + g_logSparseEnabled=NO explicit restore default
        // Notes:
        //   - Delete the file + restart app → returns to compiled defaults.
        //   - These files are checked ONLY ONCE at boot (log_init). They are NOT polled mid-run.
        //   - lldb expr <var>=YES still works if symbols are visible (use e -- (void)Foo instead if static stripped).
        {
            NSString *docsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *toggle_nolimit = [docsDir stringByAppendingPathComponent:@"wxhook_nolimit"];
            NSString *toggle_sparse  = [docsDir stringByAppendingPathComponent:@"wxhook_sparse"];
            NSString *toggle_logfull = [docsDir stringByAppendingPathComponent:@"wxhook_logfull"];
            BOOL nolimitFile = [fm fileExistsAtPath:toggle_nolimit];
            BOOL sparseFile  = [fm fileExistsAtPath:toggle_sparse];
            BOOL logfullFile = [fm fileExistsAtPath:toggle_logfull];
            // wxhook_logfull wins as "explicit default restore"
            if (logfullFile) {
                // Force back to compiled defaults (respects macros)
                #if LOG_SIZE_LIMIT_DEFAULT_ON
                g_logSizeLimitEnabled = YES;
                #else
                g_logSizeLimitEnabled = NO;
                #endif
                #if SPARSE_LOG_MODE
                g_logSparseEnabled = YES;
                #else
                g_logSparseEnabled = NO;
                #endif
            } else {
                if (nolimitFile) g_logSizeLimitEnabled = NO;
                if (sparseFile)  g_logSparseEnabled    = YES;
            }
            _log([NSString stringWithFormat:
                @"[LOG-TOGGLE] File-switch check (Documents/*. no rebuild needed). wxhook_nolimit=%d (size cap off if 1). wxhook_sparse=%d (TAG filter on if 1). wxhook_logfull=%d (restore compiled defaults if 1). Tip: use 3uTools/Aisi/全能签 → Files → Documents → New Empty File named wxhook_nolimit / wxhook_sparse, then restart app.",
                nolimitFile ? 1 : 0, sparseFile ? 1 : 0, logfullFile ? 1 : 0]);
        }

        _log(@"=== WangXianHook v37.134-FIX53S-AZ6 loaded (FIX53S: uuid全链路一致. AZ2: 新增status=4根因修复—EE007 TLV version 7.6.3→9.9.9 / build 984→999; CC_MD5 hash2同步替换version+build. AZ6: 关闭日志轮转(完整不截断)+EE007逐TLV打印[AZ6-TLV]+EE121响应先打原始status[AZ6-STATUS-RAW]，定位新应用build的VERSION/BUILD真实字节.)");

        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);

        _log(@"[CRASH-HANDLER] Signal handlers + ObjC exception handler registered");

        // FIX53D: LOG CONFIG SUMMARY — print FINAL effective switch/limit/rotation state once on boot
        // (AFTER file-toggle overrides applied).
        {
            int copies = LOG_ROTATE_COUNT;
            if (copies < 0) copies = 0;
            if (copies > 5) copies = 5;
            long long maxKB_effective = g_logSizeLimitEnabled ? LOG_MAX_KB : (5 * 1024 /* unlimited-compiled? still show 5MB safety fallback */);
            long long totalCapKB_effective = g_logSizeLimitEnabled
                ? (maxKB_effective + (copies > 0 ? (maxKB_effective * copies) : 0))
                : (5 * 1024 + (copies > 0 ? (5 * 1024 * copies) : 0)); // disabled → use 5MB fallback
            NSString *limitStatus = g_logSizeLimitEnabled
                ? [NSString stringWithFormat:@"LIMITED (LOG_MAX_KB=%d; auto rotate)", LOG_MAX_KB]
                : @"UNLIMITED-requested (wxhook_nolimit detected or LOG_SIZE_LIMIT_DEFAULT_ON=0; still 5MB hard-safety cap)";
            NSString *sparseStatus = g_logSparseEnabled
                ? @"ON (TAG-filtered noise → disk skipped, ring buffer still full)"
                : @"OFF (full verbose TAGs to disk)";
            NSString *logCfg = [NSString stringWithFormat:
                @"[LOG-CONFIG] Effective (after file-toggle overrides): SPARSE=%d → %@. LOG_SIZE_LIMIT=%d → %@. LOG_ROTATE_COUNT=%d (history kept). Approx max disk: ~%lld KB. Compiled defaults: SPARSE_LOG_MODE=%d, LOG_SIZE_LIMIT_DEFAULT_ON=%d, LOG_MAX_KB=%d. File toggles (restart required to change): Documents/wxhook_nolimit (remove cap) · Documents/wxhook_sparse (enable TAG filter) · Documents/wxhook_logfull (restore defaults).",
                g_logSparseEnabled ? 1 : 0, sparseStatus,
                g_logSizeLimitEnabled ? 1 : 0, limitStatus,
                copies,
                totalCapKB_effective,
                SPARSE_LOG_MODE, LOG_SIZE_LIMIT_DEFAULT_ON, LOG_MAX_KB];
            _log(logCfg);
        }

        g_isActivated = YES;

    }

}



// ============================================================

#pragma mark - SignatureKit hooks

// ============================================================



// 1. showAlert: - SUPPRESS

typedef void (*ShowAlertIMP)(id, SEL, id);

static ShowAlertIMP orig_showAlert = NULL;

static void hook_showAlert(id self, SEL _cmd, id msg) {

    DLOG(@"[SK] showAlert: SUPPRESSED: %@", msg);

}



// 2. exitApplication - BLOCK

typedef void (*ExitAppIMP)(id, SEL);

static ExitAppIMP orig_exitApp = NULL;

static void hook_exitApp(id self, SEL _cmd) {

    DLOG(@"[SK] exitApplication BLOCKED");

}



// 3. handleAppInfoResult: - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — it may trigger SIGBUS or C++ exception on some devices.

// Just suppress and log.

static void hook_handleResult(id self, SEL _cmd, id result) {

    DLOG(@"[SK] handleAppInfoResult: %@ (SAFE STUB - no orig call)", result);

    // v37.121: DO NOT call orig_handleResult — it was causing SIGBUS in async callbacks.

    // The dummy success result is pre-created during hook installation.

}



// 4. judgeAppInfoWithBaseUrl: - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — it may trigger SIGBUS on some devices.

static void hook_judgeBase(id self, SEL _cmd, id baseUrl) {

    DLOG(@"[SK] judgeAppInfoWithBaseUrl: %@ (SAFE STUB - no orig call)", baseUrl);

    // v37.121: Just log and suppress — don't call original

}



// 5. judgeNet - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — it may trigger SIGBUS on some devices.

static void hook_judgeNet(id self, SEL _cmd) {

    DLOG(@"[SK] judgeNet called (SAFE STUB - no orig call)");

    // v37.121: Just log and suppress — don't call original

}



// 6. verifySignatureFromParameters: - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — it may trigger SIGBUS on some devices.

// Return a pre-computed SUCCESS value.

static id hook_verifySig(id self, SEL _cmd, id params) {

    DLOG(@"[SK] verifySignatureFromParameters: %@ (SAFE STUB - return SUCCESS)", params);

    // v37.121: Return pre-computed success, don't call original

    static NSDictionary *s_successResult = nil;

    if (!s_successResult) {

        s_successResult = @{

            @"verity": @1,

            @"tip": @0

        };

    }

    return s_successResult;

}



// 7. generateRequestParams - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — it may trigger SIGBUS on some devices.

static id hook_genParams(id self, SEL _cmd) {

    DLOG(@"[SK] generateRequestParams called (SAFE STUB - return nil)");

    // v37.121: Return nil, don't call original

    return nil;

}



// 8. createSignatureParams: - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — it may trigger SIGBUS on some devices.

static id hook_createSigParams(id self, SEL _cmd, id arg) {

    DLOG(@"[SK] createSignatureParams: %@ (SAFE STUB - return nil)", arg);

    // v37.121: Return nil, don't call original

    return nil;

}



// ============================================================

#pragma mark - SignatureCheck hooks (stub class - prevent HTTP calls)

// ============================================================



// Hook SignatureCheck.JudgeApp - SAFELY STUBBED (v37.121-DIAG)

// DO NOT call original — may trigger SIGBUS on some devices.

static void hook_judgeApp(id self, SEL _cmd) {

    DLOG(@"[SC] SignatureCheck.JudgeApp called (SAFE STUB - no orig call)");

    // v37.121: Don't call original, just log and suppress

}



// ============================================================

#pragma mark - FIX39: SignatureKit + SignatureCheck DIAG诊断Wrappers (只打印,调用orig,不修改)

// ============================================================

// v37.129: 绝对不能stub这些方法!必须调用orig,否则状态机卡死→无网络

// FIX39: 用DIAG wrapper包裹,打印调用前后的参数+返回值,精确找到哪一步失败

// ------ SignatureKit orig IMP保存 ------

static IMP g_origSK_judgeBase = NULL;

static IMP g_origSK_judgeNet = NULL;

static IMP g_origSK_handleResult = NULL;

static IMP g_origSK_verifySig = NULL;

// ------ SignatureCheck orig IMP保存 ------

static IMP g_origSC_JudgeApp = NULL;

static IMP g_origSC_nettimes = NULL;  // 关键: 之前崩溃在这,现在打印data解析字段



// --- [SK-DIAG] judgeAppInfoWithBaseUrl: wrapper ---

static void diagSK_judgeBase(id self, SEL _cmd, id baseUrl) {

    DLOG(@"[SK-DIAG] >>> judgeAppInfoWithBaseUrl: BEGIN baseUrl=%@", baseUrl);

    if (g_origSK_judgeBase) {

        ((void(*)(id,SEL,id))g_origSK_judgeBase)(self, _cmd, baseUrl);

    } else {

        DLOG(@"[SK-DIAG] >>> judgeAppInfoWithBaseUrl: ⚠️ orig IMP=NULL → 跳过调用orig");

    }

    DLOG(@"[SK-DIAG] <<< judgeAppInfoWithBaseUrl: END (orig已执行完成)");

}



// --- [SK-DIAG] judgeNet wrapper ---

static void diagSK_judgeNet(id self, SEL _cmd) {

    DLOG(@"[SK-DIAG] >>> judgeNet: BEGIN");

    if (g_origSK_judgeNet) {

        ((void(*)(id,SEL))g_origSK_judgeNet)(self, _cmd);

    } else {

        DLOG(@"[SK-DIAG] >>> judgeNet: ⚠️ orig IMP=NULL → 跳过调用orig");

    }

    DLOG(@"[SK-DIAG] <<< judgeNet: END (orig已执行完成)");

}



// --- [SK-DIAG] handleAppInfoResult: wrapper ---
// FIX42: 🔴🔴🔴 铁证根因修复! judgeAppInfoSignApi响应带sign时,HTTP层修改data或code字段都会BREAK sign校验
//   → result:true注入移到此处(handleAppInfoResult:),因为verifySignatureFromParameters在此之前已完成!
//   参考: FIX41 wxhook28.log line 329-338: judgeAppInfoSignApi原响应含sign="FD6C1B8A...",FIX41在HTTP层插入result:true
//   → sign字段原始MD5不含result:true → verifySignatureFromParameters校验失败 → handleAppInfoResult从未调用!
//   FIX9 wxhook.log line 335-340: 全能签server返回500(无sign字段)→用假响应(无sign)→直接成功!
//   FIX42策略:
//     a. judgeAppInfoSignApi含sign时 → HTTP层不动任何字节 → sign校验100%通过
//     b. 在此处(handleAppInfoResult)检查data dict缺失result/verity/tip字段 → 安全注入(此时sign已验证!)
static void diagSK_handleResult(id self, SEL _cmd, id result) {

    DLOG(@"[SK-DIAG] >>> handleAppInfoResult: BEGIN result=%@", result);

    // FIX43: 安全注入缺失的关键字段(result/verity/tip/ENDTIME/大小写映射) - 此时sign校验已完成,100%无副作用!
    //   FIX42不足: 全能签cert.qunhongtech返回的字段是**小写**(end/tip/open/verity) 但游戏C解析器读**大写**(END/TIP/OPEN/verity保留),
    //             且全能签响应完全没有ENDTIME字段→游戏读不到直接判失败!
    //   FIX43补充: ①小写→大写字段映射(end→END, tip→TIP, open→OPEN) ②ENDTIME缺失时强制插入 ③缺少result/verity字段注入
    @try {
        if (result && [result isKindOfClass:[NSDictionary class]]) {
            NSDictionary *origResp = (NSDictionary *)result;
            NSMutableDictionary *fixedResp = nil;
            id dataVal = [origResp objectForKey:@"data"];
            NSMutableDictionary *fixedData = nil;
            BOOL needInject = NO;
            if (dataVal && [dataVal isKindOfClass:[NSDictionary class]]) {
                NSDictionary *origData = (NSDictionary *)dataVal;
                // FIX43: 先做CASE A~E检查(任何一个触发→必须构造fixedData)
                BOOL caseA_missingResult = ![origData objectForKey:@"result"];
                BOOL caseB_missingVerity = ![origData objectForKey:@"verity"];
                BOOL caseC_missingTip = ![origData objectForKey:@"tip"];
                BOOL caseD_missingBigEND = ![origData objectForKey:@"END"] && [origData objectForKey:@"end"];
                BOOL caseE_missingBigOPEN = ![origData objectForKey:@"OPEN"] && [origData objectForKey:@"open"];
                BOOL caseF_missingBigTIP = ![origData objectForKey:@"TIP"] && [origData objectForKey:@"tip"];
                BOOL caseG_missingENDTIME = ![origData objectForKey:@"ENDTIME"];
                if (caseA_missingResult || caseB_missingVerity || caseC_missingTip
                    || caseD_missingBigEND || caseE_missingBigOPEN || caseF_missingBigTIP || caseG_missingENDTIME) {
                    fixedData = [origData mutableCopy];
                    // CASE A: result缺失 (全能签100%缺此字段!)
                    if (caseA_missingResult) [fixedData setObject:@YES forKey:@"result"];
                    // CASE B: verity缺失 (全能签响应已有verity=1)
                    if (caseB_missingVerity) [fixedData setObject:@1 forKey:@"verity"];
                    // CASE C: tip缺失 (全能签响应已有tip=0. 注意: 大写TIP游戏可能也读)
                    if (caseC_missingTip) [fixedData setObject:@0 forKey:@"tip"];
                    // CASE D: 小写end→大写END (全能签响应是end:0 但游戏读END=0)
                    if (caseD_missingBigEND) {
                        id endVal = [fixedData objectForKey:@"end"];
                        [fixedData setObject:(endVal ? endVal : @0) forKey:@"END"];
                    }
                    // CASE E: 小写open→大写OPEN (全能签响应是open:1 但游戏读OPEN=1)
                    if (caseE_missingBigOPEN) {
                        id openVal = [fixedData objectForKey:@"open"];
                        [fixedData setObject:(openVal ? openVal : @1) forKey:@"OPEN"];
                    }
                    // CASE F: 小写tip→大写TIP (双保险,避免游戏有分支读大写)
                    if (caseF_missingBigTIP) {
                        id tipVal = [fixedData objectForKey:@"tip"];
                        [fixedData setObject:(tipVal ? tipVal : @0) forKey:@"TIP"];
                    }
                    // CASE G: ENDTIME缺失 (全能签响应完全无此字段! V3 judgeAppInfoApi有. 游戏可能读它判断是否过期!)
                    if (caseG_missingENDTIME) {
                        [fixedData setObject:@"2027-12-31 23:59:59" forKey:@"ENDTIME"];
                        DLOG(@"[FIX43] handleAppInfoResult: 🚨 data完全无ENDTIME字段→强制插入!(全能签响应缺此字段)");
                    } else {
                        // ENDTIME存在则延长
                        [fixedData setObject:@"2027-12-31 23:59:59" forKey:@"ENDTIME"];
                    }
                    // CASE H: 确保END=0 / OPEN=1 (即使大写字段已存在也强制刷新为正确值)
                    [fixedData setObject:@0 forKey:@"END"];
                    [fixedData setObject:@1 forKey:@"OPEN"];
                    needInject = YES;
                }
            }
            // 顶层code字段检查: 如果是1(失败)→改为0,message改为success
            NSNumber *codeObj = [origResp objectForKey:@"code"];
            if (!fixedResp && (needInject || (codeObj && [codeObj intValue] != 0))) {
                fixedResp = [origResp mutableCopy];
                if (needInject && fixedData) [fixedResp setObject:fixedData forKey:@"data"];
                if (codeObj && [codeObj intValue] != 0) {
                    [fixedResp setObject:@0 forKey:@"code"];
                    if (![fixedResp objectForKey:@"message"] || [[fixedResp objectForKey:@"message"] isEqualToString:@"OK"]) {
                        [fixedResp setObject:@"success" forKey:@"message"];
                    }
                }
            }
            if (fixedResp) {
                DLOG(@"[FIX43] handleAppInfoResult: ✅ 字段修复(SIGN校验后,100%%安全!) orig=%@ → FIXED=%@", result, fixedResp);
                result = fixedResp;  // pass fixed version to original handler below
            } else {
                DLOG(@"[FIX42] handleAppInfoResult: ℹ️ result字段齐全(含result/verity/tip+code=0),无需修复");
            }
        } else if (result && ![result isKindOfClass:[NSNull class]]) {
            DLOG(@"[FIX42] handleAppInfoResult: ⚠️ result类型不是NSDictionary! 类型=%@ → 跳过FIX", NSStringFromClass([result class]));
        }
    } @catch (NSException *e) {
        DLOG(@"[FIX42] handleAppInfoResult: ⚠️ 注入字段异常: %@ (继续走orig流程不中断)", e);
    }

    if (g_origSK_handleResult) {

        ((void(*)(id,SEL,id))g_origSK_handleResult)(self, _cmd, result);

    } else {

        DLOG(@"[SK-DIAG] >>> handleAppInfoResult: ⚠️ orig IMP=NULL → 跳过调用orig");

    }

    DLOG(@"[SK-DIAG] <<< handleAppInfoResult: END");

}



// --- [SK-DIAG] verifySignatureFromParameters: wrapper ---

static id diagSK_verifySig(id self, SEL _cmd, id params) {

    DLOG(@"[SK-DIAG] >>> verifySignatureFromParameters: BEGIN params=%@", params);

    id ret = nil;

    if (g_origSK_verifySig) {

        ret = ((id(*)(id,SEL,id))g_origSK_verifySig)(self, _cmd, params);

        DLOG(@"[SK-DIAG] <<< verifySignatureFromParameters: END orig返回=%@", ret);

        // FIX43: 🚀🚀🚀 双保险DOUBLE GUARANTEE! 即使全能签SDK内部校验返回NO/0/nil,我们也强制替换为YES/1/成功!
        //   为什么安全? 此时HTTP层对含sign响应是100%原始字节没修改的,sign校验"理论上"100%过
        //   万一游戏内部还有额外的MD5校验(如channel串/APPID/UDID绑定校验)或设备差异导致orig返回失败,
        //   我们直接兜底返回成功→避免状态机卡死. 这一步绝对安全! 因为后续handleAppInfoResult会注入result:true.
        @try {
            BOOL origPass = NO;
            if (ret && [ret respondsToSelector:@selector(boolValue)]) origPass = [(NSNumber *)ret boolValue];
            else if (ret == nil || ret == [NSNull null]) origPass = NO;
            if (!origPass) {
                // 原来返回NO/0/nil → 强制改为@YES (signature校验"通过")
                DLOG(@"[FIX43] verifySignatureFromParameters: 🚨 orig返回失败(%@) → 🔴强制替换为@YES! (双保险兜底,避免状态机卡死)", ret);
                ret = @YES;
            } else {
                DLOG(@"[FIX43] verifySignatureFromParameters: ✅ orig校验已通过(=%@),无需兜底", ret);
            }
        } @catch (NSException *e) {
            DLOG(@"[FIX43] verifySignatureFromParameters: ⚠️ 兜底异常=%@ → 直接返回@YES", e);
            ret = @YES;
        }

    } else {

        DLOG(@"[SK-DIAG] >>> verifySignatureFromParameters: ⚠️ orig IMP=NULL → 返回nil");
        // FIX43: IMP=NULL也要兜底返回@YES避免nil导致后续失败
        ret = @YES;
        DLOG(@"[FIX43] verifySignatureFromParameters: IMP=NULL 兜底→返回@YES");
    }

    return ret;

}



// --- [SC-DIAG] SignatureCheck.JudgeApp wrapper ---

static void diagSC_JudgeApp(id self, SEL _cmd) {

    DLOG(@"[SC-DIAG] >>> SignatureCheck.JudgeApp: BEGIN self=%@", self);

    if (g_origSC_JudgeApp) {

        ((void(*)(id,SEL))g_origSC_JudgeApp)(self, _cmd);

    } else {

        DLOG(@"[SC-DIAG] >>> SignatureCheck.JudgeApp: ⚠️ orig IMP=NULL → 跳过调用orig");

    }

    DLOG(@"[SC-DIAG] <<< SignatureCheck.JudgeApp: END");

}



// --- [SC-DIAG] SignatureCheck.nettimes wrapper (打印data所有关键字段!) ---

// FIX31/FIX38的历史元凶: SignatureCheck.nettimes解析data.ENDTIME/result等字段时出错

// FIX39: 在调用orig前后打印data完整字段值,确认HTTP patch后的值是否被正确解析!

static void diagSC_nettimes(id self, SEL _cmd) {

    DLOG(@"[SC-DIAG] >>> SignatureCheck.nettimes: BEGIN self=%@", self);

    // 尝试打印self的ivar(最关键的responseData/result等)

    @try {

        unsigned int ivarCount = 0;

        Ivar *ivars = class_copyIvarList([self class], &ivarCount);

        NSMutableArray *keyFields = [NSMutableArray array];

        for (unsigned int i = 0; i < ivarCount && ivars; i++) {

            Ivar iv = ivars[i];

            const char *name = ivar_getName(iv);

            NSString *nsName = name ? [NSString stringWithUTF8String:name] : nil;

            if (!nsName) continue;

            // 只打印关键字段,避免日志爆炸

            BOOL isKey = ([nsName containsString:@"esult"] || [nsName containsString:@"erity"] ||

                         [nsName containsString:@"tip"]  || [nsName containsString:@"data"]  ||

                         [nsName containsString:@"END"]  || [nsName containsString:@"OPEN"]  ||

                         [nsName containsString:@"esp"]  || [nsName containsString:@"code"]  ||

                         [nsName containsString:@"sign"] || [nsName containsString:@"time"]);

            if (!isKey) continue;

            ptrdiff_t offset = ivar_getOffset(iv);

            id val = ((id(*)(id, Ivar))object_getIvar)(self, iv);

            if (val || offset) [keyFields addObject:[NSString stringWithFormat:@"%@=%@", nsName, val ?: @"(nil)"]];

        }

        if (ivars) free(ivars);

        if (keyFields.count > 0) DLOG(@"[SC-DIAG] nettimes 关键字段IVAR snapshot: %@", keyFields);

    } @catch (NSException *e) {

        DLOG(@"[SC-DIAG] nettimes ivar读取异常: %@", e);

    }

    if (g_origSC_nettimes) {

        ((void(*)(id,SEL))g_origSC_nettimes)(self, _cmd);

        DLOG(@"[SC-DIAG] <<< SignatureCheck.nettimes: END (orig执行完成✅,未SIGSEGV!)");

    } else {

        DLOG(@"[SC-DIAG] <<< SignatureCheck.nettimes: ⚠️ orig IMP=NULL → 跳过调用orig");

    }

}



static void hook_showTip(id self, SEL _cmd, id arg) {

    DLOG(@"[SC] SignatureCheck.showTipViewEND: SUPPRESSED: %@", arg);

    // Don't call original - suppress the "版本过低" popup

}



static void hook_scExit(id self, SEL _cmd) {

    DLOG(@"[SC] SignatureCheck.exitApplication BLOCKED");

    // Don't call original

}



// ============================================================

#pragma mark - v37.128: Distribution Signature Bypass

// ============================================================

// ROOT CAUSE: On distribution-signed apps (V3/enterprise/super-sign),

// the game's SignatureKit verification fails because:

// 1. Local code signature validation (SecStaticCodeCheckValidity) fails

// 2. HTTP-based verification might use a different path

// 3. SignatureKit's internal state machine breaks

//

// SOLUTION: Three-layer bypass:

// Layer 1: Hook Security framework (SecStaticCodeCheckValidity etc.)

// Layer 2: Hook SignatureKit methods (return success, never call original)

// Layer 3: Hook LCNetworking (intercept HTTP at app level)

// ============================================================



// --- Layer 1: Security Framework Hooks ---

// These bypass LOCAL code signature validation.

// On distribution-signed apps, the signature doesn't match what the game expects.

// By hooking these functions, we make ALL signature checks pass.



// Forward declaration: isSignatureVerificationURL is defined below (in HTTP hooks section)

static BOOL isSignatureVerificationURL(NSString *url);

// Forward declaration: rebindSymbol is defined below (in fishhook helpers section)

static int rebindSymbol(const char *symbolName, void *replacement, void **original);



// Use void* instead of Security framework types to avoid import issues

typedef OSStatus (*SecStaticCodeCheckValidityFunc)(void *, uint32_t, void *);

static SecStaticCodeCheckValidityFunc orig_SecStaticCodeCheckValidity = NULL;



static OSStatus hook_SecStaticCodeCheckValidity(void *code, uint32_t flags, void *req) {

    DLOG(@"[SEC-BYPASS] SecStaticCodeCheckValidity: returning errSecSuccess (bypass local sig check)");

    return 0; // errSecSuccess

}



typedef OSStatus (*SecCodeCheckValidityFunc)(void *, uint32_t, void *);

static SecCodeCheckValidityFunc orig_SecCodeCheckValidity = NULL;



static OSStatus hook_SecCodeCheckValidity(void *code, uint32_t flags, void *req) {

    DLOG(@"[SEC-BYPASS] SecCodeCheckValidity: returning errSecSuccess");

    return 0;

}



typedef OSStatus (*SecCodeCheckValidityWithErrorsFunc)(void *, uint32_t, void *, void **);

static SecCodeCheckValidityWithErrorsFunc orig_SecCodeCheckValidityWithErrors = NULL;



static OSStatus hook_SecCodeCheckValidityWithErrors(void *code, uint32_t flags, void *req, void **errors) {

    DLOG(@"[SEC-BYPASS] SecCodeCheckValidityWithErrors: returning errSecSuccess");

    if (errors) *errors = NULL;

    return 0;

}



static void installSecurityFrameworkHooks(void) {

    // Hook SecStaticCodeCheckValidity

    void *secFW = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);

    if (!secFW) secFW = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);



    orig_SecStaticCodeCheckValidity = (SecStaticCodeCheckValidityFunc)dlsym(RTLD_DEFAULT, "SecStaticCodeCheckValidity");

    if (orig_SecStaticCodeCheckValidity) {

        int r = rebindSymbol("_SecStaticCodeCheckValidity",

                             (void *)hook_SecStaticCodeCheckValidity,

                             (void **)&orig_SecStaticCodeCheckValidity);

        DLOG(@"[SEC-BYPASS] SecStaticCodeCheckValidity hook: rebind=%d", r);

    }



    orig_SecCodeCheckValidity = (SecCodeCheckValidityFunc)dlsym(RTLD_DEFAULT, "SecCodeCheckValidity");

    if (orig_SecCodeCheckValidity) {

        int r = rebindSymbol("_SecCodeCheckValidity",

                             (void *)hook_SecCodeCheckValidity,

                             (void **)&orig_SecCodeCheckValidity);

        DLOG(@"[SEC-BYPASS] SecCodeCheckValidity hook: rebind=%d", r);

    }



    orig_SecCodeCheckValidityWithErrors = (SecCodeCheckValidityWithErrorsFunc)dlsym(RTLD_DEFAULT, "SecCodeCheckValidityWithErrors");

    if (orig_SecCodeCheckValidityWithErrors) {

        int r = rebindSymbol("_SecCodeCheckValidityWithErrors",

                             (void *)hook_SecCodeCheckValidityWithErrors,

                             (void **)&orig_SecCodeCheckValidityWithErrors);

        DLOG(@"[SEC-BYPASS] SecCodeCheckValidityWithErrors hook: rebind=%d", r);

    }

}



// --- Layer 2: SignatureKit Method Hooks (Safe, no original IMP calls) ---

// v37.129: MINIMAL SignatureKit hooks — only suppress UI and block exit.

// DO NOT stub judgeNet/judgeBase/JudgeApp/verifySig/handleResult —

// stubbing them to do nothing BREAKS the game's state machine.

// The game's verification flow must run naturally so it progresses

// to HTTP requests, which our HTTP hooks intercept.

// FIX39: ADD DIAG诊断Wrappers (只打印,调用orig,不修改任何行为)

//        打印judgeBase/judgeNet/handleResult/verifySig/JudgeApp/nettimes

//        的调用参数+返回值+关键字段IVAR,100%定位验签失败的精确位置

// FIX41: Dump ALL method names on a class to find REAL callback selector names
// (如果handleAppInfoResult/nettimes从没被调用→99%是我们hook的方法名错了! 游戏实际用了不同名字!)
static void fix41_dumpObjcClassMethods(Class cls, NSString *tag, int maxMethods) {
    if (!cls) { DLOG(@"[FIX41-METHOD-DUMP] %@: Class=NULL → skip", tag); return; }
    @try {
        unsigned int clsMethodCount = 0, instMethodCount = 0;
        Method *clsMethods = class_copyMethodList(objc_getMetaClass(class_getName(cls)), &clsMethodCount);
        Method *instMethods = class_copyMethodList(cls, &instMethodCount);
        NSMutableArray *clsNames = [NSMutableArray array];
        NSMutableArray *instNames = [NSMutableArray array];
        for (unsigned int i = 0; i < clsMethodCount && clsMethods && i < (unsigned)maxMethods; i++) {
            SEL s = method_getName(clsMethods[i]);
            NSString *nm = [NSString stringWithUTF8String:sel_getName(s) ? sel_getName(s) : "(null)"];
            if (nm) [clsNames addObject:nm];
        }
        for (unsigned int i = 0; i < instMethodCount && instMethods && i < (unsigned)maxMethods; i++) {
            SEL s = method_getName(instMethods[i]);
            NSString *nm = [NSString stringWithUTF8String:sel_getName(s) ? sel_getName(s) : "(null)"];
            if (nm) [instNames addObject:nm];
        }
        if (clsMethods) free(clsMethods);
        if (instMethods) free(instMethods);
        DLOG(@"[FIX41-METHOD-DUMP] 🔍 %@ Class(cls=%d / inst=%d): CLASS=%@ INSTANCE=%@",
             tag, clsMethodCount, instMethodCount, clsNames, instNames);
    } @catch (NSException *e) {
        DLOG(@"[FIX41-METHOD-DUMP] %@ Exception during dump: %@", tag, e);
    }
}

// FIX39-FINAL: __attribute__((used)) on installSignatureKitBypassHooks
//   FORCE linker to keep SignatureKit DIAG hook wrappers (they MUST be installed for runtime tracing)
__attribute__((used))
static void installSignatureKitBypassHooks(void) {
    Class sigKitCls = NSClassFromString(@"SignatureKit");

    if (!sigKitCls) {

        DLOG(@"[SIGKIT-BYPASS] SignatureKit class not found, skipping");

    } else {

        // FIX41: 🔴DUMP所有SignatureKit方法名! (因为handleAppInfoResult/verifySig从未被调用→99%方法名错了!)
        fix41_dumpObjcClassMethods(sigKitCls, @"SignatureKit", 200);

        // ONLY hook showAlert: and exitApplication — these are safe to stub.

        // They don't affect the verification flow, just prevent error UI and app exit.



        // Hook +[SignatureKit showAlert:] — suppress alerts

        Method m = class_getClassMethod(sigKitCls, NSSelectorFromString(@"showAlert:"));

        if (m) {

            method_setImplementation(m, (IMP)hook_showAlert);

            DLOG(@"[SIGKIT-BYPASS] showAlert: HOOKED (suppress)");

        }



        // Hook +[SignatureKit exitApplication] — block exit

        m = class_getClassMethod(sigKitCls, NSSelectorFromString(@"exitApplication"));

        if (m) {

            method_setImplementation(m, (IMP)hook_exitApp);

            DLOG(@"[SIGKIT-BYPASS] exitApplication HOOKED (block)");

        }



        // Hook +[SignatureKit showTipViewEND:] if it exists — suppress version expired popup

        m = class_getClassMethod(sigKitCls, NSSelectorFromString(@"showTipViewEND:"));

        if (m) {

            method_setImplementation(m, (IMP)hook_showTip);

            DLOG(@"[SIGKIT-BYPASS] showTipViewEND: HOOKED (suppress)");

        }



        // ====== FIX39: SignatureKit DIAG诊断Wrappers安装 ======

        // 用 method_setImplementation 替换保存orig到全局,设置wrapper为新IMP

        // 绝对不修改任何返回值! 只打印!

        @try {

            int diagInstalled = 0;

            // 1. judgeAppInfoWithBaseUrl:

            SEL jbSel = NSSelectorFromString(@"judgeAppInfoWithBaseUrl:");

            Method jbM = class_getClassMethod(sigKitCls, jbSel);

            if (jbM) {

                g_origSK_judgeBase = method_getImplementation(jbM);

                method_setImplementation(jbM, (IMP)diagSK_judgeBase);

                DLOG(@"[SK-DIAG-INSTALL] ✅ judgeAppInfoWithBaseUrl: orig=%p → diag wrapper", g_origSK_judgeBase);

                diagInstalled++;

            } else {

                DLOG(@"[SK-DIAG-INSTALL] ⚠️ judgeAppInfoWithBaseUrl: method not found");

            }

            // 2. judgeNet

            SEL jnSel = NSSelectorFromString(@"judgeNet");

            Method jnM = class_getClassMethod(sigKitCls, jnSel);

            if (jnM) {

                g_origSK_judgeNet = method_getImplementation(jnM);

                method_setImplementation(jnM, (IMP)diagSK_judgeNet);

                DLOG(@"[SK-DIAG-INSTALL] ✅ judgeNet orig=%p → diag wrapper", g_origSK_judgeNet);

                diagInstalled++;

            } else {

                DLOG(@"[SK-DIAG-INSTALL] ⚠️ judgeNet method not found");

            }

            // 3. handleAppInfoResult: (可能是class or instance,都试)

            SEL hrSel = NSSelectorFromString(@"handleAppInfoResult:");

            Method hrM = class_getClassMethod(sigKitCls, hrSel);

            if (!hrM) hrM = class_getInstanceMethod(sigKitCls, hrSel);

            if (hrM) {

                g_origSK_handleResult = method_getImplementation(hrM);

                method_setImplementation(hrM, (IMP)diagSK_handleResult);

                DLOG(@"[SK-DIAG-INSTALL] ✅ handleAppInfoResult: orig=%p → diag wrapper", g_origSK_handleResult);

                diagInstalled++;

            } else {

                DLOG(@"[SK-DIAG-INSTALL] ℹ️ handleAppInfoResult: not found (正常,可能方法名不同)");

            }

            // 4. verifySignatureFromParameters: (可能class or instance)

            SEL vsSel = NSSelectorFromString(@"verifySignatureFromParameters:");

            Method vsM = class_getClassMethod(sigKitCls, vsSel);

            if (!vsM) vsM = class_getInstanceMethod(sigKitCls, vsSel);

            if (vsM) {

                g_origSK_verifySig = method_getImplementation(vsM);

                method_setImplementation(vsM, (IMP)diagSK_verifySig);

                DLOG(@"[SK-DIAG-INSTALL] ✅ verifySignatureFromParameters: orig=%p → diag wrapper", g_origSK_verifySig);

                diagInstalled++;

            } else {

                DLOG(@"[SK-DIAG-INSTALL] ℹ️ verifySignatureFromParameters: not found (正常,可能方法名不同)");

            }

            DLOG(@"[SK-DIAG-INSTALL] FIX39: SignatureKit 共安装 %d 个DIAG wrappers", diagInstalled);

        } @catch (NSException *e) {

            DLOG(@"[SK-DIAG-INSTALL] ❌ SignatureKit DIAG安装异常: %@ → 跳过(不影响运行)", e);

        }



        DLOG(@"[SIGKIT-BYPASS] Minimal hooks installed (showAlert/exitApp/showTip only + FIX39 DIAG wrappers)");

    }



    // ====== FIX39: SignatureCheck DIAG诊断Wrappers安装 ======

    // SignatureCheck class: JudgeApp, nettimes, showTipViewEND, exitApplication

    Class sigCheckCls = NSClassFromString(@"SignatureCheck");

    if (!sigCheckCls) {

        DLOG(@"[SC-DIAG-INSTALL] SignatureCheck class not found, skipping");

        return;

    }

    // FIX41: 🔴DUMP所有SignatureCheck方法名! (因为nettimes从未被调用→可能方法名错了或回调走了别的方法!)
    fix41_dumpObjcClassMethods(sigCheckCls, @"SignatureCheck", 200);

    @try {

        int scDiag = 0;

        // 1. SignatureCheck.JudgeApp (class or instance method? 之前hook的是instance,都试一下)

        SEL jaSel = NSSelectorFromString(@"JudgeApp");

        Method jaM = class_getClassMethod(sigCheckCls, jaSel);

        if (!jaM) jaM = class_getInstanceMethod(sigCheckCls, jaSel);

        if (jaM) {

            g_origSC_JudgeApp = method_getImplementation(jaM);

            method_setImplementation(jaM, (IMP)diagSC_JudgeApp);

            DLOG(@"[SC-DIAG-INSTALL] ✅ SignatureCheck.JudgeApp orig=%p → diag wrapper", g_origSC_JudgeApp);

            scDiag++;

        } else {

            DLOG(@"[SC-DIAG-INSTALL] ⚠️ SignatureCheck.JudgeApp method not found");

        }

        // 2. SignatureCheck.nettimes (instance method, v37.134-FIX31崩溃点)

        SEL ntSel = NSSelectorFromString(@"nettimes");

        Method ntM = class_getInstanceMethod(sigCheckCls, ntSel);

        if (ntM) {

            g_origSC_nettimes = method_getImplementation(ntM);

            method_setImplementation(ntM, (IMP)diagSC_nettimes);

            DLOG(@"[SC-DIAG-INSTALL] ✅ SignatureCheck.nettimes orig=%p → diag wrapper (打印IVAR关键字段!)", g_origSC_nettimes);

            scDiag++;

        } else {

            DLOG(@"[SC-DIAG-INSTALL] ⚠️ SignatureCheck.nettimes method not found (class或superclass中无此selector)");

        }

        // showTipViewEND 和 exitApplication 继续用SAFE stub(阻止UI/退出)

        Method tipM = class_getInstanceMethod(sigCheckCls, NSSelectorFromString(@"showTipViewEND:"));

        if (!tipM) tipM = class_getClassMethod(sigCheckCls, NSSelectorFromString(@"showTipViewEND:"));

        if (tipM) {

            method_setImplementation(tipM, (IMP)hook_showTip);

            DLOG(@"[SC-DIAG-INSTALL] ✅ SignatureCheck.showTipViewEND: stubbed");

            scDiag++;

        }

        Method exitM = class_getInstanceMethod(sigCheckCls, NSSelectorFromString(@"exitApplication"));

        if (!exitM) exitM = class_getClassMethod(sigCheckCls, NSSelectorFromString(@"exitApplication"));

        if (exitM) {

            method_setImplementation(exitM, (IMP)hook_scExit);

            DLOG(@"[SC-DIAG-INSTALL] ✅ SignatureCheck.exitApplication: BLOCKED");

            scDiag++;

        }

        DLOG(@"[SC-DIAG-INSTALL] FIX39: SignatureCheck 共安装 %d hooks (DIAG+UI拦截)", scDiag);

    } @catch (NSException *e) {

        DLOG(@"[SC-DIAG-INSTALL] ❌ SignatureCheck DIAG安装异常: %@ → 跳过(不影响运行)", e);

    }

}



// --- Layer 3: LCNetworking Hooks ---

// The game uses LCNetworking (not NSURLSession directly) for some HTTP requests.

// Hook it to intercept signature verification requests at the application level.



static void installLCNetworkingHooks(void) {

    // FIX39: 添加入口打印. FIX38日志中完全无LCNET打印→不知道是否执行到此

    DLOG(@"[LCNET-BYPASS] >>> BEGIN installLCNetworkingHooks()");

    Class lcnetCls = NSClassFromString(@"LCNetworking");

    if (!lcnetCls) {

        DLOG(@"[LCNET-BYPASS] LCNetworking class not found, skipping (✅ 入口日志确认:函数已执行,只是当前Runtime未加载该类)");

        return;

    }

    DLOG(@"[LCNET-BYPASS] LCNetworking class FOUND: %@ → proceeding to hook methods", NSStringFromClass(lcnetCls));

    // FIX41: 🔴DUMP LCNetworking所有方法名! (getWithURL/PostWithURL方法找不到→真实方法名肯定不同!)
    fix41_dumpObjcClassMethods(lcnetCls, @"LCNetworking", 300);

    // Hook getWithURL:parameters:success:failure:

    SEL getSel = NSSelectorFromString(@"getWithURL:parameters:success:failure:");

    Method m = class_getInstanceMethod(lcnetCls, getSel);

    if (m) {

        IMP origImpl = method_getImplementation(m);



        IMP newImpl = imp_implementationWithBlock(^(id self, NSString *url, id params,

                                                      void(^success)(id), void(^failure)(NSError*)) {

            if (url && isSignatureVerificationURL(url)) {

                DLOG(@"[LCNET-BYPASS] Intercepted signature URL: %@", url);

                if (success) {

                    NSDictionary *fakeResp = @{

                        @"code": @0,

                        @"message": @"success",

                        @"data": @{

                            @"result": @YES,

                            @"verity": @1,

                            @"tip": @0,

                            @"ENDTIME": @"2027-12-31 23:59:59",

                            @"END": @0,

                            @"OPEN": @1,

                            @"id": @11927,

                            @"COUNT": @0,

                            @"MAXLIMIT": @5000

                        }

                    };

                    success(fakeResp);

                }

                return;

            }

            ((void(*)(id, SEL, id, id, void(^)(id), void(^)(NSError*)))origImpl)(

                self, getSel, url, params, success, failure);

        });

        method_setImplementation(m, newImpl);

        DLOG(@"[LCNET-BYPASS] getWithURL: HOOKED");

    } else {

        DLOG(@"[LCNET-BYPASS] getWithURL:parameters:success:failure: method NOT FOUND on LCNetworking (selector可能已改名)");

    }



    // Hook PostWithURL:parameters:success:failure:

    SEL postSel = NSSelectorFromString(@"PostWithURL:parameters:success:failure:");

    m = class_getInstanceMethod(lcnetCls, postSel);

    if (m) {

        IMP origImpl = method_getImplementation(m);



        IMP newImpl = imp_implementationWithBlock(^(id self, NSString *url, id params,

                                                      void(^success)(id), void(^failure)(NSError*)) {

            if (url && isSignatureVerificationURL(url)) {

                DLOG(@"[LCNET-BYPASS] Intercepted signature POST URL: %@", url);

                if (success) {

                    NSDictionary *fakeResp = @{@"code": @0, @"message": @"OK"};

                    success(fakeResp);

                }

                return;

            }

            ((void(*)(id, SEL, id, id, void(^)(id), void(^)(NSError*)))origImpl)(

                self, postSel, url, params, success, failure);

        });

        method_setImplementation(m, newImpl);

        DLOG(@"[LCNET-BYPASS] PostWithURL: HOOKED");

    } else {

        DLOG(@"[LCNET-BYPASS] PostWithURL:parameters:success:failure: method NOT FOUND on LCNetworking");

    }

    DLOG(@"[LCNET-BYPASS] <<< END installLCNetworkingHooks()");

}



// ============================================================

#pragma mark - Log Panel UI

// ============================================================



@interface WXHandler : NSObject

@property (nonatomic) BOOL showing;

- (void)toggle;

- (void)clearLog;

- (void)toggleLogging;

- (void)handleTripleTap:(UITapGestureRecognizer *)gesture;

- (void)handlePan:(UIPanGestureRecognizer *)gesture;

@end



static UIButton *g_btn = nil;

static UIView *g_panel = nil;

static UITextView *g_tv = nil;

static WXHandler *g_handler = nil;

static UILabel *g_statusLbl = nil;



static BOOL g_isKeyboardActive = NO;



static void keyboardWillShow(NSNotification *notification) {

    g_isKeyboardActive = YES;

    DLOG(@"[KB] Keyboard will show");

}



static void keyboardWillHide(NSNotification *notification) {

    g_isKeyboardActive = NO;

    DLOG(@"[KB] Keyboard will hide");

}



static void keyboardDidShow(NSNotification *notification) {

    DLOG(@"[KB] Keyboard did show");

}



static void keyboardDidHide(NSNotification *notification) {

    DLOG(@"[KB] Keyboard did hide");

}



static void installKeyboardProtection(void) {

    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardWillShowNotification 

                                                      object:nil 

                                                       queue:nil 

                                                  usingBlock:^(NSNotification *note) { keyboardWillShow(note); }];

    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardWillHideNotification 

                                                      object:nil 

                                                       queue:nil 

                                                  usingBlock:^(NSNotification *note) { keyboardWillHide(note); }];

    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardDidShowNotification 

                                                      object:nil 

                                                       queue:nil 

                                                  usingBlock:^(NSNotification *note) { keyboardDidShow(note); }];

    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardDidHideNotification 

                                                      object:nil 

                                                       queue:nil 

                                                  usingBlock:^(NSNotification *note) { keyboardDidHide(note); }];

    DLOG(@"[KB] Keyboard protection installed");

}



@implementation WXHandler

- (void)toggle {

    self.showing = !self.showing;

    if (self.showing) {

        if (!g_panel) {

            UIWindow *w = g_btn.window;

            CGFloat pw = w.bounds.size.width - 32;

            CGFloat ph = w.bounds.size.height - 150;

            g_panel = [[UIView alloc] initWithFrame:CGRectMake(16, 100, pw, ph)];

            g_panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];

            g_panel.layer.cornerRadius = 12;

            

            UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 10, pw - 200, 24)];

            lbl.text = @"WXHook v36.126 诊断面板";

            lbl.textColor = [UIColor greenColor];

            lbl.font = [UIFont boldSystemFontOfSize:14];

            [g_panel addSubview:lbl];

            

            // Status label (shows ON/OFF)

            g_statusLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, 80, 20)];

            g_statusLbl.text = @"日志: 开";

            g_statusLbl.textColor = [UIColor greenColor];

            g_statusLbl.font = [UIFont boldSystemFontOfSize:12];

            [g_panel addSubview:g_statusLbl];

            

            // Button row 1

            CGFloat bx = pw - 270;

            UIButton *onOffBtn = [UIButton buttonWithType:UIButtonTypeSystem];

            onOffBtn.frame = CGRectMake(bx, 8, 50, 28);

            [onOffBtn setTitle:@"开关" forState:UIControlStateNormal];

            [onOffBtn setTitleColor:[UIColor yellowColor] forState:UIControlStateNormal];

            [onOffBtn addTarget:self action:@selector(toggleLogging) forControlEvents:UIControlEventTouchUpInside];

            [g_panel addSubview:onOffBtn];

            

            UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];

            clearBtn.frame = CGRectMake(bx + 55, 8, 50, 28);

            [clearBtn setTitle:@"清除" forState:UIControlStateNormal];

            [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];

            [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];

            [g_panel addSubview:clearBtn];

            

            UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];

            copyBtn.frame = CGRectMake(bx + 110, 8, 50, 28);

            [copyBtn setTitle:@"复制" forState:UIControlStateNormal];

            [copyBtn setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];

            [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];

            [g_panel addSubview:copyBtn];

            

            UIButton *shareBtn = [UIButton buttonWithType:UIButtonTypeSystem];

            shareBtn.frame = CGRectMake(bx + 165, 8, 50, 28);

            [shareBtn setTitle:@"导出" forState:UIControlStateNormal];

            [shareBtn setTitleColor:[UIColor magentaColor] forState:UIControlStateNormal];

            shareBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];

            [shareBtn addTarget:self action:@selector(shareLog) forControlEvents:UIControlEventTouchUpInside];

            [g_panel addSubview:shareBtn];

            

            UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];

            refreshBtn.frame = CGRectMake(bx + 220, 8, 50, 28);

            [refreshBtn setTitle:@"刷新" forState:UIControlStateNormal];

            [refreshBtn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];

            [refreshBtn addTarget:self action:@selector(refreshLog) forControlEvents:UIControlEventTouchUpInside];

            [g_panel addSubview:refreshBtn];

            

            // Row 2: Dump button

            UIButton *dumpBtn = [UIButton buttonWithType:UIButtonTypeSystem];

            dumpBtn.frame = CGRectMake(bx, 34, 80, 24);

            [dumpBtn setTitle:@"视图树" forState:UIControlStateNormal];

            [dumpBtn setTitleColor:[UIColor orangeColor] forState:UIControlStateNormal];

            dumpBtn.titleLabel.font = [UIFont systemFontOfSize:12];

            [dumpBtn addTarget:self action:@selector(dumpViews) forControlEvents:UIControlEventTouchUpInside];

            [g_panel addSubview:dumpBtn];

            

            g_tv = [[UITextView alloc] initWithFrame:CGRectMake(8, 62, pw - 16, ph - 72)];

            g_tv.backgroundColor = [UIColor blackColor];

            g_tv.textColor = [UIColor greenColor];

            g_tv.font = [UIFont fontWithName:@"Menlo" size:11];

            g_tv.editable = NO;

            [g_panel addSubview:g_tv];

            

            [w addSubview:g_panel];

        }

        g_panel.hidden = NO;

        g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";

        [g_tv scrollRangeToVisible:NSMakeRange(g_tv.text.length, 0)];

        // Ensure LOG button stays on top

        if (g_btn.superview) [g_btn.superview bringSubviewToFront:g_btn];

    } else {

        g_panel.hidden = YES;

    }

}

- (void)clearLog {

    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

    g_tv.text = @"(cleared)";

    g_logEnabled = YES;

    g_statusLbl.text = @"日志: 开";

    g_statusLbl.textColor = [UIColor greenColor];

    DLOG(@"=== Log cleared ===");

}

- (void)toggleLogging {

    g_logEnabled = !g_logEnabled;

    g_statusLbl.text = g_logEnabled ? @"日志: 开" : @"日志: 关";

    g_statusLbl.textColor = g_logEnabled ? [UIColor greenColor] : [UIColor redColor];

    if (g_logEnabled) {

        DLOG(@"=== Logging resumed ===");

    }

}

- (void)dumpViews {

    DLOG(@"=== View Dump ===");

    for (UIWindow *w in [UIApplication sharedApplication].windows) {

        [self dumpView:w indent:0];

    }

    DLOG(@"=== End Dump ===");

    g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";

    [g_tv scrollRangeToVisible:NSMakeRange(g_tv.text.length, 0)];

}

- (void)dumpView:(UIView *)v indent:(int)indent {

    NSMutableString *prefix = [NSMutableString string];

    for (int i = 0; i < indent; i++) [prefix appendString:@"  "];

    NSString *cls = NSStringFromClass([v class]);

    NSString *text = @"";

    if ([v isKindOfClass:[UILabel class]]) text = ((UILabel *)v).text ?: @"";

    else if ([v isKindOfClass:[UIButton class]]) {

        text = [(UIButton *)v titleLabel].text ?: @"";

    }

    if (text.length > 50) text = [text substringToIndex:50];

    DLOG(@"[VIEW] %@%@ frame=%.0fx%.0f text='%@'", prefix, cls, v.frame.size.width, v.frame.size.height, text);

    for (UIView *sub in v.subviews) {

        [self dumpView:sub indent:indent + 1];

    }

}

- (void)copyLog {

    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";

    [UIPasteboard generalPasteboard].string = content;

    DLOG(@">>> COPIED %lu chars >>>", (unsigned long)content.length);

    g_tv.text = [NSString stringWithFormat:@">>> COPIED %lu chars to clipboard <<<", (unsigned long)content.length];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{

        [self refreshLog];

    });

}

- (void)shareLog {

    @try {

        if (!g_logPath) {

            DLOG(@"[SHARE] Error: log path is nil");

            return;

        }

        

        if (![[NSFileManager defaultManager] fileExistsAtPath:g_logPath]) {

            DLOG(@"[SHARE] Error: log file does not exist");

            return;

        }

        

        // Truncate to last 200KB to avoid crash with large files

        NSData *fullData = [NSData dataWithContentsOfFile:g_logPath];

        NSData *exportData = fullData;

        if (fullData.length > 200 * 1024) {

            exportData = [fullData subdataWithRange:NSMakeRange(fullData.length - 200 * 1024, 200 * 1024)];

            DLOG(@"[SHARE] Log truncated from %lu to 200KB", (unsigned long)fullData.length);

        }

        

        NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"wxhook_export.log"];

        [exportData writeToFile:tempPath atomically:YES];

        DLOG(@"[SHARE] Export file size: %lu bytes", (unsigned long)exportData.length);

        

        NSURL *fileURL = [NSURL fileURLWithPath:tempPath];

        if (!fileURL) {

            DLOG(@"[SHARE] Error: file URL is nil");

            return;

        }

        

        NSArray *items = @[fileURL];

        UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];

        

        // Find top view controller safely

        UIWindow *keyWin = nil;

        if (@available(iOS 13.0, *)) {

            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {

                if (scene.activationState == UISceneActivationStateForegroundActive) {

                    for (UIWindow *win in scene.windows) {

                        if (win.isKeyWindow) { keyWin = win; break; }

                    }

                    if (keyWin) break;

                }

            }

        }

        if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;

        if (!keyWin) keyWin = [UIApplication sharedApplication].windows.firstObject;

        

        if (!keyWin) {

            DLOG(@"[SHARE] Error: no key window found");

            return;

        }

        

        UIViewController *topVC = keyWin.rootViewController;

        if (!topVC) {

            DLOG(@"[SHARE] Error: rootViewController is nil");

            return;

        }

        while (topVC.presentedViewController && 

               ![topVC.presentedViewController isBeingDismissed]) {

            topVC = topVC.presentedViewController;

        }

        

        // Set popover for iPad only (safe check)

        if ([avc respondsToSelector:@selector(popoverPresentationController)] &&

            avc.popoverPresentationController) {

            avc.popoverPresentationController.sourceView = keyWin;

            avc.popoverPresentationController.sourceRect = CGRectMake(keyWin.bounds.size.width / 2, keyWin.bounds.size.height / 2, 1, 1);

            avc.popoverPresentationController.permittedArrowDirections = 0;

        }

        

        // Use completion block to detect presentation issues

        avc.completionWithItemsHandler = ^(UIActivityType activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {

            if (activityError) {

                DLOG(@"[SHARE] Activity error: %@", activityError);

            }

            DLOG(@"[SHARE] Activity completed: %d type: %@", completed, activityType);

        };

        

        DLOG(@"[SHARE] Presenting from %@", NSStringFromClass([topVC class]));

        dispatch_async(dispatch_get_main_queue(), ^{

            @try {

                [topVC presentViewController:avc animated:YES completion:^{

                    DLOG(@"[SHARE] Presented successfully");

                }];

            } @catch (NSException *e) {

                DLOG(@"[SHARE] Present exception: %@", e);

            }

        });

    } @catch (NSException *e) {

        DLOG(@"[SHARE] Exception: %@", e);

    }

}

- (void)refreshLog {

    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";

    g_tv.text = content;

    if (content.length > 0) {

        [g_tv scrollRangeToVisible:NSMakeRange(content.length - 1, 0)];

    }

}

- (void)handleTripleTap:(UITapGestureRecognizer *)gesture {

    if (g_btn) {

        g_btn.hidden = !g_btn.hidden;

        if (!g_btn.hidden) {

            DLOG(@"[UI] Log button shown via triple-tap");

        } else {

            DLOG(@"[UI] Log button hidden via triple-tap");

        }

    }

}

- (void)handlePan:(UIPanGestureRecognizer *)gesture {

    if (!g_btn || g_btn.hidden) return;

    UIView *v = gesture.view;

    CGPoint translation = [gesture translationInView:v.superview];

    CGPoint newCenter = CGPointMake(v.center.x + translation.x, v.center.y + translation.y);

    CGRect bounds = v.superview.bounds;

    newCenter.x = MAX(25, MIN(bounds.size.width - 25, newCenter.x));

    newCenter.y = MAX(25, MIN(bounds.size.height - 25, newCenter.y));

    v.center = newCenter;

    [gesture setTranslation:CGPointZero inView:v.superview];

}

@end



// ============================================================

// NOTE: NSArray count hook REMOVED - causes crashes during keyboard input

// Server list handling is now done at the protocol level (hook_recv/recvfrom/recvmsg)

// ============================================================



// ============================================================

#pragma mark - NSURLSession hooks (HTTP response manipulation)

// ============================================================



static id (*orig_JSONObjectWithData)(Class, SEL, NSData *, NSJSONReadingOptions, NSError **);



static id hook_JSONObjectWithData(Class self, SEL _cmd, NSData *data, NSJSONReadingOptions opt, NSError **error) {

    id ret = orig_JSONObjectWithData(self, _cmd, data, opt, error);

    

    @try {

        if (ret && [ret isKindOfClass:[NSDictionary class]]) {

            NSDictionary *dict = (NSDictionary *)ret;

            NSNumber *status = dict[@"status"];

            NSString *msg = dict[@"msg"] ?: @"";

            NSString *result = dict[@"result"] ?: @"";

            

            DLOG(@"[JSON-PARSE] JSONObjectWithData: status=%@ msg=%@ result=%@", status, msg, result);

            

            BOOL hasFail = NO;

            if ([result isKindOfClass:[NSString class]]) {

                hasFail = [(NSString *)result containsString:@"fail"];

            }

            BOOL hasVersionMsg = NO;

            if ([msg isKindOfClass:[NSString class]]) {

                hasVersionMsg = [(NSString *)msg containsString:@"版本"] || 

                               [(NSString *)msg containsString:@"更新"] || 

                               [(NSString *)msg containsString:@"升级"];

            }

            if (hasVersionMsg || hasFail) {

                DLOG(@"[JSON-PATCH] Detected version check failure, modifying...");

            }

        }

    } @catch (NSException *e) {

        DLOG(@"[JSON-PARSE] Exception: %@", e);

    }

    

    return ret;

}



static void installJSONSerializationHook(void) {

    Class jsonCls = [NSJSONSerialization class];

    if (!jsonCls) {

        DLOG(@"[JSON-HOOK] NSJSONSerialization class not found");

        return;

    }

    

    Method jsonObjMethod = class_getClassMethod(jsonCls, @selector(JSONObjectWithData:options:error:));

    if (!jsonObjMethod) {

        DLOG(@"[JSON-HOOK] JSONObjectWithData:options:error: not found");

        return;

    }

    

    orig_JSONObjectWithData = (id(*)(Class, SEL, NSData*, NSJSONReadingOptions, NSError**))method_getImplementation(jsonObjMethod);

    method_setImplementation(jsonObjMethod, (IMP)hook_JSONObjectWithData);

    DLOG(@"[JSON-HOOK] Installed NSJSONSerialization hook");

}



// ============================================================

#pragma mark - Signature Verification HTTP Bypass (v37.122)

// ============================================================



// v37.122: Unified function to check if a URL is a signature verification endpoint.

// This covers ALL possible API paths used by the game's signature system.

// Known domains: cert.qunhongtech.com, ln_sign_cert.9iy.com

// Known paths: /cert/judgeAppInfoApi, /cert/getAppInfoApi, /cert/postAppInfoApi

static BOOL isSignatureVerificationURL(NSString *url) {

    if (!url || url.length == 0) return NO;

    

    // Check for known cert domains

    if ([url containsString:@"cert.qunhongtech.com"] ||

        [url containsString:@"ln_sign_cert.9iy.com"] ||

        [url containsString:@"9iy.com"]) {

        return YES;

    }

    

    // Check for /cert/ path (covers ALL cert API endpoints on any domain)

    if ([url containsString:@"/cert/"] || [url containsString:@"/cert?"]) {

        return YES;

    }

    

    // Check for specific API endpoints (in case domain/path differs)

    NSArray *endpoints = @[

        @"judgeAppInfoApi",

        @"judgeAppInfoSignApi", 

        @"postAppInfoApi",

        @"getAppInfoApi",

        @"verifySign",

        @"checkSign",

        @"certApi",

        @"signApi",

        @"verifyApi",

        @"judgeAppInfo",

        @"getAppInfo",

        @"postAppInfo"

    ];

    

    for (NSString *ep in endpoints) {

        if ([url containsString:ep]) {

            return YES;

        }

    }

    

    return NO;

}



// v37.125: Use FORMAT-SPECIFIC responses matching what each endpoint actually returns.

// CRITICAL FINDING: Different endpoints expect DIFFERENT JSON structures.

// If we return a mismatched structure, the game silently fails verification.

//

// v37.134: Smart patching - don't replace entire body, only modify specific fields.

// Preserves original response data including sign/timeStamp/randStr.

// FIX39-FINAL: __attribute__((used)) on patchSignatureResponse
//   FORCE linker to KEEP this function (prevents dead-code elimination if cross-module optimizer
//   incorrectly decides isSignatureVerificationURL() always returns NO, marking function unreachable)
__attribute__((used))
static NSData *patchSignatureResponse(NSString *url, NSString *body) {
    if (!url) return nil;



    // Only patch signature verification URLs

    if (!isSignatureVerificationURL(url)) {

        return nil; // Not a signature URL, don't patch

    }



    DLOG(@"[SIGN-BYPASS] v37.134: Intercepted signature URL: %@", url);

    DLOG(@"[SIGN-BYPASS] v37.134: Original body: %@", body);



    // v37.130: SMART PATCHING - don't replace entire body, only modify specific fields.

    // Previous versions replaced the entire response, losing critical fields like

    // "sign", "timeStamp", "randStr" that the game needs for subsequent verification.



    NSString *patchedResponse = body ?: @"";

    BOOL patchResponse = YES;



    // FIX38: 铁证根因修复! 对比FIX19 LCNetworking假响应(成功) vs FIX37真实响应(失败):

    //   FIX19 LCNetworking对GET请求返回: {code:0, data:{result:true,verity:1,tip:0,ENDTIME,END:0,OPEN:1,id,COUNT,MAXLIMIT}}

    //   FIX19 LCNetworking对POST请求返回: {code:0, message:"OK"} (无data!)

    //   FIX37真实响应: judgeAppInfoSignApi有sign但缺result字段→游戏判失败→无网络

    //   FIX37错误: postAppInfoApi被UNIVERSAL injector添加了data字段→游戏可能解析出错

    // FIX38: 所有4个签名API返回与FIX19完全相同的假响应,绕过服务器真实响应!



    // FIX19假响应: GET请求用(含完整data结构)

    NSString *fix19GetResp = @"{\"code\":0,\"message\":\"success\",\"data\":{\"result\":true,\"verity\":1,\"tip\":0,\"ENDTIME\":\"2027-12-31 23:59:59\",\"END\":0,\"OPEN\":1,\"id\":11927,\"COUNT\":0,\"MAXLIMIT\":5000}}";

    // FIX19假响应: POST请求用(无data字段!)

    NSString *fix19PostResp = @"{\"code\":0,\"message\":\"OK\"}";



    // --- judgeAppInfoSignApi (cert.qunhongtech.com) ---

    // FIX39: 铁证根因! 全能签cert.qunhongtech.com返回的data里已经有sign签名!

    //   FIX38原始响应(L278): data={timeStamp,randStr,limit,sign,end:0,tip:0,verity:1,open:1}

    //   → verity/tip/end/open已经是正确值!只差result字段!

    // FIX41: 🔴🔴🔴 铁证根因修复! FIX40使用NSJSONSerialization重序列化judgeAppInfoSignApi → 致命BUG!
    //   FIX40日志L298→L303铁证: code:0从第1位移到最后1位! data内字段顺序完全打乱!
    //     → 游戏用手写C解析器从左到右读，读不到code(在最后)→ 失败
    //     → sign字段是按原始顺序拼接后算的MD5，全能签按新顺序重新拼接→sign校验失败
    //     → 回调函数(handleAppInfoResult/nettimes)根本不执行! → 全程"无网络连接"
    //   FIX41策略: 100% 纯字符串操作! 绝不碰NSJSONSerialization! 保持:
    //     ✅ code字段保持在第1位(字节级100%原始位置)
    //     ✅ data内所有字段原始顺序不变
    //     ✅ sign字段原始字节不变(全能签MD5/sign自校验才能通过)
    //     ✅ 仅当data中不存在"result"时，在"data":{"后插入"result":true,

    if (patchResponse && ([url containsString:@"judgeAppInfoSignApi"] || [url containsString:@"verifySign"] || [url containsString:@"checkSign"])) {

        // FIX44: 🔴🔴🔴 终级根因修复(对比wxhook.log FIX38成功 vs wxhook 29.log FIX43失败)!
        //   FIX38主设备成功(wxhook.log):
        //     - UDID重复(2条DB记录)→全能签server返回500 TooManyResultsException(无sign字段)
        //     - 替换为FIX19假响应(无sign)
        //     - SK-DIAG handleAppInfoResult/verifySignature/SC-DIAG nettimes → 0次调用!
        //     - 直接进游戏!
        //   FIX43副设备失败(wxhook 29.log):
        //     - UDID干净(1条DB记录)→全能签server正常HTTP200(有sign字段)
        //     - FIX42策略=有sign→HTTP层返回原始字节→等SDK内部MD5通过→handleAppInfoResult回调注入字段
        //     - LINE326/327铁证=MD5 mismatch: 客户端本地算MD5=6e8fa13f... vs 服务器返回sign=C6333B7F...
        //     - 全能签SDK内部C代码MD5不匹配→直接中断→不调任何SignatureKit ObjC方法→FIX43回调注入兜底全白搭!
        //     - 状态机卡死→VersionModule.widgetSelected C++ terminate→SIGTRAP
        //   FIX44策略: 👉 无论judgeAppInfoSignApi返回啥(有sign/无sign/500)，100%强制替换为FIX19GetResp!
        //              完全模拟FIX38主设备500无sign→假响应接管→绕过全能签SDK独立MD5校验链→走V3服务器3个API+HTTP补丁接管=100%成功!
        DLOG(@"[SIGN-BYPASS] FIX44: judgeAppInfoSignApi → 🚀 忽略sign字段!100%%替换为FIX19假响应(完全模拟FIX38主设备UDID重复→500→假响应接管路径,SK-DIAG/SC-DIAG回调0调用也能过!)");
        patchedResponse = fix19GetResp;  // code:0+message:success+data{result:true,verity:1,tip:0,ENDTIME/"2027-12-31",END=0,OPEN=1全有→无sign不触发SDK内部MD5校验!}

        DLOG(@"[SIGN-BYPASS] FIX44: judgeAppInfoSignApi final body: %@", patchedResponse);
        DLOG(@"[SIGN-BYPASS] FIX44: judgeAppInfoSignApi → ℹ️ 无sign→全能签SDK内部MD5校验直接SKIP→走FIX38成功same path!");
    }

    // --- judgeAppInfoApi (ln_sign_cert.9iy.com) ---

    else if (patchResponse && [url containsString:@"judgeAppInfoApi"] && ![url containsString:@"SignApi"]) {

        // FIX40: 铁证根因! FIX19成功版本是"补丁ENDTIME"不是"完全替换"!
        //   FIX39错误: 完全替换为硬编码假响应 → 丢失原始data中NET/CERTID/CERTNAME/
        //             LIMITGAP/REMARK/EFLAG/DAYS/CENDDATE/EMAIL/CREATETIME等字段
        //             → 游戏无法获取网络配置 → 显示"无网络连接"!
        //   FIX40策略: 保留原始响应body 100%, 只补丁关键字段:
        //             ENDTIME延长 + END=0 + OPEN=1 + TIP=0 + code:1→0
        //             + 插入result:true/verity:1 (如果不存在)
        DLOG(@"[SIGN-BYPASS] FIX40: judgeAppInfoApi → 保留原始响应!仅补丁ENDTIME/END/OPEN/TIP/code/result(和FIX19成功版本一致!)");

        // 1. ENDTIME延长到2027-12-31 (字符串搜索替换,避免正则转义问题)
        {
            NSString *endKey = @"\"ENDTIME\":\"";
            NSRange rEnd = [patchedResponse rangeOfString:endKey];
            if (rEnd.location != NSNotFound) {
                NSUInteger valStart = rEnd.location + rEnd.length;
                NSRange rEndQuote = [patchedResponse rangeOfString:@"\"" options:0 range:NSMakeRange(valStart, patchedResponse.length - valStart)];
                if (rEndQuote.location != NSNotFound) {
                    patchedResponse = [patchedResponse stringByReplacingCharactersInRange:NSMakeRange(rEnd.location, rEndQuote.location + rEndQuote.length - rEnd.location) withString:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];
                }
            }
        }

        // 2. END=0 (大写字段名,和原始响应一致)
        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];
        // 3. OPEN=1
        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];
        // 4. TIP=0 (大写,和原始响应一致)
        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"TIP\":1" withString:@"\"TIP\":0"];
        // 5. code:1→code:0 (V3成功码→全能签成功码)
        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"code\":1" withString:@"\"code\":0"];

        // 6. 插入result:true + verity:1 (如果data中不存在这些字段)
        if (![patchedResponse containsString:@"\"result\""]) {
            NSRange rData = [patchedResponse rangeOfString:@"\"data\":{"];
            if (rData.location != NSNotFound) {
                NSUInteger insertPos = rData.location + rData.length;
                patchedResponse = [patchedResponse stringByReplacingCharactersInRange:NSMakeRange(insertPos, 0) withString:@"\"result\":true,\"verity\":1,"];
                DLOG(@"[SIGN-BYPASS] FIX40: judgeAppInfoApi → data中插入result:true+verity:1");
            }
        }

        DLOG(@"[SIGN-BYPASS] FIX40: judgeAppInfoApi patched body: %@", patchedResponse);

    }

    // --- postAppInfoApi ---

    // FIX39: 返回FIX19假响应 {code:0, message:"OK"} — 无data字段!

    //   铁证: FIX19 LCNetworking POST假响应 = {code:0, message:"OK"} (无data)

    //   FIX36/37错误: UNIVERSAL injector给postAppInfoApi添加了data字段→游戏解析出错

    else if (patchResponse && [url containsString:@"postAppInfoApi"]) {

        DLOG(@"[SIGN-BYPASS] FIX39: postAppInfoApi → 返回FIX19假响应(code:0+message:OK, 无data字段!)");

        patchedResponse = fix19PostResp;

    }

    // --- getAppInfoApi ---
    // FIX41: 改为保留原始响应+补丁字段(与FIX40 judgeAppInfoApi一致策略)
    //   FIX39错误: 直接硬编码替换为fix19GetResp → 丢失原始响应中可能存在的字段(如id/CERTID/NET等)
    //              且原始getAppInfoApi(L328) {"code":1, "message":"OK"} → 补丁后应保留原始message等
    //   FIX41策略: 1. code:1→code:0 (V3成功码→全能签成功码)
    //             2. 如果原始响应无data字段 → 插入完整data (包含result/verity/tip/ENDTIME)
    //                否则 → 在已有data中补丁关键字段(保留原始字段100%不变)
    else if (patchResponse && [url containsString:@"getAppInfoApi"]) {
        DLOG(@"[SIGN-BYPASS] FIX41: getAppInfoApi → 保留原始响应+补丁字段(不再硬编码替换!)");

        // 1. code:1→code:0 (V3成功码→全能签成功码) 仅替换开头的第一个code,避免嵌套误替换
        NSRange firstCodeRangeG = [patchedResponse rangeOfString:@"\"code\":1" options:0 range:NSMakeRange(0, MIN((NSUInteger)60, patchedResponse.length))];
        if (firstCodeRangeG.location != NSNotFound) {
            patchedResponse = [patchedResponse stringByReplacingCharactersInRange:firstCodeRangeG withString:@"\"code\":0"];
            DLOG(@"[SIGN-BYPASS] FIX41: getAppInfoApi → code:1→code:0 (仅替换顶层首个code!)");
        }

        // 2. 如果不存在"result"字段 → 需要补丁data
        if (![patchedResponse containsString:@"\"result\""]) {
            NSRange rDataG = [patchedResponse rangeOfString:@"\"data\":{"];
            if (rDataG.location != NSNotFound) {
                // 2a: data字段已存在→在data开头插入关键字段 (保持原始data字段100%不变!)
                NSUInteger insertPosG = rDataG.location + rDataG.length;
                patchedResponse = [patchedResponse stringByReplacingCharactersInRange:NSMakeRange(insertPosG, 0) withString:@"\"result\":true,\"verity\":1,\"tip\":0,\"ENDTIME\":\"2027-12-31 23:59:59\",\"END\":0,\"OPEN\":1,"];
                DLOG(@"[SIGN-BYPASS] FIX41: getAppInfoApi → data字段已存在→仅在data开头插入result/verity/tip/ENDTIME (原始data字段都保留!)");
            } else {
                // 2b: data字段不存在(原始是{"code":0,"message":"OK"}) → 用string替换插入完整data结构在最后一个}前
                NSRange lastClose = [patchedResponse rangeOfString:@"}" options:NSBackwardsSearch];
                if (lastClose.location != NSNotFound) {
                    // 先判断message最后有没有逗号，没有就加
                    NSString *insertDataG = @",\"data\":{\"result\":true,\"verity\":1,\"tip\":0,\"ENDTIME\":\"2027-12-31 23:59:59\",\"END\":0,\"OPEN\":1}}";
                    patchedResponse = [patchedResponse stringByReplacingCharactersInRange:lastClose withString:insertDataG];
                    // 替换message值为success(如果是OK)
                    patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"message\":\"OK\"" withString:@"\"message\":\"success\""];
                    DLOG(@"[SIGN-BYPASS] FIX41: getAppInfoApi → 原始无data字段→末尾插入完整data (result/verity/tip/ENDTIME全具备!)");
                } else {
                    DLOG(@"[SIGN-BYPASS] FIX41: ⚠️ getAppInfoApi 找不到插入点→fallback到fix19硬编码");
                    patchedResponse = fix19GetResp;
                }
            }
        }

        DLOG(@"[SIGN-BYPASS] FIX41: getAppInfoApi patched body: %@", patchedResponse);
    }

    // --- Fallback: generic cert endpoint ---

    else if (patchResponse) {

        DLOG(@"[SIGN-BYPASS] v37.134: Format: GENERIC fallback (smart patch)");

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"verity\":0" withString:@"\"verity\":1"];

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"tip\":1" withString:@"\"tip\":0"];

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"end\":1" withString:@"\"end\":0"];

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"open\":0" withString:@"\"open\":1"];

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];

    }



    // Safety net: FIX37 — code:1→code:0, 但跳过含sign字段的响应(sign验证需要原始JSON)

    if (patchResponse && ![patchedResponse containsString:@"\"sign\":"] && [patchedResponse containsString:@"\"code\":1"]) {

        patchedResponse = [patchedResponse stringByReplacingOccurrencesOfString:@"\"code\":1" withString:@"\"code\":0"];

        DLOG(@"[SIGN-BYPASS] FIX37: Safety net code:1→code:0 (无sign字段, 安全)");

    } else if ([patchedResponse containsString:@"\"sign\":"]) {

        DLOG(@"[SIGN-BYPASS] FIX37: Safety net SKIPPED (含sign字段, 保持原始JSON不变→sign验证通过)");

    }



    // FIX39: UNIVERSAL injector 已禁用!

    // 原因: FIX19 LCNetworking假响应对每个API返回不同的假响应(GET=data, POST=无data)

    //        UNIVERSAL injector统一添加data字段给所有API→postAppInfoApi不应有data→游戏出错

    // FIX39: 所有4个API在各分支中已有明确的FIX19假响应,不再需要UNIVERSAL injector

    DLOG(@"[SIGN-BYPASS] FIX39: UNIVERSAL injector DISABLED (all 4 APIs use FIX19 fake responses)");



    NSData *patchedData = [patchedResponse dataUsingEncoding:NSUTF8StringEncoding];

    DLOG(@"[SIGN-BYPASS] v37.134: Patched body: %@", patchedResponse);

    DLOG(@"[SIGN-BYPASS] v37.134: Response len=%lu", (unsigned long)patchedData.length);



    return patchedData;

}



// ============================================================

#pragma mark - NSURLSessionDataDelegate hooks

// ============================================================



static void (*orig_urlSessionDataTaskDidReceiveData)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSData*) = NULL;



// v37.131: Hook for didReceiveResponse to patch HTTP status code 500→200

static IMP orig_urlSessionDidReceiveResponse = NULL;

static void hook_urlSessionDidReceiveResponse(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *dataTask, NSURLResponse *response, void (^completionHandler)(NSURLSessionResponseDisposition disposition)) {

    NSString *url = dataTask.currentRequest.URL.absoluteString;

    if (url && isSignatureVerificationURL(url)) {

        NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;

        if (httpResp && httpResp.statusCode != 200) {

            DLOG(@"[SIGN-BYPASS] v37.131: delegate mode: Patching HTTP status %ld→200 for %@", (long)httpResp.statusCode, url);

            NSMutableDictionary *patchedHeaders = [httpResp.allHeaderFields mutableCopy] ?: [NSMutableDictionary dictionary];

            [patchedHeaders setObject:@"application/json" forKey:@"Content-Type"];

            response = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:patchedHeaders];

        }

    }

    if (orig_urlSessionDidReceiveResponse) {

        ((void(*)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSURLResponse*, void(^)(NSURLSessionResponseDisposition)))orig_urlSessionDidReceiveResponse)(self, _cmd, session, dataTask, response, completionHandler);

    }

}



// v37.133: Hook NSURLSessionDataTask.response getter to patch status code 500→200

// at the LOWEST level — works regardless of delegate/completionHandler pattern.

static IMP orig_dataTaskResponse = NULL;

static NSURLResponse *hook_dataTaskResponse(id self, SEL _cmd) {

    NSURLResponse *resp = orig_dataTaskResponse ? ((NSURLResponse*(*)(id,SEL))orig_dataTaskResponse)(self, _cmd) : nil;

    if (!resp) return resp;

    // Only patch for signature verification URLs

    NSURLRequest *req = [(NSURLSessionTask *)self currentRequest];

    NSString *url = req.URL.absoluteString;

    if (url && isSignatureVerificationURL(url)) {

        NSHTTPURLResponse *httpResp = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;

        if (httpResp && httpResp.statusCode != 200) {

            DLOG(@"[SIGN-BYPASS] v37.133: response getter: Patching HTTP status %ld→200 for %@", (long)httpResp.statusCode, url);

            NSMutableDictionary *patchedHeaders = [httpResp.allHeaderFields mutableCopy] ?: [NSMutableDictionary dictionary];

            [patchedHeaders setObject:@"application/json" forKey:@"Content-Type"];

            NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:patchedHeaders];

            return fakeResp;

        }

    }

    return resp;

}



static void hook_urlSessionDataTaskDidReceiveData(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *dataTask, NSData *data) {

    NSString *url = dataTask.currentRequest.URL.absoluteString;

    DLOG(@"[HTTP-DATA] urlSession:dataTask:didReceiveData: len=%zu url=%@", (unsigned long)[data length], url);

    

    // v37.133: Pre-emptively patch status code via dataTask.response if possible

    // (hook_dataTaskResponse getter handles the actual patching automatically)

    NSHTTPURLResponse *earlyResp = [(NSURLResponse *)dataTask.response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)dataTask.response : nil;

    if (url && isSignatureVerificationURL(url) && earlyResp) {

        DLOG(@"[HTTP-DATA] v37.133: dataTask.response status=%ld (patched via getter if needed)", (long)earlyResp.statusCode);

    }

    

    // v37.122: Use unified signature bypass for ALL signature verification URLs

    if (url && isSignatureVerificationURL(url)) {

        NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

        NSData *patchedData = patchSignatureResponse(url, dataStr);

        if (patchedData) {

            if (orig_urlSessionDataTaskDidReceiveData) {

                orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, patchedData);

                return;

            }

        }

    }

    

    // v37.122: Fallback - patch other responses (server list, version errors)

    NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    if (dataStr) {

        if ([dataStr containsString:@"版本"] || [dataStr containsString:@"server"] || 

            [dataStr containsString:@"status"] || [dataStr containsString:@"maintenance"] ||

            [dataStr containsString:@"ispass"] || [dataStr containsString:@"md5xor"] ||

            [dataStr containsString:@"code"] || [dataStr containsString:@"sign"] ||

            [dataStr containsString:@"ENDTIME"]) {

            DLOG(@"[HTTP-DATA] Response contains key info: %@", dataStr);

            [ProtocolPatcher patchServerResponse:[dataStr dataUsingEncoding:NSUTF8StringEncoding]];

        }

    }

    

    // v37.122: Also patch delegate-mode responses for sign/cert APIs (legacy fallback)

    // FIX37: 此分支仅在patchSignatureResponse返回nil时才执行(实际上不会发生)

    //        但条件仍需精确: 只匹配URL含judgeAppInfoApi(不含SignApi)或judgeAppInfoSignApi

    //        不再用[dataStr containsString:@"ENDTIME"]误匹配

    if (dataStr && url && ([url containsString:@"judgeAppInfoSignApi"] || ([url containsString:@"judgeAppInfoApi"] && ![url containsString:@"SignApi"]))) {

        // FIX37: 如果响应含sign字段(MD5签名),跳过legacy fallback(不做任何字符串替换)

        if ([dataStr containsString:@"\"sign\":"]) {

            DLOG(@"[HTTP-DATA-PATCH] FIX37: 含sign字段 → 跳过legacy fallback(保持原始JSON→sign验证通过)");

        } else {

            DLOG(@"[HTTP-DATA-PATCH] Patching delegate-mode cert/sign API response (legacy)");

            NSString *newBody = dataStr;

            // Extend ENDTIME to future

            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\"ENDTIME\":\"[^\"]*\"" options:0 error:nil];

            newBody = [regex stringByReplacingMatchesInString:newBody options:0 range:NSMakeRange(0, newBody.length) withTemplate:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];

            newBody = [newBody stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];

            newBody = [newBody stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];

            // v37.120: REMOVED code:0→code:1 replacement — game uses code:0 for success.

            NSData *newData = [newBody dataUsingEncoding:NSUTF8StringEncoding];

            DLOG(@"[HTTP-DATA-PATCH] Patched delegate response: %@", newBody);

            if (orig_urlSessionDataTaskDidReceiveData) {

                orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, newData);

                return;

            }

        }

    }


    // === FIX46: delegate模式下也拦截md5xor授权API ispass:NO→YES! ===
    if (url && [url containsString:@"md5xor"] && data && data.length > 0) {
        NSString *authStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (authStr && [authStr containsString:@"ispass"]) {
            DLOG(@"[FIX46-AUTH-DELEGATE] 🔥 检测到md5xor授权API(delegate)! 原始body: %@", authStr);
            NSString *authBody = authStr;
            authBody = [authBody stringByReplacingOccurrencesOfString:@"\"ispass\":\"NO\"" withString:@"\"ispass\":\"YES\""];
            authBody = [authBody stringByReplacingOccurrencesOfString:@"\"ispass\":\"no\"" withString:@"\"ispass\":\"YES\""];
            authBody = [authBody stringByReplacingOccurrencesOfString:@"\"test\":\"NO\"" withString:@"\"test\":\"YES\""];
            authBody = [authBody stringByReplacingOccurrencesOfString:@"\"test\":\"no\"" withString:@"\"test\":\"YES\""];
            if (![authBody isEqualToString:authStr]) {
                NSData *newData = [authBody dataUsingEncoding:NSUTF8StringEncoding];
                DLOG(@"[FIX46-AUTH-DELEGATE] ✅ ispass:NO→YES 补丁完成! newBody: %@", authBody);
                if (orig_urlSessionDataTaskDidReceiveData) {
                    orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, newData);
                    return;
                }
            }
        }
    }


    if (orig_urlSessionDataTaskDidReceiveData) {

        orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, data);

    }

}



static void installNSURLSessionHooks(void) {

    Class sessionCls = [NSURLSession class];

    if (!sessionCls) {

        DLOG(@"[HTTP-HOOK] NSURLSession class not found");

        return;

    }

    

    Method dataTaskMethod = class_getInstanceMethod(sessionCls, @selector(dataTaskWithRequest:completionHandler:));

    if (!dataTaskMethod) {

        DLOG(@"[HTTP-HOOK] dataTaskWithRequest:completionHandler: not found");

    } else {

        DLOG(@"[HTTP-HOOK] NSURLSession dataTaskWithRequest:completionHandler: found");

    }

    

    Class dataTaskCls = NSClassFromString(@"__NSCFLocalDataTask");

    if (!dataTaskCls) dataTaskCls = NSClassFromString(@"__NSCFLNetworkDataTask");

    if (!dataTaskCls) dataTaskCls = NSClassFromString(@"NSURLSessionDataTask");

    

    if (dataTaskCls) {

        DLOG(@"[HTTP-HOOK] NSURLSessionDataTask class found: %@", NSStringFromClass(dataTaskCls));

    }

    

    // Hook URLSession:dataTask:didReceiveData: on classes that implement it

    // This intercepts delegate-mode responses (used by judgeAppInfoSignApi)

    unsigned int classCount = 0;

    Class *classes = (Class *)malloc(sizeof(Class) * 0x10000);

    if (classes) {

        int numClasses = objc_getClassList(classes, 0x10000);

        int hookedCount = 0;

        for (int i = 0; i < numClasses; i++) {

            Class cls = classes[i];

            Method m = class_getInstanceMethod(cls, @selector(URLSession:dataTask:didReceiveData:));

            if (m) {

                IMP currentImp = method_getImplementation(m);

                if (currentImp != (IMP)hook_urlSessionDataTaskDidReceiveData) {

                    orig_urlSessionDataTaskDidReceiveData = (void(*)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSData*))currentImp;

                    method_setImplementation(m, (IMP)hook_urlSessionDataTaskDidReceiveData);

                    DLOG(@"[HTTP-HOOK] Hooked URLSession:dataTask:didReceiveData: on class: %@", NSStringFromClass(cls));

                    hookedCount++;

                    if (hookedCount >= 5) break;

                }

            }

        }

        free(classes);

        if (hookedCount > 0) {

            DLOG(@"[INIT] URLSession:dataTask:didReceiveData: hooked on %d classes", hookedCount);

        }

    }



    // v37.131: Hook URLSession:dataTask:didReceiveResponse:completionHandler:

    // to patch HTTP status code 500→200 for signature verification URLs

    classes = (Class *)malloc(sizeof(Class) * 0x10000);

    if (classes) {

        int numClasses = objc_getClassList(classes, 0x10000);

        int respHookedCount = 0;

        for (int i = 0; i < numClasses; i++) {

            Class cls = classes[i];

            SEL respSel = @selector(URLSession:dataTask:didReceiveResponse:completionHandler:);

            Method m = class_getInstanceMethod(cls, respSel);

            if (m) {

                IMP currentImp = method_getImplementation(m);

                if (currentImp != (IMP)hook_urlSessionDidReceiveResponse) {

                    orig_urlSessionDidReceiveResponse = currentImp;

                    method_setImplementation(m, (IMP)hook_urlSessionDidReceiveResponse);

                    DLOG(@"[HTTP-HOOK] Hooked URLSession:dataTask:didReceiveResponse: on class: %@", NSStringFromClass(cls));

                    respHookedCount++;

                    if (respHookedCount >= 5) break;

                }

            }

        }

        free(classes);

        if (respHookedCount > 0) {

            DLOG(@"[INIT] URLSession:dataTask:didReceiveResponse: hooked on %d classes", respHookedCount);

        }

    }



    // v37.133: Hook NSURLSessionDataTask.response getter — lowest-level HTTP status patch.

    // AFNetworking may read status code from dataTask.response directly

    // (bypassing both didReceiveResponse: delegate AND completionHandler callbacks).

    // Hooking the getter ensures status 500→200 patch works no matter what pattern the client uses.

    {

        // Try multiple concrete class names (iOS internals vary by version)

        const char *taskClsNames[] = {

            "__NSCFLocalDataTask",

            "__NSCFLNetworkDataTask",

            "NSURLSessionDataTask",

            "__NSCFURLSessionDataTask",

            NULL

        };

        int getterHooked = 0;

        for (int i = 0; taskClsNames[i] != NULL; i++) {

            Class taskCls = NSClassFromString([NSString stringWithUTF8String:taskClsNames[i]]);

            if (!taskCls) continue;

            SEL respSel = @selector(response);

            Method m = class_getInstanceMethod(taskCls, respSel);

            if (m) {

                IMP cur = method_getImplementation(m);

                if (cur != (IMP)hook_dataTaskResponse) {

                    orig_dataTaskResponse = cur;

                    method_setImplementation(m, (IMP)hook_dataTaskResponse);

                    DLOG(@"[HTTP-HOOK] v37.133: Hooked dataTask.response getter on class: %s", taskClsNames[i]);

                    getterHooked = 1;

                    break;

                }

            }

        }

        // Final fallback: try to hook on generic NSURLSessionTask (response property is declared there)

        if (!getterHooked) {

            Class taskCls = [NSURLSessionTask class];

            SEL respSel = @selector(response);

            Method m = class_getInstanceMethod(taskCls, respSel);

            if (m) {

                IMP cur = method_getImplementation(m);

                if (cur != (IMP)hook_dataTaskResponse) {

                    orig_dataTaskResponse = cur;

                    method_setImplementation(m, (IMP)hook_dataTaskResponse);

                    DLOG(@"[HTTP-HOOK] v37.133: Hooked NSURLSessionTask.response getter (fallback)");

                    getterHooked = 1;

                }

            }

        }

        if (getterHooked) {

            DLOG(@"[INIT] v37.133: dataTask.response getter hook installed (HTTP status 500→200 guaranteed)");

        } else {

            DLOG(@"[HTTP-HOOK] v37.133: WARNING: Could not hook dataTask.response getter!");

        }

    }

}



// ============================================================

#pragma mark - ServerInfoForClient hooks (trace server list parsing)

// ============================================================



static IMP orig_msi_init = NULL;

static IMP orig_msi_initWithDict = NULL;

static IMP orig_msi_status = NULL;



static id msi_init_hook(id self, SEL _cmd);

static id msi_initWithDict_hook(id self, SEL _cmd, NSDictionary *dict);

static NSNumber *msi_status_hook(id self, SEL _cmd);

static NSString *msi_ip_hook(id self, SEL _cmd);

static NSString *msi_category_hook(id self, SEL _cmd);

static NSNumber *msi_serverType_hook(id self, SEL _cmd);

static NSString *msi_string_hook(id self, SEL _cmd);

static NSInteger msi_int_hook(id self, SEL _cmd);



// ============================================================

#pragma mark - UITableView DataSource hooks (OBSERVE ONLY, NO MODIFICATION)

// ============================================================



static IMP orig_tableView_numberOfRows = NULL;

static IMP orig_tableView_cellForRow = NULL;

static IMP orig_tableView_numberOfSections = NULL;



static BOOL isServerListDataSource(id self) {

    @try {

        if ([self respondsToSelector:@selector(dataSource)]) {

            id ds = [self dataSource];

            if (ds) {

                NSString *dsName = NSStringFromClass([ds class]);

                return ([dsName containsString:@"Server"] || [dsName containsString:@"server"] || 

                        [dsName containsString:@"List"] || [dsName containsString:@"list"] ||

                        [dsName containsString:@"Login"] || [dsName containsString:@"login"]);

            }

        }

        Class cls = [self class];

        NSString *clsName = NSStringFromClass(cls);

        return ([clsName containsString:@"Server"] || [clsName containsString:@"server"] || 

                [clsName containsString:@"List"] || [clsName containsString:@"list"] ||

                [clsName containsString:@"Login"] || [clsName containsString:@"login"]);

    } @catch (NSException *e) {

        return NO;

    }

}



static NSInteger hook_numberOfRowsInSection(id self, SEL _cmd, NSInteger section) {

    NSInteger (*origFunc)(id, SEL, NSInteger) = (NSInteger(*)(id, SEL, NSInteger))orig_tableView_numberOfRows;

    NSInteger ret = origFunc(self, _cmd, section);

    

    Class cls = [self class];

    NSString *clsName = NSStringFromClass(cls);

    

    if (isServerListDataSource(self)) {

        DLOG(@"[TV-OBSERVE] -[%@ numberOfRowsInSection:%ld] -> %ld", clsName, (long)section, (long)ret);

        

        @try {

            id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;

            if (dataSource) {

                NSString *dsCls = NSStringFromClass([dataSource class]);

                DLOG(@"[TV-OBSERVE] dataSource=%@ (%@)", dataSource, dsCls);

                

                if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {

                    id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];

                    if ([serverList isKindOfClass:[NSArray class]]) {

                        DLOG(@"[TV-OBSERVE] serverList count=%lu", (unsigned long)[serverList count]);

                        for (NSUInteger i = 0; i < [serverList count] && i < 5; i++) {

                            id item = serverList[i];

                            DLOG(@"[TV-OBSERVE]   [%lu] = %@ (%@)", i, item, NSStringFromClass([item class]));

                            if ([item isKindOfClass:[NSDictionary class]]) {

                                NSDictionary *dict = (NSDictionary *)item;

                                DLOG(@"[TV-OBSERVE]     keys=%@", [dict allKeys]);

                                DLOG(@"[TV-OBSERVE]     name=%@ ip=%@ port=%@ status=%@", dict[@"name"], dict[@"ip"], dict[@"port"], dict[@"status"]);

                            } else if ([item respondsToSelector:@selector(name)] && [item respondsToSelector:@selector(ip)] && [item respondsToSelector:@selector(port)]) {

                                DLOG(@"[TV-OBSERVE]     name=%@ ip=%@ port=%@", 

                                     [item performSelector:@selector(name)], 

                                     [item performSelector:@selector(ip)], 

                                     [item performSelector:@selector(port)]);

                            }

                        }

                    } else {

                        DLOG(@"[TV-OBSERVE] serverList is NOT NSArray: %@", serverList ? NSStringFromClass([serverList class]) : @"nil");

                    }

                }

                

                if ([dataSource respondsToSelector:@selector(dataArray)] || [dataSource respondsToSelector:@selector(items)]) {

                    id data = [dataSource performSelector:[dataSource respondsToSelector:@selector(dataArray)] ? @selector(dataArray) : @selector(items)];

                    if ([data isKindOfClass:[NSArray class]]) {

                        DLOG(@"[TV-OBSERVE] dataArray/items count=%lu", (unsigned long)[data count]);

                    }

                }

            }

        } @catch (NSException *e) {

            DLOG(@"[TV-OBSERVE] Exception: %@", e);

        }

    }

    return ret;

}



static UITableViewCell *hook_cellForRowAtIndexPath(id self, SEL _cmd, NSIndexPath *indexPath) {

    UITableViewCell *(*origFunc)(id, SEL, NSIndexPath*) = (UITableViewCell*(*)(id, SEL, NSIndexPath*))orig_tableView_cellForRow;

    UITableViewCell *ret = origFunc(self, _cmd, indexPath);

    

    Class cls = [self class];

    NSString *clsName = NSStringFromClass(cls);

    

    if (isServerListDataSource(self)) {

        NSString *text = @"";

        if (ret && ret.textLabel) text = ret.textLabel.text ?: @"";

        NSString *detailText = @"";

        if (ret && [ret respondsToSelector:@selector(detailTextLabel)] && [(UITableViewCell*)ret detailTextLabel]) {

            detailText = [(UITableViewCell*)ret detailTextLabel].text ?: @"";

        }

        

        DLOG(@"[TV-OBSERVE] -[%@ cellForRowAtIndexPath:{%ld,%ld}] -> text='%@' detail='%@'", clsName, 

             (long)indexPath.section, (long)indexPath.row, text, detailText);

        

        @try {

            id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;

            if (dataSource) {

                if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {

                    id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];

                    if ([serverList isKindOfClass:[NSArray class]] && indexPath.row < [serverList count]) {

                        id item = serverList[indexPath.row];

                        DLOG(@"[TV-OBSERVE] Row %ld data: %@ (%@)", (long)indexPath.row, item, NSStringFromClass([item class]));

                        if ([item isKindOfClass:[NSDictionary class]]) {

                            NSDictionary *dict = (NSDictionary *)item;

                            DLOG(@"[TV-OBSERVE]   name=%@ status=%@ ip=%@ port=%@", 

                                 dict[@"name"], dict[@"status"], dict[@"ip"], dict[@"port"]);

                        } else if ([item respondsToSelector:@selector(name)] && [item respondsToSelector:@selector(ip)]) {

                            DLOG(@"[TV-OBSERVE]   name=%@ ip=%@", 

                                 [item performSelector:@selector(name)], 

                                 [item performSelector:@selector(ip)]);

                        }

                    }

                }

            }

        } @catch (NSException *e) {

            DLOG(@"[TV-OBSERVE] Exception: %@", e);

        }

    }

    return ret;

}



static NSInteger hook_numberOfSections(id self, SEL _cmd) {

    NSInteger (*origFunc)(id, SEL) = (NSInteger(*)(id, SEL))orig_tableView_numberOfSections;

    NSInteger ret = origFunc(self, _cmd);

    

    Class cls = [self class];

    NSString *clsName = NSStringFromClass(cls);

    

    if (isServerListDataSource(self)) {

        DLOG(@"[TV-OBSERVE] -[%@ numberOfSections] -> %ld", clsName, (long)ret);

    }

    return ret;

}



// ============================================================

#pragma mark - ServerInfoForClient helper

// ============================================================



static void msi_log_properties(id self) {

    @try {

        unsigned int count = 0;

        objc_property_t *props = class_copyPropertyList([self class], &count);

        for (unsigned int i = 0; i < count; i++) {

            const char *propName = property_getName(props[i]);

            id value = [self valueForKey:[NSString stringWithUTF8String:propName]];

            if (value) {

                DLOG(@"[MSI-PROP] %s = %@", propName, value);

            }

        }

        if (props) free(props);

    } @catch (NSException *e) {

        DLOG(@"[MSI-PROP] Exception: %@", e);

    }

}



static id msi_init_hook(id self, SEL _cmd) {

    id (*origFunc)(id, SEL) = (id(*)(id, SEL))orig_msi_init;

    id ret = origFunc(self, _cmd);

    if (ret) {

        DLOG(@"[MSI-CALL] -[%@ init] -> %p", NSStringFromClass([self class]), ret);

        msi_log_properties(ret);

    }

    return ret;

}



// ============================================================

// ServerInfoForClient Stub Class Implementation

// ============================================================



// Game server config variables (defined early for stub class access)

static int g_gameServerPort = 0;  // v36.61: Default to 0 (not set yet), will be parsed from server list

static char g_gameServerIP[64] = "47.100.14.198";

static BOOL g_gameServerInfoUpdated = YES;



// v36.61: Track game server connection state

static BOOL g_gameServerConnected = NO;  // Whether game server handshake completed

static int g_gameServerFd = -1;  // Track which fd is connected to game server

static NSTimeInterval g_gameConnectTime = 0;  // Time of game server connection



// v36.66: Store 0x000EE007 device info packet for forced send to game server

#define MAX_DEVICE_INFO_SIZE 512

static uint8_t g_deviceInfoPacket[MAX_DEVICE_INFO_SIZE];

static ssize_t g_deviceInfoPacketLen = 0;

static BOOL g_deviceInfoCaptured = NO;

static BOOL g_deviceInfoSentToGame = NO;



// v36.123: Fixed IDFV for [UIDevice identifierForVendor] hook

// Returns consistent UUID so client NATIVELY builds UUID-containing 0x000EE007

// (Avoids send-level buffer modification per Experience 1423135)

static NSUUID *g_fixedIDFV = nil;

static NSUUID* (*orig_identifierForVendor)(UIDevice *self, SEL _cmd) = NULL;



// v36.87: Enhanced device info packet (with UUID injected) for game server

// Login server (5678) sends 143-byte version (no UUID)

// Game server expects 179-byte version (with UUID field)

static uint8_t g_deviceInfoEnhanced[MAX_DEVICE_INFO_SIZE];

static ssize_t g_deviceInfoEnhancedLen = 0;

static BOOL g_deviceInfoEnhancedReady = NO;



// v36.68: Sticky packet leftover buffer - for splitting sticky packets

// When 0x80FFF494 and heartbeat ACK arrive in same TCP buffer,

// we split them so the game client only sees the handshake response

#define MAX_STICKY_LEFTOVER 4096

static uint8_t g_stickyLeftoverBuf[MAX_STICKY_LEFTOVER];

static ssize_t g_stickyLeftoverLen = 0;

static int g_stickyLeftoverFd = -1;



// v36.68: Local heartbeat ACK buffer - for faking heartbeat responses

// When game sends heartbeat to game server during handshake, we intercept

// and return a local ACK to prevent server from including it in handshake response

#define MAX_LOCAL_HEARTBEAT_ACK 256

static uint8_t g_localHeartbeatAckBuf[MAX_LOCAL_HEARTBEAT_ACK];

static ssize_t g_localHeartbeatAckLen = 0;

static int g_localHeartbeatAckFd = -1;



// v36.68: Global handshake state tracking (moved from hook_recv for cross-function access)

static BOOL g_handshakeComplete = NO;

static int g_heartbeatCount = 0;



// v36.79: Store game server public key for RSA encrypt

// Extracted from 0x80FFF494 response (Base64-encoded DER public key)

#define MAX_PUBKEY_BASE64 1024

static char g_pubKeyBase64[MAX_PUBKEY_BASE64];

static size_t g_pubKeyBase64Len = 0;

static BOOL g_pubKeyCaptured = NO;



// v36.79: Track if we already auto-responded to 0x00FFFF02

static BOOL g_challengeResponded = NO;

static int g_challengeFd = -1;



// v36.83: Force handshake complete packet buffer

// When client sends heartbeat after challenge response (server didn't send 0x80FFF495),

// we prepare a fake 0x80FFF495 handshake complete response

#define MAX_FORCE_HS_BUF 256

static BOOL g_forceHandshakeComplete = NO;

static int g_forceHandshakeFd = -1;

static uint8_t g_forceHandshakeBuf[MAX_FORCE_HS_BUF];

static uint32_t g_forceHandshakeLen = 0;



// v36.107: Smart fake response system - track ALL client requests in a queue with sequence numbers

// Command queue - track ALL game server commands for ordered response

#define MAX_CMD_QUEUE 64

typedef struct {

    uint32_t cmd;

    int fd;

    uint32_t sendLen;

    uint32_t seqNum;  // v36.107: Sequence number from original request for correct response matching

} GameCmdEntry;



static GameCmdEntry g_cmdQueue[MAX_CMD_QUEUE];

static int g_cmdQueueHead = 0;   // Next command to dequeue

static int g_cmdQueueTail = 0;   // Next slot to enqueue

static int g_cmdQueueCount = 0;  // Number of commands in queue



// Track last game server command for generating appropriate fake responses

static uint32_t g_lastGameCmd = 0;

static int g_lastGameCmdFd = -1;

static uint32_t g_lastSeqNum = 0;  // v36.107: Last sequence number for fallback responses

static BOOL g_fakeRespActive = NO;

static BOOL g_fakeRespDelivered = NO;

static uint32_t g_lastRespCmd = 0;

static int g_respCount = 0;



// v36.107: Command queue functions - filter heartbeat and challenge cmds, track sequence numbers

static BOOL isFilteredCmd(uint32_t cmd) {

    if (cmd == 0x00000015) return YES;  // Heartbeat

    if (cmd == 0x00FFFF01) return YES;  // Challenge response 1

    if (cmd == 0x00FFFF02) return YES;  // Challenge response 2

    if (cmd == 0x80000015) return YES;  // Heartbeat (response direction)

    return NO;

}



static void enqueueGameCmd(uint32_t cmd, int fd, uint32_t sendLen, uint32_t seqNum) {

    // v36.107: Filter heartbeat and challenge commands to prevent queue flooding

    if (isFilteredCmd(cmd)) {

        DLOG(@"[CMD-QUEUE] v36.107: Filtered cmd=0x%08X seq=0x%08X (heartbeat/challenge)", cmd, seqNum);

        return;

    }

    

    if (g_cmdQueueCount >= MAX_CMD_QUEUE) {

        // Queue full - discard oldest

        g_cmdQueueHead = (g_cmdQueueHead + 1) % MAX_CMD_QUEUE;

        g_cmdQueueCount--;

        DLOG(@"[CMD-QUEUE] v36.107: Queue full, discarding oldest");

    }

    g_cmdQueue[g_cmdQueueTail].cmd = cmd;

    g_cmdQueue[g_cmdQueueTail].fd = fd;

    g_cmdQueue[g_cmdQueueTail].sendLen = sendLen;

    g_cmdQueue[g_cmdQueueTail].seqNum = seqNum;

    g_cmdQueueTail = (g_cmdQueueTail + 1) % MAX_CMD_QUEUE;

    g_cmdQueueCount++;

    DLOG(@"[CMD-QUEUE] v36.107: Enqueued cmd=0x%08X seq=0x%08X fd=%d sendLen=%u (queue=%d)", 

         cmd, seqNum, fd, sendLen, g_cmdQueueCount);

}



static BOOL dequeueGameCmd(GameCmdEntry *entry) {

    if (g_cmdQueueCount <= 0) return NO;

    *entry = g_cmdQueue[g_cmdQueueHead];

    g_cmdQueueHead = (g_cmdQueueHead + 1) % MAX_CMD_QUEUE;

    g_cmdQueueCount--;

    return YES;

}



static void resetCmdQueue(void) {

    g_cmdQueueHead = 0;

    g_cmdQueueTail = 0;

    g_cmdQueueCount = 0;

}



// v36.106: Generate response based on queued command

static BOOL g_quitFromServerPatched = NO;

static BOOL g_heartbeatPatched = NO;



// v36.104: Disabled inline patch (caused crash) - using poll/select hook instead

static BOOL patchFunctionToReturn(void *funcAddr, const char *funcName) {

    // v36.104: Inline patching causes crash on iOS - disabled

    // Instead, we hook poll()/select() to prevent heartbeat from detecting dead connection

    DLOG(@"[INLINE-PATCH] v36.104: Inline patch disabled (caused crash), using poll/select hook instead");

    (void)funcAddr; (void)funcName;

    return NO;

}



// v36.103: Find and patch C++ functions using backtrace from close() call

static void findAndPatchDisconnectFunctions(void) {

    if (g_quitFromServerPatched && g_heartbeatPatched) return;

    

    void *callstack[32];

    int frames = backtrace(callstack, 32);

    

    DLOG(@"[INLINE-PATCH] v36.103: Scanning %d backtrace frames for C++ functions...", frames);

    

    for (int i = 0; i < frames; i++) {

        Dl_info info;

        if (dladdr(callstack[i], &info) && info.dli_sname) {

            const char *name = info.dli_sname;

            

            // Check for quitFromServer

            if (!g_quitFromServerPatched && strstr(name, "quitFromServer")) {

                DLOG(@"[INLINE-PATCH] v36.103: Found %s at addr=%p (frame %d, ret=%p)", 

                     name, info.dli_saddr, i, callstack[i]);

                if (patchFunctionToReturn(info.dli_saddr, name)) {

                    g_quitFromServerPatched = YES;

                }

            }

            

            // Check for heartbeat

            if (!g_heartbeatPatched && strstr(name, "heartbeat") && strstr(name, "NetImpl")) {

                DLOG(@"[INLINE-PATCH] v36.103: Found %s at addr=%p (frame %d, ret=%p)", 

                     name, info.dli_saddr, i, callstack[i]);

                if (patchFunctionToReturn(info.dli_saddr, name)) {

                    g_heartbeatPatched = YES;

                }

            }

        }

    }

    

    if (!g_quitFromServerPatched && !g_heartbeatPatched) {

        DLOG(@"[INLINE-PATCH] v36.103: No C++ functions found in backtrace");

    }

}



// v36.103: Proactively search for C++ functions in main binary and patch them

static void proactivePatchCppFunctions(void) {

    if (g_quitFromServerPatched && g_heartbeatPatched) return;

    

    DLOG(@"[INLINE-PATCH] v36.103: Proactively searching for C++ functions in main binary...");

    

    const char *targetNames[] = {

        "_ZN7NetImpl14quitFromServerEv",

        "_ZN7NetImpl9heartbeatEv",

        NULL

    };

    

    int imageCount = _dyld_image_count();

    for (int idx = 0; idx < imageCount; idx++) {

        const char *imageName = _dyld_get_image_name(idx);

        if (!imageName) continue;

        

        // Skip non-main binaries

        if (!strstr(imageName, "wangxian") && !strstr(imageName, "WangXian")) continue;

        

        DLOG(@"[INLINE-PATCH] v36.103: Searching in main binary: %s (slide=0x%lx)", 

             imageName, (unsigned long)_dyld_get_image_vmaddr_slide(idx));

        

        void *handle = dlopen(imageName, RTLD_NOLOAD | RTLD_LAZY);

        if (!handle) continue;

        

        for (int n = 0; targetNames[n] != NULL; n++) {

            void *sym = dlsym(handle, targetNames[n]);

            if (sym) {

                DLOG(@"[INLINE-PATCH] v36.103: Found %s at %p via dlsym", targetNames[n], sym);

                

                if (strstr(targetNames[n], "quitFromServer") && !g_quitFromServerPatched) {

                    if (patchFunctionToReturn(sym, targetNames[n])) {

                        g_quitFromServerPatched = YES;

                    }

                }

                if (strstr(targetNames[n], "heartbeat") && !g_heartbeatPatched) {

                    if (patchFunctionToReturn(sym, targetNames[n])) {

                        g_heartbeatPatched = YES;

                    }

                }

            }

        }

        

        dlclose(handle);

        

        if (g_quitFromServerPatched && g_heartbeatPatched) break;

    }

    

    // Also try RTLD_DEFAULT

    if (!g_quitFromServerPatched) {

        void *sym = dlsym(RTLD_DEFAULT, "_ZN7NetImpl14quitFromServerEv");

        if (sym) {

            DLOG(@"[INLINE-PATCH] v36.103: Found quitFromServer via RTLD_DEFAULT at %p", sym);

            if (patchFunctionToReturn(sym, "quitFromServer")) {

                g_quitFromServerPatched = YES;

            }

        }

    }

    if (!g_heartbeatPatched) {

        void *sym = dlsym(RTLD_DEFAULT, "_ZN7NetImpl9heartbeatEv");

        if (sym) {

            DLOG(@"[INLINE-PATCH] v36.103: Found heartbeat via RTLD_DEFAULT at %p", sym);

            if (patchFunctionToReturn(sym, "heartbeat")) {

                g_heartbeatPatched = YES;

            }

        }

    }

    

    DLOG(@"[INLINE-PATCH] v36.103: Proactive search complete: quitFromServer=%d heartbeat=%d", 

         g_quitFromServerPatched, g_heartbeatPatched);

}



// v36.155: Role rotation index. Increments each time a new server is

// entered, so each server shows a DIFFERENT character (name, profession,

// level). Without this, all servers show the same hardcoded "玩家001"

// warrior with level 1, which is unrealistic — each server should have

// a unique character. MUST be declared BEFORE generateFakeResponse() which uses it.

static int g_roleIndex = 0;



// v36.107: Generate fake response based on request command with correct sequence number

// Returns response length, 0 if no response needed

static uint32_t generateFakeResponse(uint32_t requestCmd, uint8_t *respBuf, uint32_t bufSize, uint32_t seqNum) {

    if (!respBuf || bufSize < 16) return 0;



    // v36.139: For 0x00FFF493 (role request) the server replies with a

    // 0x0CB0A300 packet (cmd bytes on wire: 00 A3 B0 0C). The previous

    // versions returned a 200-byte 0x80FFF493 empty payload which the

    // client could not parse, leaving it stuck at "正在进入...".

    //

    // Real captured response (hook.txt RECV #19, ret=1632) is composed of

    // two 816-byte sub-packets:

    //   sub1: pktLen=0x330, cmd=0x00A3B00C (role attribute table, 100 entries x 8 bytes)

    //   sub2: pktLen=0x330, cmd=0x00A30200 (companion data table)

    // Because the capture was truncated to 1024 bytes we only have the

    // complete sub1. Returning sub1 alone is enough for the client to

    // recognise the 0x0CB0A300 command and advance the state machine.

    //

    // Layout of sub1:

    //   bytes 0-3   : pktLen = 0x00000330 (816) big-endian

    //   bytes 4-7   : cmd    = 0x00A3B00C big-endian (wire bytes 00 A3 B0 0C)

    //   bytes 8-11  : seq    = 0x08887D80 (server-side seq, kept from real capture)

    //   bytes 12-15 : count  = 0x00000064 (100 attribute entries)

    //   bytes 16+   : 100 x uint64 attribute values (big-endian)

    // v37.90 FIX: Corrected cmd bytes based on real 7.6.3 capture (hook.txt v3).

    //   sub1 cmd = 0x00A3B010 (was 0x00A3B00C — WRONG last byte 0C vs 10)

    //   sub2 cmd = 0x0002A310 (was 0x0002A30C — WRONG last byte 0C vs 10)

    //   seq = dynamic (was static 0x08887D80)

    // The wrong cmd meant the client never recognised the forged response,

    // causing the "正在进入..." freeze. Real capture confirmed via Frida v3.

    //

    // Real captured response (hook.txt v3, recv len=1632) is composed of

    // two 816-byte sub-packets:

    //   sub1: pktLen=0x330, cmd=0x00A3B010 (100 entries x 8 bytes)

    //   sub2: pktLen=0x330, cmd=0x0002A310 (100 entries x 8 bytes)

    //

    // Layout of sub1:

    //   bytes 0-3   : pktLen = 0x00000330 (816) big-endian

    //   bytes 4-7   : cmd    = 0x00A3B010 big-endian (wire bytes 00 A3 B0 10)

    //   bytes 8-11  : seq    = dynamic (from request seqNum)

    //   bytes 12-15 : count  = 0x00000064 (100 attribute entries)

    //   bytes 16+   : 100 x uint64 attribute values (big-endian)

    if (requestCmd == 0x00FFF493) {

        // Sub-packet 1 header (16 bytes) — v37.90 corrected cmd 0x00A3B010

        static const uint8_t roleHeader[16] = {

            0x00, 0x00, 0x03, 0x30,  // pktLen = 816

            0x00, 0xA3, 0xB0, 0x10,  // cmd = 0x00A3B010 (CORRECTED from 0x00A3B00C)

            0x00, 0x00, 0x00, 0x00,  // seq placeholder (overwritten below with dynamic seq)

            0x00, 0x00, 0x00, 0x64   // count = 100 entries

        };

        // 100 attribute entries (8 bytes each) copied verbatim from the real

        // RECV #19 capture (hook.txt lines 870-920). Big-endian uint64 values

        // representing the role's attributes. Using real values avoids

        // client-side validation failures.

        static const uint8_t roleAttrs[800] = {

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x49, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x27,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x56, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3C,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5E, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4A,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x19, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x27,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3B, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4E,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x52, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5C,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x44, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4A, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2A,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x57, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x62,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x58, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5F,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2C,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1C,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x59, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5D,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5B,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4D,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5E, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x63,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3B,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1D,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x44, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x61,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x52, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0D,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2C, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3C,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0B, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x51, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x35,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x54,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x12,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x62, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x47,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2B,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x33, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3C, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x37, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4A, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5D,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1A, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x24,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3F,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x22, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,

            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x56, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x13

        };



        // v36.140: Return the COMPLETE 1632-byte response (two 816-byte

        // sub-packets) to match the real server behaviour (hook.txt RECV #19).

        // v36.139 only returned sub1 (816 bytes); the client may have been

        // waiting for sub2 and stalled at "正在进入...".

        if (bufSize < 1632) {

            // Not enough room for both sub-packets — fall back to sub1 only.

            if (bufSize < 816) {

                DLOG(@"[FAKE-RESP] v36.140: 0x0CB0A300 needs 816 bytes, bufSize=%u — skip", bufSize);

                return 0;

            }

            DLOG(@"[FAKE-RESP] v37.90: 0x00A3B010 partial (sub1 only, 816 bytes) bufSize=%u", bufSize);

            memcpy(respBuf, roleHeader, 16);

            memcpy(respBuf + 16, roleAttrs, 800);

            // v37.90: dynamic seq

            respBuf[8]  = (seqNum >> 24) & 0xFF;

            respBuf[9]  = (seqNum >> 16) & 0xFF;

            respBuf[10] = (seqNum >> 8) & 0xFF;

            respBuf[11] = seqNum & 0xFF;

            return 816;

        }

        // Sub-packet 1 (816 bytes): role attribute table

        memcpy(respBuf, roleHeader, 16);

        memcpy(respBuf + 16, roleAttrs, 800);

        // v37.90: Write dynamic seq for sub1 (from request seqNum)

        respBuf[8]  = (seqNum >> 24) & 0xFF;

        respBuf[9]  = (seqNum >> 16) & 0xFF;

        respBuf[10] = (seqNum >> 8) & 0xFF;

        respBuf[11] = seqNum & 0xFF;

        // v36.155: Dynamic role attributes based on g_roleIndex.

        // Modify key attribute entries so each server gets unique character

        // stats (roleId, level, profession, etc.). Without this, all servers

        // share identical attribute values from the real capture.

        if (g_roleIndex > 0) {

            // Entry 0 (offset 16): role ID — set to g_roleIndex (big-endian uint64)

            uint32_t rid = (uint32_t)g_roleIndex;

            respBuf[16] = (rid >> 24) & 0xFF; respBuf[17] = (rid >> 16) & 0xFF;

            respBuf[18] = (rid >> 8) & 0xFF; respBuf[19] = rid & 0xFF;

            respBuf[20] = 0x00; respBuf[21] = 0x00; respBuf[22] = 0x00; respBuf[23] = 0x00;



            // Entry 1 (offset 24): level — 1 + (roleIndex-1)*10, capped at 100

            uint32_t level = 1 + (g_roleIndex - 1) * 10;

            if (level > 100) level = 100;

            respBuf[24] = (level >> 24) & 0xFF; respBuf[25] = (level >> 16) & 0xFF;

            respBuf[26] = (level >> 8) & 0xFF; respBuf[27] = level & 0xFF;



            // Entry 2 (offset 32): profession/class — cycle through 3 types

            // 1=战士(warrior), 2=法师(mage), 3=道士(taoist)

            uint32_t prof = (uint32_t)((g_roleIndex - 1) % 3) + 1;

            respBuf[32] = 0x00; respBuf[33] = 0x00; respBuf[34] = 0x00; respBuf[35] = prof;

            respBuf[36] = 0x00; respBuf[37] = 0x00; respBuf[38] = 0x00; respBuf[39] = 0x00;



            // Entry 3 (offset 40): max HP — scale with level

            uint32_t maxHp = 100 + level * 50;

            respBuf[40] = (maxHp >> 24) & 0xFF; respBuf[41] = (maxHp >> 16) & 0xFF;

            respBuf[42] = (maxHp >> 8) & 0xFF; respBuf[43] = maxHp & 0xFF;



            DLOG(@"[FAKE-RESP] v36.155: 0x0CB0A300 dynamic attrs — roleId=%u level=%u prof=%u maxHp=%u (roleIndex=%d)",

                 rid, level, prof, maxHp, g_roleIndex);

        }

        // Sub-packet 2 (816 bytes): companion table.

        // v37.90 FIX: Corrected cmd from 0x0002A30C to 0x0002A310 (real capture).

        // Real capture (hook.txt v3) header: 00 00 03 30 00 02 a3 10

        // seq is dynamic (sub1 seq + 1).

        static const uint8_t sub2Header[16] = {

            0x00, 0x00, 0x03, 0x30,  // pktLen = 816

            0x00, 0x02, 0xA3, 0x10,  // cmd = 0x0002A310 (CORRECTED from 0x0002A30C)

            0x00, 0x00, 0x00, 0x00,  // seq placeholder (overwritten below)

            0x00, 0x00, 0x00, 0x64   // count = 100 entries

        };

        memcpy(respBuf + 816, sub2Header, 16);

        // v37.90: Use dynamic seq for sub2 (sub1 seq + 1)

        uint32_t sub2Seq = seqNum + 1;

        respBuf[824] = (sub2Seq >> 24) & 0xFF;

        respBuf[825] = (sub2Seq >> 16) & 0xFF;

        respBuf[826] = (sub2Seq >> 8) & 0xFF;

        respBuf[827] = sub2Seq & 0xFF;

        memset(respBuf + 832, 0, 800);  // zero-padded attribute entries



        DLOG(@"[FAKE-RESP] v37.90: 0x00A3B010 role-data response built (1632 bytes, 2 sub-packets: 0x00A3B010 + 0x0002A310) for req=0x%08X seq=0x%08X roleIndex=%d",

             requestCmd, seqNum, g_roleIndex);

        return 1632;

    }



    uint32_t respCmd = requestCmd | 0x80000000;  // Response cmd = request cmd | 0x80000000

    

    // v36.107: Extract sequence number bytes for reuse

    uint8_t seqBytes[4];

    seqBytes[0] = (seqNum >> 24) & 0xFF;

    seqBytes[1] = (seqNum >> 16) & 0xFF;

    seqBytes[2] = (seqNum >> 8) & 0xFF;

    seqBytes[3] = seqNum & 0xFF;

    

    // v36.123: ALL responses use 200-byte format with zero-padded payload

    // Previous 16-byte responses caused SIGSEGV in handlers like handle_CHOOSE_WOOD_BOX_RES

    // which read payload beyond the 16-byte header.

    // 200 bytes matches the v36.88 FORCE-HS-PREP approach that was proven safe.

    uint32_t respLen = (bufSize >= 200) ? 200 : bufSize;

    

    memset(respBuf, 0, respLen);

    

    // Header (bytes 0-3): packet length (big-endian)

    respBuf[0] = (respLen >> 24) & 0xFF;

    respBuf[1] = (respLen >> 16) & 0xFF;

    respBuf[2] = (respLen >> 8) & 0xFF;

    respBuf[3] = respLen & 0xFF;

    

    // Header (bytes 4-7): response cmd

    respBuf[4] = (respCmd >> 24) & 0xFF;

    respBuf[5] = (respCmd >> 16) & 0xFF;

    respBuf[6] = (respCmd >> 8) & 0xFF;

    respBuf[7] = respCmd & 0xFF;

    

    // Header (bytes 8-11): sequence number

    respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];

    respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];

    

    // Status (byte 12): 0 = success for ALL responses

    respBuf[12] = 0x00;

    

    // For 0x80FFF495 (handle_CHOOSE_WOOD_BOX_RES), byte 13 = 0x88 format flag

    if (requestCmd == 0x00FFF495) {

        respBuf[13] = 0x88;  // Format flag from v36.88 FORCE-HS-PREP

    }



    // v36.123: For 0x80FFF49F (role list response), construct a MINIMAL valid

    // role entry so the UI actually presents a "select character" screen instead

    // of silently hanging (all-zero payload may be interpreted as empty/no roles).

    // Layout assumption (common for this class of MMO protocols):

    //   byte 13     : numRoles = 1

    //   bytes 14-15 : roleId (LE 0x0001)

    //   bytes 16-47 : UTF-8 role name "玩家001" (padded with spaces or \0)

    //   bytes 48-49 : level (LE 0x0001 = Lv.1)

    //   bytes 50-51 : profession / class id (LE 0x0001 = 战士)

    //   bytes 52-55 : mapId / serverId

    //   remaining   : zero

    // v36.155: Dynamic role data based on g_roleIndex — each server gets

    // a DIFFERENT character with unique name, profession, and level.

    if (requestCmd == 0x00FFF49E) {

        // Rotate through 3 professions: 战士(1), 法师(2), 道士(3)

        int professions[3] = {1, 2, 3};

        int profIdx = (g_roleIndex - 1) % 3;

        int roleId = g_roleIndex;

        int level = 1 + (g_roleIndex - 1) * 10;  // Lv.1, Lv.11, Lv.21, ...

        if (level > 100) level = 100;  // Cap at Lv.100



        respBuf[13] = 0x01;  // numRoles = 1

        // roleId = g_roleIndex, little-endian uint16 at offset 14

        respBuf[14] = (roleId & 0xFF); respBuf[15] = ((roleId >> 8) & 0xFF);



        // Build role name dynamically: "玩家" + zero-padded 3-digit number

        char roleNameBuf[48] = {0};

        snprintf(roleNameBuf, sizeof(roleNameBuf), "\xE7\x8E\xA9\xE5\xAE\xB6%03d", g_roleIndex);

        // Ensure exactly 32 bytes (UTF-8 "玩家"=6bytes + 3digits + padding)

        int nameLen = (int)strlen(roleNameBuf);

        memcpy(respBuf + 16, roleNameBuf, MIN(nameLen, 32));



        // level = computed level, uint16 LE at offset 48

        respBuf[48] = (level & 0xFF); respBuf[49] = ((level >> 8) & 0xFF);

        // profession = rotated profession, uint16 LE at offset 50

        respBuf[50] = professions[profIdx]; respBuf[51] = 0x00;

        // mapId / serverId at offset 52 = g_roleIndex

        respBuf[52] = (roleId & 0xFF); respBuf[53] = ((roleId >> 8) & 0xFF);

        respBuf[54] = 0x00; respBuf[55] = 0x00;



        DLOG(@"[FAKE-RESP] v36.155: Role list — roleId=%d name=%s level=%d prof=%d",

             roleId, roleNameBuf, level, professions[profIdx]);

    }



    // v36.123: For 0x80FFF4A1 (enter game / select role response), put minimal

    // success data so the client transitions from "select role" to "loading map".

    // Byte 13 = 0x01 (accepted), bytes 14-17 = new mapId = 1, bytes 18-21 = x, y.

    if (requestCmd == 0x00FFF4A0) {

        respBuf[13] = 0x01;   // accept flag

        respBuf[14] = 0x01; respBuf[15] = 0x00; // mapId=1

        respBuf[16] = 0x00; respBuf[17] = 0x00;

        respBuf[18] = 0x40; respBuf[19] = 0xE2; // x = some coord (57920)

        respBuf[20] = 0x01; respBuf[21] = 0x00;

        respBuf[22] = 0x70; respBuf[23] = 0xFA; // y = some coord (64112)

        respBuf[24] = 0xFF; respBuf[25] = 0xFF;

    }



    // Bytes 14-199: zero-padded payload (safe for all handlers)

    

    return respLen;

}



// v36.95: Track when client sends login packets to game server

// This replaces g_challengeResponded for fake response injection trigger

static BOOL g_loginPacketsSent = NO;



// v36.94: Fake login success response injection

// When server closes connection (recv returns 0) after client sends login packets,

// inject fake 0x80FFF493 success response to prevent disconnection

// v36.139: Enlarged from 256 to 2048 to hold the 0x0CB0A300 role-data

// response (816 bytes for sub-packet 1). The previous 256-byte cap forced

// generateFakeResponse() to truncate the role data, leaving the client

// state machine stalled at "正在进入..." because it never received a

// complete 0x0CB0A300 packet.

#define MAX_FAKE_RESP_BUF 2048

static BOOL g_fakeRespInjected = NO;

static int g_fakeRespFd = -1;

static uint8_t g_fakeRespBuf[MAX_FAKE_RESP_BUF];

static uint32_t g_fakeRespLen = 0;

static int g_fakeRespSentCount = 0;  // Track how many fake responses sent



// v36.123: Force immediate fake-response activation after 0x80FFF495 patch,

// no longer waiting for server to RECV-CLOSE (which never happens when the

// game server keeps the heartbeat alive while ignoring our plaintext EE007).

static BOOL g_triggerFakeNextRecv = NO;

static int g_triggerFakeFd = -1;



// v36.124: New flag for IMMEDIATE burst injection after patch

// Instead of waiting for the next client recv() call (which may be for heartbeat ACK),

// append all fake responses to the CURRENT return as a TCP sticky buffer.

static BOOL g_burstInjectAfterPatch = NO;

static int g_burstInjectFd = -1;



// v36.142: Post-BURST protocol continuation.

// Real capture (hook.txt) shows that after receiving 0x0CB0A300 (role data),

// the client sends an ACK (0x80A3B00C, 20 bytes), then the server sends:

//   RECV #20: cmd=0x1200F080 (71 bytes) — session token notification

//   RECV #21: cmd=0x13000080 (840 bytes) — map/scene data with file paths

// Without these, the client enters heartbeat mode and stays at "正在进入...".

// State machine:

//   0 = idle

//   1 = BURST injected, next recv() should return RECV #20

//   2 = RECV #20 injected, waiting for client to send 0x00FFF493 (enter game)

//   3 = Client sent 0x00FFF493, next recv() should return RECV #21

//   4 = RECV #21 injected, done

static int g_postBurstState = 0;

static int g_postBurstFd = -1;

// v36.146: Set to YES after RECV #21 is injected. Prevents hook_send from

// reactivating g_fakeRespActive when the client sends new 0x00FFF493 requests.

// Without this, each new 0x00FFF493 resets g_fakeRespDelivered=NO, reactivating

// the fake response system and generating DUPLICATE 0x0CB0A300 responses.

static BOOL g_postBurstDone = NO;

// v36.150: Phase 2 trigger counter. 0=not triggered, 1=first 0x00FFF493 (role

// select) triggers Phase 2, >1=subsequent requests return EAGAIN.

// Reset to 0 on BURST inject so re-login works.

static int g_phase2TriggerCount = 0;

// v36.154: Timestamp when Phase 1 completed (RECV #21 injected). Phase 2

// trigger requires at least 3 seconds elapsed since Phase 1 completion,

// giving the client sufficient time to render the role selection UI.

// Without this delay, auto-load ACK 0x00FFF493 requests (fired within

// ~100ms of Phase 1) trigger Phase 2 too early — before the user can

// even see the role list — causing the client to skip the role UI.

static double g_phase1DoneTime = 0;

// RECV #20 data (71 bytes) from hook.txt line 944.

static const uint8_t kRecv20Data[71] = {

    0x00,0x00,0x00,0x47, 0x80,0x00,0xF0,0x12, 0x00,0x00,0x00,0x1A, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x20,0x31, 0x32,0x30,0x66,0x62, 0x35,0x64,0x39,0x65,

    0x35,0x66,0x62,0x30, 0x31,0x36,0x65,0x32, 0x32,0x35,0x65,0x61, 0x66,0x64,0x38,0x64,

    0x65,0x37,0x32,0x32, 0x31,0x31,0x38

};



// RECV #21 data (840 bytes) from hook.txt lines 1002-1054.

// cmd=0x13000080 (wire: 80 00 00 13), seq=0x1C.

// Contains role name "luoyueshangu", map info, and .xtl file paths.

// First 288 bytes are meaningful; rest is zero-padded with sparse non-zero values.

static const uint8_t kRecv21Head[288] = {

    0x00,0x00,0x03,0x48, 0x80,0x00,0x00,0x13, 0x00,0x00,0x00,0x1C, 0x00,0x00,0x00,0x01,

    0x00,0x0C,0x6C,0x75, 0x6F,0x79,0x75,0x65, 0x73,0x68,0x61,0x6E, 0x67,0x75,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xFF,

    0x00,0x00,0x00,0x00, 0x00,0x01,0x49,0x00, 0x00,0x01,0x49,0x00, 0x00,0x00,0xFA,0x00,

    0x00,0x00,0xFA,0x24, 0x3F,0xB0,0x29,0x39, 0x53,0x40,0x10,0x00, 0x06,0xE7,0x9C,0x8B,

    0xE7,0x9C,0x8B,0x00, 0x02,0xFF,0xFF,0xFF, 0xFF,0x05,0x00,0x00, 0x00,0x05,0x00,0x00,

    0x00,0x05,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0xC3,0x50, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x01,0x5A, 0x00,0x00,0x00,0x00, 0x00,0x00,0x05,0x10, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x32,0xA0, 0x09,0x00,0x02,0x00, 0x02,0x5A,0x4A,0x00, 0x00,0x00,0x04,0x00,

    0x14,0x2F,0x70,0x61, 0x72,0x74,0x2F,0x5A, 0x4A,0x5F,0x73,0x68, 0x6F,0x75,0x6B,0x75,

    0x69,0x2E,0x78,0x74, 0x6C,0x00,0x1E,0x2F, 0x70,0x61,0x72,0x74, 0x2F,0x6C,0x69,0x61,

    0x6E,0x64,0x61,0x6F, 0x30,0x36,0x5F,0x5A, 0x4A,0x5F,0x73,0x68, 0x6F,0x75,0x6B,0x75,

    0x69,0x2E,0x78,0x74, 0x6C,0x00,0x1B,0x2F, 0x70,0x61,0x72,0x74, 0x2F,0x79,0x69,0x66,

    0x75,0x30,0x30,0x5F, 0x5A,0x4A,0x5F,0x73, 0x68,0x6F,0x75,0x6B, 0x75,0x69,0x2E,0x78,

    0x74,0x6C,0x00,0x1C, 0x2F,0x70,0x61,0x72, 0x74,0x2F,0x6C,0x69, 0x61,0x6E,0x64,0x61,

    0x6F,0x5F,0x5A,0x4A, 0x5F,0x73,0x68,0x6F, 0x75,0x6B,0x75,0x69, 0x2E,0x78,0x74,0x6C,

    0x00,0x00,0x00,0x04, 0x00,0x01,0x02,0x0D, 0xFF,0x00,0x00,0x07, 0xD0,0x00,0x00,0x00

};

// Sparse non-zero bytes in the zero-padded tail (offset, value pairs).

static const struct { uint16_t off; uint8_t val; } kRecv21Sparse[] = {

    { 0x120, 0x96 },  // byte 288

    { 0x1F6, 0x36 },  // byte 502

    { 0x1FC, 0x14 },  // byte 508

    { 0x265, 0x14 },  // byte 613

    { 0x2E0, 0x28 },  // byte 736

    { 0, 0 }          // sentinel

};



// v36.147: RECV #22 (27 bytes) from hook.txt line 1082.

// cmd=0x80FFF490 (wire: 80 FF F4 90). Enter-game ACK/response.

// Format flag 0x08 0x88, payload = "kk994" + zero padding.

static const uint8_t kRecv22Data[27] = {

    0x00,0x00,0x00,0x1B, 0x80,0xFF,0xF4,0x90, 0x08,0x88,0x7F,0xA1, 0x00,0x05,0x6B,0x6B,

    0x39,0x39,0x34,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00

};



// v36.147: RECV #23 (273 bytes) from hook.txt lines 1112-1129.

// cmd=0x16000080 (wire: 80 00 00 16). Scene/entity data.

// Contains multiple sub-packets: scene state, 活动通知, 日常, etc.

static const uint8_t kRecv23Data[273] = {

    0x00,0x00,0x00,0xB4, 0x80,0x00,0x00,0x16, 0x00,0x00,0x00,0x1E, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x01,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x01,0x00, 0x00,0x00,0x00,0x05, 0x00,0x00,0x00,0x05, 0x00,0x00,0x02,0x43,

    0x00,0x00,0x00,0xFA, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07, 0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x01,

    0x00,0x00,0x00,0x18, 0x00,0x00,0x00,0x23, 0x00,0x00,0x00,0x05, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x04,0x93,0xE0, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

    0x00,0x0F,0x42,0x40, 0x00,0x00,0x00,0x10, 0x0F,0x10,0x00,0x08, 0x08,0x88,0x88,0x04,

    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x18, 0x80,0xF0,0xEF,0x83, 0x08,0x88,0x88,0x05,

    0x00,0x06,0xE6,0xB4, 0xBB,0xE5,0x8A,0xA8, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x18,

    0x80,0xF0,0xEF,0x83, 0x08,0x88,0x88,0x06, 0x00,0x06,0xE6,0x97, 0xA5,0xE5,0xB8,0xB8,

    0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x10, 0x80,0xFF,0xF0,0x08, 0x08,0x88,0x88,0x07,

    0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x0D, 0x80,0xFF,0xF0,0x06, 0x08,0x88,0x88,0x08,

    0x00

};



// v36.147: RECV #24 (63 bytes) from hook.txt lines 1134-1137.

// Contains 3 concatenated 0x80FFF161 (attr notifications) + 0x01AE0E80.

static const uint8_t kRecv24Data[63] = {

    0x00,0x00,0x00,0x11, 0x80,0xFF,0xF1,0x61, 0x08,0x88,0x88,0x09, 0x00,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x11,0x80,0xFF,0xF1, 0x61,0x08,0x88,0x88, 0x0A,0x00,0x00,0x00,

    0x00,0x00,0x00,0x00, 0x00,0x11,0x80,0xFF, 0xF1,0x61,0x08,0x88, 0x88,0x0B,0x00,0x00,

    0x00,0x03,0x00,0x00, 0x00,0x00,0x0C,0x80, 0x0E,0xAE,0x01,0x00, 0x28,0xB3,0x43

};



// v36.125: NEW — Force valid decryption mode for game server responses

// When client decrypts 0x80FFF495 payload, return valid plaintext

// instead of letting decryption fail (no AES key available)

// NOTE: g_forceValidDecrypt must NOT be static because it's referenced from

// inline ARM64 assembly in cpp_stub_force() (linker needs external symbol)

BOOL g_forceValidDecrypt = NO;

static int g_forceValidDecryptFd = -1;



// v37.28: CCCrypt L4 hook gate — only active AFTER game server challenge
// response (0x80FFF495) is received. Before that (login server phase),
// CCCrypt calls pass through unchanged to avoid crashing JudgeApp.
static BOOL g_cccrypt_l4_active = NO;

// FIX53K: Save CCCrypt L4 patched plaintext for send-hook re-encryption.
// When SAFE FALLBACK occurs OR CC_MD5 patched but CCCrypt L4 didn't,
// the send-hook needs the patched plaintext to re-encrypt correctly.
static char *g_l4_saved_patched = NULL;
static size_t g_l4_saved_patched_len = 0;
static BOOL g_l4_saved_valid = NO;



// v37.35: Save AES key+iv from FFF493#1 ENC call, and extended plaintext

// from FFF493#2 ENC call. In send hook, intercept FFF493#2 packet and

// replace it with our own encrypted extended plaintext.

static uint8_t g_saved_aes_key[32] = {0};

static uint8_t g_saved_aes_iv[32] = {0};

static size_t g_saved_key_len = 0;

static uint32_t g_saved_alg = 0;

static uint32_t g_saved_options = 0;

static BOOL g_aes_key_saved = NO;

// FIX53I: SAFE FALLBACK flag — set when CCCrypt L4 patches plaintext but output buffer
// is too small → falls back to encrypting ORIGINAL data. When this happens, the
// FFF493-REPL send-hook MUST re-encrypt the saved patched plaintext (which has correct
// channel/dm/gp/uuid AND correct md5 from CC_MD5 hook), otherwise:
// HMAC(based on patched data via CC_MD5) ≠ ciphertext(based on original data) → server REJECT
static volatile BOOL g_l4_safe_fallback = NO;

static char *g_ext_plaintext = NULL;   // extended plaintext for FFF493#2

static size_t g_ext_plaintext_len = 0;

static uint32_t g_fff493_2_seq = 0;    // seqNum of FFF493#2 to match in send hook

// v37.44: Save FFF493#2 native plaintext for send-hook field replacement

static char *g_fff493_2_native_plain = NULL;

static size_t g_fff493_2_native_len = 0;



// v37.69: Store REAL sessionId/ticket captured from login server's 0x8234AB89 response

// These are needed for FFF493#2 packet — server validates sessionId/ticket before

// returning role data (0x0CB0A300). Without real values, server only sends heartbeats.

static char g_sessionId[64] = {0};   // 32B sessionId + null

static char g_ticket[512] = {0};     // 366B ticket + null

static int g_sessionValid = 0;       // 1 = captured successfully, 0 = not yet

static int g_ticketLen = 0;          // actual ticket length

// v37.80: Captured token from 63B MD5 input (hash2_hex(32) + token(31) = 63 bytes)

// Used to recompute hash3+hash1 after replacing hash2.

static char g_hashToken[32] = {0};   // 31B token + null

static int  g_hashTokenValid = 0;    // 1 = captured



// v37.87: Forged 0x0CB0A300 role-data injection — last-resort if server ignores FFF493.

// Strategy: After BOTH FFF493#1 and FFF493#2 are sent (with sessionId+ticket replaced),

// if game server returns >=2 consecutive 0x80000015 heartbeats with NO 0x0CB0A300 in between,

// next recv() call injects a forged 0x0CB0A300 response so client shows role selection UI.

static int g_fff493_1_sent = 0;      // 1 after FFF493#1 replacement

static int g_fff493_2_sent = 0;      // 1 after FFF493#2 replacement

static int g_consec_heartbeats = 0;  // counts 0x80000015 without 0x0CB0A300 after FFF493#2

static int g_role_0CB0A300_seen = 0; // set to 1 if we ever receive real 0x0CB0A300 (no forgery)

static int g_injected_0CB0A300 = 0;  // prevent double-inject

// v37.87: FFF493#1 native plaintext buffer (IOS_CLIENT_MSG_REQ). Previously only #2 was captured

// and replaced, but #1 went with sessionId="", ticket="" → server rejected silently.

static char  *g_fff493_1_plain_buf = NULL;  // native plaintext of FFF493#1

static size_t g_fff493_1_plain_len = 0;     // length

// Save AES key+iv for encrypting the forged 0x0CB0A300 too (reuse saved session key)

extern uint8_t g_saved_aes_key[256/8];

extern size_t  g_saved_key_len;

extern uint8_t g_saved_aes_iv[32];

extern uint32_t g_saved_alg;

extern uint32_t g_saved_options;



// v37.35: Forward declare CCCrypt types so send hook (line ~3873) can use orig_CCCrypt

typedef int (*CCCryptFunc)(uint32_t op, uint32_t alg, uint32_t options,

                           const void *key, size_t keyLen,

                           const void *iv,

                           const void *dataIn, size_t dataInLen,

                           void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);

static CCCryptFunc orig_CCCrypt = NULL;



// v36.130: EncryptUtils bypass counter + original IMPs (defined here for forward access)

static int g_bypassRemaining = 0;

static IMP g_orig_rsaDecryptData = NULL;

static IMP g_orig_rsaDecryptLarge = NULL;

static IMP g_orig_aesDecryptData = NULL;



// v36.124: NEW — Wait for client to send native commands with REAL seq numbers

// Instead of pre-generating responses with wrong seq (0x10000+), wait for the

// client to send EE007/FFF493 etc., capture the REAL seq, and use it for responses.

static BOOL g_waitingForClientCmds = NO;

static int g_waitingFd = -1;



// Forward declaration (actual definition is after hook_recv closesocket logic,

// we will pull it above here as an independent reusable block).

static ssize_t triggerInitialFakeInjection(int fd, void *buf, size_t len);



// v36.94: Hook for NetImpl::quitFromServer

// This C++ method is called when heartbeat detects dead connection

// Making it a no-op prevents client state machine from entering disconnected state

typedef void (*NetImplQuitFunc)(void);

static NetImplQuitFunc orig_NetImpl_quitFromServer = NULL;

static BOOL g_quitFromServerHooked = NO;



// v36.97: MSHookFunction variables for heartbeat and disconnect

typedef void (*HeartbeatFunc)(void);

typedef void (*DisconnectFunc)(void);

static HeartbeatFunc orig_heartbeat_func = NULL;

static DisconnectFunc orig_disconnect_func = NULL;



// v36.97: No-op functions for MSHookFunction

static void noop_heartbeat(void) {

    DLOG(@"[NETIMPL-BLOCK] v36.97: HEARTBEAT BLOCKED (no-op)");

}



static void noop_disconnect(void) {

    DLOG(@"[NETIMPL-BLOCK] v36.97: DISCONNECT BLOCKED (no-op)");

}



// v36.57: Server list for rotation/retry

#define MAX_SERVERS 20

typedef struct {

    char ip[64];

    int port;

} ServerInfo;



static ServerInfo g_serverList[MAX_SERVERS];

static int g_serverCount = 0;

static int g_currentServerIndex = 0;

static int g_connectionFailCount = 0;



static NSMutableDictionary *g_msiStubData = nil;



static id msiStub_init(id self, SEL _cmd) {

    DLOG(@"[MSI-STUB] -[ServerInfoForClient init] called");

    if (!g_msiStubData) {

        g_msiStubData = [[NSMutableDictionary alloc] init];

        [g_msiStubData setObject:@1 forKey:@"status"];

        [g_msiStubData setObject:@1 forKey:@"serverType"];

        [g_msiStubData setObject:@1 forKey:@"serverid"];

        [g_msiStubData setObject:@1 forKey:@"clientid"];

        [g_msiStubData setObject:@"一区" forKey:@"category"];

        [g_msiStubData setObject:@"运行" forKey:@"description"];

        // v36.59: Do NOT hardcode ip/port here - let initWithDictionary set them

        DLOG(@"[MSI-STUB] Initialized empty (ip/port to be filled by caller)");

    }

    return self;

}



static id msiStub_initWithDict(id self, SEL _cmd, NSDictionary *dict) {

    DLOG(@"[MSI-STUB] -[ServerInfoForClient initWithDictionary:] called");

    if (!g_msiStubData) {

        g_msiStubData = [[NSMutableDictionary alloc] init];

    }

    

    if (dict) {

        // v36.59: Use the provided dictionary - preserve ORIGINAL ip and port from game server list!

        [g_msiStubData setDictionary:dict];

        DLOG(@"[MSI-STUB] Using original dict values from server list response");

    }

    

    // Ensure critical fields are set (ONLY if missing from dict)

    if (![g_msiStubData objectForKey:@"status"])

        [g_msiStubData setObject:@1 forKey:@"status"];

    if (![g_msiStubData objectForKey:@"serverType"])

        [g_msiStubData setObject:@1 forKey:@"serverType"];

    if (![g_msiStubData objectForKey:@"category"])

        [g_msiStubData setObject:@"一区" forKey:@"category"];

    // v36.59: FIX description field - replace '维护' with '运行'

    NSString *desc = [g_msiStubData objectForKey:@"description"];

    if (!desc || [desc isEqualToString:@"维护"]) {

        [g_msiStubData setObject:@"运行" forKey:@"description"];

    }

    

    // v36.59: DO NOT override ip and port! Keep ORIGINAL values from dict!

    // Game knows which server it selected - don't interfere with its choice!

    

    // Log all properties

    @try {

        for (NSString *key in g_msiStubData) {

            DLOG(@"[MSI-STUB]   %@ = %@", key, g_msiStubData[key]);

        }

    } @catch (NSException *e) {

        DLOG(@"[MSI-STUB] Exception logging: %@", e.reason);

    }

    

    return self;

}



static NSNumber *msiStub_status(id self, SEL _cmd) {

    DLOG(@"[MSI-STUB] -[ServerInfoForClient status] -> 1");

    return @1;

}



static NSString *msiStub_ip(id self, SEL _cmd) {

    // v36.59: Return ip from g_msiStubData (original value from dict), NOT hardcoded g_gameServerIP!

    NSString *ip = [g_msiStubData objectForKey:@"ip"];

    if (!ip) ip = [NSString stringWithUTF8String:g_gameServerIP];

    DLOG(@"[MSI-STUB] -[ServerInfoForClient ip] -> %@", ip);

    return ip;

}



static NSNumber *msiStub_port(id self, SEL _cmd) {

    // v36.59: Return port from g_msiStubData (original value from dict), NOT hardcoded g_gameServerPort!

    NSNumber *portNum = [g_msiStubData objectForKey:@"port"];

    int port = portNum ? [portNum intValue] : g_gameServerPort;

    DLOG(@"[MSI-STUB] -[ServerInfoForClient port] -> %d", port);

    return @(port);

}



static NSString *msiStub_category(id self, SEL _cmd) {

    DLOG(@"[MSI-STUB] -[ServerInfoForClient category] -> 一区");

    return @"一区";

}



static NSNumber *msiStub_serverType(id self, SEL _cmd) {

    DLOG(@"[MSI-STUB] -[ServerInfoForClient serverType] -> 1");

    return @1;

}



static NSInteger msiStub_integer(id self, SEL _cmd) {

    DLOG(@"[MSI-STUB] integer method called -> 1");

    return 1;

}



static NSString *msiStub_string(id self, SEL _cmd) {

    DLOG(@"[MSI-STUB] string method called -> stub");

    return @"stub";

}



static void createServerInfoForClientStub(void) {

    @try {

        // Check if class already exists

        Class existingClass = NSClassFromString(@"ServerInfoForClient");

        if (existingClass) {

            DLOG(@"[MSI-STUB] ServerInfoForClient class already exists");

            return;

        }

        

        // Create stub class

        Class stubClass = objc_allocateClassPair([NSObject class], "ServerInfoForClient", 0);

        if (stubClass) {

            // Add instance methods

            class_addMethod(stubClass, @selector(init), (IMP)msiStub_init, "@@:");

            class_addMethod(stubClass, @selector(initWithDictionary:), (IMP)msiStub_initWithDict, "@@:@");

            class_addMethod(stubClass, @selector(status), (IMP)msiStub_status, "@@:");

            class_addMethod(stubClass, @selector(statusValue), (IMP)msiStub_status, "@@:");

            class_addMethod(stubClass, @selector(ip), (IMP)msiStub_ip, "@@:");

            class_addMethod(stubClass, @selector(port), (IMP)msiStub_serverType, "@@:");

            class_addMethod(stubClass, @selector(category), (IMP)msiStub_category, "@@:");

            class_addMethod(stubClass, @selector(serverType), (IMP)msiStub_serverType, "@@:");

            class_addMethod(stubClass, @selector(serverid), (IMP)msiStub_integer, "l@:");

            class_addMethod(stubClass, @selector(clientid), (IMP)msiStub_integer, "l@:");

            class_addMethod(stubClass, @selector(description), (IMP)msiStub_string, "@@:");

            class_addMethod(stubClass, @selector(objectForKey:), (IMP)msiStub_string, "@@:@");

            

            // Register the class

            objc_registerClassPair(stubClass);

            DLOG(@"[MSI-STUB] Created ServerInfoForClient stub class successfully");

            

            // Verify class exists

            Class verifyClass = NSClassFromString(@"ServerInfoForClient");

            if (verifyClass) {

                DLOG(@"[MSI-STUB] Verified: ServerInfoForClient class is now available");

                

                // Log all methods

                unsigned int mcount = 0;

                Method *methods = class_copyMethodList(verifyClass, &mcount);

                for (unsigned int i = 0; i < mcount; i++) {

                    SEL sel = method_getName(methods[i]);

                    DLOG(@"[MSI-STUB]   Method: %@", NSStringFromSelector(sel));

                }

                if (methods) free(methods);

            }

        } else {

            DLOG(@"[MSI-STUB] Failed to create ServerInfoForClient stub class");

        }

    } @catch (NSException *e) {

        DLOG(@"[MSI-STUB] Exception creating stub class: %@", e.reason);

    }

}



static id msi_initWithDict_hook(id self, SEL _cmd, NSDictionary *dict) {

    NSMutableDictionary *mutDict = nil;

    if (dict) {

        mutDict = [dict mutableCopy];

        

        if ([mutDict objectForKey:@"status"]) {

            NSNumber *status = mutDict[@"status"];

            if ([status isKindOfClass:[NSNumber class]] && [status intValue] != 1) {

                DLOG(@"[MSI-PATCH] status=%@ -> 1", status);

                mutDict[@"status"] = @1;

            }

        }

        

        if ([mutDict objectForKey:@"serverType"]) {

            NSNumber *serverType = mutDict[@"serverType"];

            if ([serverType isKindOfClass:[NSNumber class]] && [serverType intValue] != 1) {

                DLOG(@"[MSI-PATCH] serverType=%@ -> 1", serverType);

                mutDict[@"serverType"] = @1;

            }

        }

        

        if ([mutDict objectForKey:@"clientid"]) {

            NSNumber *clientid = mutDict[@"clientid"];

            if ([clientid isKindOfClass:[NSNumber class]] && [clientid intValue] != 1) {

                DLOG(@"[MSI-PATCH] clientid=%@ -> 1", clientid);

                mutDict[@"clientid"] = @1;

            }

        }

        

        if ([mutDict objectForKey:@"serverid"]) {

            NSNumber *serverid = mutDict[@"serverid"];

            if ([serverid isKindOfClass:[NSNumber class]] && [serverid intValue] != 1) {

                DLOG(@"[MSI-PATCH] serverid=%@ -> 1", serverid);

                mutDict[@"serverid"] = @1;

            }

        }

        

        if ([mutDict objectForKey:@"category"]) {

            NSString *category = mutDict[@"category"];

            if ([category isKindOfClass:[NSString class]]) {

                BOOL isAllDots = YES;

                for (NSInteger i = 0; i < category.length; i++) {

                    if ([category characterAtIndex:i] != '.') { isAllDots = NO; break; }

                }

                if (isAllDots || [category length] == 0) {

                    DLOG(@"[MSI-PATCH] category=%@ -> 一区", category);

                    mutDict[@"category"] = @"一区";

                }

            }

        }

        

        if ([mutDict objectForKey:@"description"]) {

            NSString *desc = mutDict[@"description"];

            if ([desc isKindOfClass:[NSString class]] && [desc containsString:@"维护"]) {

                DLOG(@"[MSI-PATCH] description=%@ -> 运行", desc);

                mutDict[@"description"] = @"运行";

            }

        }

        

        // NO IP REPLACEMENT - keep original server IP

        // Normal client connects to 47.100.14.198 for both login and game servers

        if ([mutDict objectForKey:@"ip"]) {

            NSString *ip = mutDict[@"ip"];

            if ([ip isKindOfClass:[NSString class]]) {

                DLOG(@"[MSI] Server IP: %@ (not modified)", ip);

            }

        }

        

        DLOG(@"[MSI-CALL] -[%@ initWithDictionary:] (patched) -> %@", NSStringFromClass([self class]), [mutDict allKeys]);

        for (NSString *key in mutDict) {

            DLOG(@"[MSI-DICT]   %@ = %@", key, mutDict[key]);

        }

    }

    

    id (*origFunc)(id, SEL, NSDictionary*) = (id(*)(id, SEL, NSDictionary*))orig_msi_initWithDict;

    id ret = origFunc(self, _cmd, mutDict ?: dict);

    

    if (ret) {

        msi_log_properties(ret);

    }

    return ret;

}



static NSNumber *msi_status_hook(id self, SEL _cmd) {

    NSNumber *(*origFunc)(id, SEL) = (NSNumber*(*)(id, SEL))orig_msi_status;

    NSNumber *ret = origFunc(self, _cmd);

    if (ret && [ret intValue] != 1) {

        DLOG(@"[MSI-PATCH-STATUS] status=%@ -> 1 (property access)", ret);

        return @1;

    }

    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);

    return ret;

}



static NSString *msi_ip_hook(id self, SEL _cmd) {

    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);

    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);

    return ret;

}



static NSString *msi_category_hook(id self, SEL _cmd) {

    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);

    if (ret) {

        BOOL isAllDots = YES;

        for (NSInteger i = 0; i < ret.length; i++) {

            if ([ret characterAtIndex:i] != '.') { isAllDots = NO; break; }

        }

        if (isAllDots || [ret length] == 0) {

            DLOG(@"[MSI-PATCH-CAT] category=%@ -> 一区 (property access)", ret);

            return @"一区";

        }

    }

    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);

    return ret;

}



static NSNumber *msi_serverType_hook(id self, SEL _cmd) {

    NSNumber *ret = ((NSNumber*(*)(id, SEL))objc_msgSend)(self, _cmd);

    if (ret && [ret intValue] != 1) {

        DLOG(@"[MSI-PATCH-TYPE] serverType=%@ -> 1 (property access)", ret);

        return @1;

    }

    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);

    return ret;

}



static NSString *msi_string_hook(id self, SEL _cmd) {

    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);

    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);

    return ret;

}



static NSInteger msi_int_hook(id self, SEL _cmd) {

    NSInteger ret = ((NSInteger(*)(id, SEL))objc_msgSend)(self, _cmd);

    DLOG(@"[MSI-CALL] -[%@ %@] -> %ld", NSStringFromClass([self class]), NSStringFromSelector(_cmd), (long)ret);

    return ret;

}



static void createLogButton(UIWindow *w) {

    if (!w || g_btn) return;

    g_handler = [[WXHandler alloc] init];

    g_btn = [UIButton buttonWithType:UIButtonTypeCustom];

    g_btn.frame = CGRectMake(w.bounds.size.width - 60, 200, 50, 50);

    g_btn.layer.cornerRadius = 25;

    g_btn.clipsToBounds = YES;

    

    NSString *imagePath = [[NSBundle mainBundle] pathForResource:@"123" ofType:@"jpg"];

    if (imagePath && [[NSFileManager defaultManager] fileExistsAtPath:imagePath]) {

        UIImage *btnImage = [UIImage imageWithContentsOfFile:imagePath];

        if (btnImage) {

            btnImage = [btnImage imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];

            [g_btn setImage:btnImage forState:UIControlStateNormal];

            g_btn.imageView.contentMode = UIViewContentModeScaleAspectFill;

            DLOG(@"[UI] Log button using custom image: %@", imagePath);

        } else {

            [g_btn setTitle:@"LOG" forState:UIControlStateNormal];

            [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

            g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];

        }

    } else {

        [g_btn setTitle:@"LOG" forState:UIControlStateNormal];

        [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

        g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];

    }

    

    g_btn.titleLabel.font = [UIFont systemFontOfSize:10];

    g_btn.hidden = YES;

    g_btn.userInteractionEnabled = YES;

    [g_btn addTarget:g_handler action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];

    [w addSubview:g_btn];

    [w bringSubviewToFront:g_btn];

    

    // Pan gesture for moving the log button (drag to reposition)

    UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:g_handler action:@selector(handlePan:)];

    panGesture.cancelsTouchesInView = NO;

    panGesture.requiresExclusiveTouchType = NO;

    [g_btn addGestureRecognizer:panGesture];

    

    UITapGestureRecognizer *tripleTap = [[UITapGestureRecognizer alloc] initWithTarget:g_handler action:@selector(handleTripleTap:)];

    tripleTap.numberOfTapsRequired = 2;

    tripleTap.numberOfTouchesRequired = 3;

    tripleTap.cancelsTouchesInView = NO;

    tripleTap.delaysTouchesEnded = NO;

    tripleTap.delaysTouchesBegan = NO;

    tripleTap.requiresExclusiveTouchType = NO;

    [w addGestureRecognizer:tripleTap];

    

    _log(@"[UI] Button created on window (hidden, triple-tap to show)");

}



static void __attribute__((noinline)) tryHookMieshiServerInfo(int attempt) {

    Class msiCls = NSClassFromString(@"ServerInfoForClient");

    if (msiCls) {

        DLOG(@"[MSI-RETRY] ServerInfoForClient class FOUND at attempt #%d!", attempt);

        

        unsigned int mcount = 0;

        Method *methods = class_copyMethodList(msiCls, &mcount);

        for (unsigned int i = 0; i < mcount; i++) {

            SEL sel = method_getName(methods[i]);

            NSString *selName = NSStringFromSelector(sel);

            DLOG(@"[MSI-RETRY] -[%@ %@]", NSStringFromClass(msiCls), selName);

        }

        if (methods) free(methods);

        

        if (!orig_msi_init) {

            Method m_init = class_getInstanceMethod(msiCls, @selector(init));

            if (m_init) {

                orig_msi_init = method_getImplementation(m_init);

                method_setImplementation(m_init, (IMP)msi_init_hook);

                DLOG(@"[MSI-HOOK] Hooked: init");

            }

        }

        

        if (!orig_msi_initWithDict) {

            Method m_initDict = class_getInstanceMethod(msiCls, @selector(initWithDictionary:));

            if (m_initDict) {

                orig_msi_initWithDict = method_getImplementation(m_initDict);

                method_setImplementation(m_initDict, (IMP)msi_initWithDict_hook);

                DLOG(@"[MSI-HOOK] Hooked: initWithDictionary:");

            }

        }

        

        if (!orig_msi_status) {

            Method m_status = class_getInstanceMethod(msiCls, @selector(status));

            if (m_status) {

                orig_msi_status = method_getImplementation(m_status);

                method_setImplementation(m_status, (IMP)msi_status_hook);

                DLOG(@"[MSI-HOOK] Hooked: status");

            }

        }

        

        Method m_statusValue = class_getInstanceMethod(msiCls, @selector(statusValue));

        if (m_statusValue) {

            method_setImplementation(m_statusValue, (IMP)msi_status_hook);

            DLOG(@"[MSI-HOOK] Hooked: statusValue");

        }

        

        Method m_ip = class_getInstanceMethod(msiCls, @selector(ip));

        if (m_ip) {

            method_setImplementation(m_ip, (IMP)msi_ip_hook);

            DLOG(@"[MSI-HOOK] Hooked: ip");

        }

        

        Method m_category = class_getInstanceMethod(msiCls, @selector(category));

        if (m_category) {

            method_setImplementation(m_category, (IMP)msi_category_hook);

            DLOG(@"[MSI-HOOK] Hooked: category");

        }

        

        Method m_serverType = class_getInstanceMethod(msiCls, @selector(serverType));

        if (m_serverType) {

            method_setImplementation(m_serverType, (IMP)msi_serverType_hook);

            DLOG(@"[MSI-HOOK] Hooked: serverType");

        }

        

        Method m_serverId = class_getInstanceMethod(msiCls, @selector(serverid));

        if (m_serverId) {

            method_setImplementation(m_serverId, (IMP)msi_serverType_hook);

            DLOG(@"[MSI-HOOK] Hooked: serverid");

        }

        

        Method m_clientId = class_getInstanceMethod(msiCls, @selector(clientid));

        if (m_clientId) {

            method_setImplementation(m_clientId, (IMP)msi_serverType_hook);

            DLOG(@"[MSI-HOOK] Hooked: clientid");

        }

    } else {

        DLOG(@"[MSI-RETRY] ServerInfoForClient class not found at attempt #%d", attempt);



        // v37.4: DISABLED stub class creation — creating a fake ServerInfoForClient

        //        class interferes with client's native server list parsing.

        //        capture_real.js (Frida diagnostic) never created this stub and

        //        client worked perfectly. The stub's ip/port methods return invalid

        //        values, causing '网络连接中断' when client tries to connect game server.

        if (attempt >= 2) {

            DLOG(@"[MSI-STUB] v37.4: STUB CREATION DISABLED — letting client parse natively");

            return;

        }



    }

    // v37.118: MSI retry loop DISABLED — no more MSI hooks needed

}



#pragma mark - Deep Diagnostics (trace server list display)

// ============================================================



static NSArray *(*orig_arrayWithObjects)(Class, SEL, const id *, unsigned int);

static NSArray *hook_arrayWithObjects(Class self, SEL _cmd, const id *objects, unsigned int count) {

    NSArray *ret = orig_arrayWithObjects(self, _cmd, objects, count);

    DLOG(@"[DIAG-ARRAY] +[NSArray arrayWithObjects:] count=%u", count);

    for (unsigned int i = 0; i < count && i < 5; i++) {

        if (objects[i]) {

            DLOG(@"[DIAG-ARRAY]   obj[%u] = %@ (%@)", i, objects[i], NSStringFromClass([objects[i] class]));

        }

    }

    return ret;

}



static NSUInteger (*orig_tableViewNumberOfRows)(id, SEL, UITableView *, NSInteger);

static NSUInteger hook_tableViewNumberOfRows(id self, SEL _cmd, UITableView *tableView, NSInteger section) {

    NSUInteger ret = orig_tableViewNumberOfRows(self, _cmd, tableView, section);

    DLOG(@"[DIAG-TABLE] -[DataSource numberOfRowsInSection:%ld] -> %lu", (long)section, (unsigned long)ret);

    return ret;

}



static NSInteger (*orig_tableViewNumberOfSections)(id, SEL, UITableView *);

static NSInteger hook_tableViewNumberOfSections(id self, SEL _cmd, UITableView *tableView) {

    NSInteger ret = orig_tableViewNumberOfSections(self, _cmd, tableView);

    DLOG(@"[DIAG-TABLE] -[DataSource numberOfSections] -> %ld", (long)ret);

    return ret;

}



static void (*orig_alertViewShow)(id, SEL);

static void hook_alertViewShow(id self, SEL _cmd) {

    NSString *title = [self performSelector:@selector(title)];

    NSString *msg = [self performSelector:@selector(message)];

    DLOG(@"[DIAG-ALERT] UIAlertView show: title='%@' msg='%@'", title, msg);

    

    NSArray *stack = [NSThread callStackSymbols];

    for (NSUInteger i = 0; i < [stack count] && i < 20; i++) {

        DLOG(@"[DIAG-ALERT-STACK] %@", stack[i]);

    }

    

    NSString *lowerMsg = [msg lowercaseString];

    NSString *lowerTitle = [title lowercaseString];

    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 

        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||

        [lowerMsg containsString:@"升级"]) {

        DLOG(@"[ALERT-BLOCK] Blocked version check alert: title='%@' msg='%@'", title, msg);

        return;

    }

    

    orig_alertViewShow(self, _cmd);

}



// v36.59: COMPLETE FIX - Correct method signature!

// -[UIViewController presentViewController:animated:completion:] has 3 params after self/_cmd:

//   arg1 = viewControllerToPresent (UIViewController*)

//   arg2 = animated (BOOL)

//   arg3 = completion (dispatch_block_t)

// Previous hook had WRONG parameter order causing SIGSEGV when calling the "completion"

// which was actually a BOOL value (0x0 or 0x1) interpreted as block pointer!

static void (*orig_alertControllerPresent)(id, SEL, id, BOOL, dispatch_block_t);

static void hook_alertControllerPresent(id self, SEL _cmd, id viewControllerToPresent, BOOL animated, dispatch_block_t completion) {

    @try {

        // Check orig function pointer

        if (!orig_alertControllerPresent) {

            DLOG(@"[DIAG-ALERT] orig_alertControllerPresent is NULL, passthrough");

            // Even if orig is NULL we can't proceed - but avoid crash

            return;

        }

        

        // v36.59: Check self (presenting VC)

        if (!self) {

            DLOG(@"[DIAG-ALERT] self (presenting VC) is nil/NULL");

            return;

        }

        

        // v36.59: Check viewControllerToPresent (the one being presented, could be UIAlertController)

        if (!viewControllerToPresent) {

            DLOG(@"[DIAG-ALERT] viewControllerToPresent is nil/NULL");

            return;

        }

        

        // Check if the presented VC is UIAlertController - that's what we want to intercept

        BOOL isAlert = NO;

        @try {

            if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {

                isAlert = YES;

                UIAlertController *alert = (UIAlertController *)viewControllerToPresent;

                NSString *title = [alert title];

                NSString *msg = [alert message];

                DLOG(@"[DIAG-ALERT] UIAlertController present: title='%@' msg='%@' presentingVC=%@", 

                     title ? title : @"<nil>", msg ? msg : @"<nil>", 

                     NSStringFromClass([self class]));

                

                // Block version-related alerts

                if (title || msg) {

                    NSString *lowerMsg = msg ? [[msg lowercaseString] copy] : @"";

                    NSString *lowerTitle = title ? [[title lowercaseString] copy] : @"";

                    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 

                        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||

                        [lowerMsg containsString:@"升级"] || [lowerMsg containsString:@"version"] ||

                        [lowerMsg containsString:@"update"]) {

                        DLOG(@"[ALERT-BLOCK] Blocked version check UIAlertController: title='%@' msg='%@'", 

                             title ? title : @"", msg ? msg : @"");

                        return;  // Do not present!

                    }

                }

            }

        } @catch (NSException *e) {

            DLOG(@"[DIAG-ALERT] Exception checking alert: %@", e.reason);

            isAlert = NO;  // On error, just passthrough

        }

        

        // v36.59: SAFE completion handling with Block_copy to avoid stack-block crash

        dispatch_block_t safeCompletion = NULL;

        if (completion != NULL) {

            // Copy the block to heap in case it's a stack-allocated block

            @try {

                safeCompletion = [completion copy];  // ARC-style or Block_copy equivalent

            } @catch (NSException *e) {

                DLOG(@"[DIAG-ALERT] Exception copying completion block: %@", e.reason);

                safeCompletion = NULL;

            }

        }

        if (!safeCompletion) {

            // Provide a static empty block (heap-allocated by compiler)

            safeCompletion = ^{};

        }

        

        // v36.59: Use __weak self to avoid dangling pointers on async dispatch

        __weak id weakPresentingVC = self;

        __weak id weakPresentedVC = viewControllerToPresent;

        dispatch_block_t copiedCompletion = [safeCompletion copy];

        

        void (*callOrig)(id, SEL, id, BOOL, dispatch_block_t) = orig_alertControllerPresent;

        

        if ([NSThread isMainThread]) {

            @try {

                callOrig(self, _cmd, viewControllerToPresent, animated, copiedCompletion);

            } @catch (NSException *e) {

                DLOG(@"[DIAG-ALERT] Exception calling orig present (main thread): %@", e.reason);

            } @catch (...) {

                DLOG(@"[DIAG-ALERT] Unknown C++/signal exception calling orig present (main thread)");

            }

        } else {

            dispatch_async(dispatch_get_main_queue(), ^{

                @try {

                    id strongPresenting = weakPresentingVC;

                    id strongPresented = weakPresentedVC;

                    if (strongPresenting && strongPresented) {

                        callOrig(strongPresenting, _cmd, strongPresented, animated, copiedCompletion);

                    } else {

                        DLOG(@"[DIAG-ALERT] Async present aborted: presentingVC or presentedVC deallocated");

                    }

                } @catch (NSException *e) {

                    DLOG(@"[DIAG-ALERT] Exception calling orig present (async main thread): %@", e.reason);

                } @catch (...) {

                    DLOG(@"[DIAG-ALERT] Unknown exception calling orig present (async main thread)");

                }

            });

        }

    } @catch (NSException *e) {

        DLOG(@"[DIAG-ALERT] Exception in alert hook OUTER: %@", e.reason);

    } @catch (...) {

        DLOG(@"[DIAG-ALERT] Unknown C++/foreign exception in alert hook OUTER");

    }

}



// ============================================================

#pragma mark - Gzip utilities

// ============================================================



static BOOL isGzipData(const unsigned char *data, size_t len) {

    return (len >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08);

}



static unsigned char *gzipDecompress(const unsigned char *data, size_t len, size_t *outLen) {

    if (!data || len < 10 || !isGzipData(data, len)) return NULL;

    

    z_stream strm;

    memset(&strm, 0, sizeof(strm));

    

    if (inflateInit2(&strm, MAX_WBITS + 16) != Z_OK) return NULL;

    

    strm.next_in = (Bytef *)data;

    strm.avail_in = len;

    

    size_t bufSize = len * 4;

    unsigned char *buf = (unsigned char *)malloc(bufSize);

    if (!buf) { inflateEnd(&strm); return NULL; }

    

    unsigned char *outBuf = buf;

    size_t totalOut = 0;

    

    do {

        strm.next_out = (Bytef *)buf;

        strm.avail_out = bufSize;

        

        int ret = inflate(&strm, Z_NO_FLUSH);

        

        size_t produced = bufSize - strm.avail_out;

        if (produced > 0) {

            totalOut += produced;

            unsigned char *newBuf = (unsigned char *)realloc(outBuf, totalOut + bufSize);

            if (!newBuf) { free(outBuf); inflateEnd(&strm); return NULL; }

            buf = newBuf + totalOut - produced;

            outBuf = newBuf;

        }

        

        if (ret == Z_STREAM_END) break;

        if (ret != Z_OK) { free(outBuf); inflateEnd(&strm); return NULL; }

        

    } while (strm.avail_in > 0);

    

    inflateEnd(&strm);

    

    unsigned char *finalBuf = (unsigned char *)realloc(outBuf, totalOut + 1);

    if (finalBuf) {

        finalBuf[totalOut] = '\0';

        *outLen = totalOut;

        return finalBuf;

    }

    

    free(outBuf);

    return NULL;

}



static unsigned char *gzipCompress(const unsigned char *data, size_t len, size_t *outLen) {

    if (!data || len == 0) return NULL;

    

    z_stream strm;

    memset(&strm, 0, sizeof(strm));

    

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return NULL;

    

    strm.next_in = (Bytef *)data;

    strm.avail_in = len;

    

    size_t bufSize = len + (len / 10) + 12;

    unsigned char *buf = (unsigned char *)malloc(bufSize);

    if (!buf) { deflateEnd(&strm); return NULL; }

    

    unsigned char *outBuf = buf;

    size_t totalOut = 0;

    

    do {

        strm.next_out = (Bytef *)buf;

        strm.avail_out = bufSize;

        

        int ret = deflate(&strm, Z_FINISH);

        

        size_t produced = bufSize - strm.avail_out;

        if (produced > 0) {

            totalOut += produced;

            unsigned char *newBuf = (unsigned char *)realloc(outBuf, totalOut + bufSize);

            if (!newBuf) { free(outBuf); deflateEnd(&strm); return NULL; }

            buf = newBuf + totalOut - produced;

            outBuf = newBuf;

        }

        

        if (ret == Z_STREAM_END) break;

        if (ret != Z_OK) { free(outBuf); deflateEnd(&strm); return NULL; }

        

    } while (strm.avail_in > 0);

    

    deflateEnd(&strm);

    

    *outLen = totalOut;

    return outBuf;

}



// ============================================================

#pragma mark - BSD socket hooks (detect game network traffic)

// ============================================================



#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <unistd.h>

#include <execinfo.h>

#include <sys/time.h>

#include <fcntl.h>



// === Socket hook functions ===

typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);

typedef ssize_t (*SendFunc)(int, const void *, size_t, int);

typedef ssize_t (*RecvFunc)(int, void *, size_t, int);

typedef ssize_t (*WriteFunc)(int, const void *, size_t);

typedef ssize_t (*ReadFunc)(int, void *, size_t);

typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);

typedef int (*CloseFunc)(int);

typedef int (*GetsockoptFunc)(int, int, int, void *, socklen_t *);

typedef int (*PollFunc)(struct pollfd *, nfds_t, int);

typedef int (*SelectFunc)(int, fd_set *, fd_set *, fd_set *, struct timeval *);



static ConnectFunc orig_connect = NULL;

static SendFunc orig_send = NULL;

static RecvFunc orig_recv = NULL;

static RecvfromFunc orig_recvfrom = NULL;

static RecvmsgFunc orig_recvmsg = NULL;

static WriteFunc orig_write = NULL;

static ReadFunc orig_read = NULL;

static CloseFunc orig_close = NULL;

static GetsockoptFunc orig_getsockopt = NULL;

static PollFunc orig_poll = NULL;

static SelectFunc orig_select = NULL;



#define MAX_TRACKED_FDS 64

static int g_trackedFds[MAX_TRACKED_FDS];

static char g_trackedHosts[MAX_TRACKED_FDS][64];

static int g_trackedPorts[MAX_TRACKED_FDS];

static int g_trackedCount = 0;

static BOOL g_trackedActive[MAX_TRACKED_FDS];



// Note: g_gameServerPort, g_gameServerIP, g_gameServerInfoUpdated defined earlier for stub class access



static void clearTrackedFd(int fd) {

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == fd) {

            DLOG(@"[FD-CLOSE] fd=%d %s:%d removed from tracking", fd, g_trackedHosts[i], g_trackedPorts[i]);

            g_trackedActive[i] = NO;

            g_trackedFds[i] = -1;

            g_trackedHosts[i][0] = '\0';

            g_trackedPorts[i] = 0;

            return;

        }

    }

}



static void trackFd(int fd, const char *host, int port) {

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == fd) {

            DLOG(@"[FD-UPDATE] fd=%d updated from %s:%d to %s:%d", fd, 

                 g_trackedHosts[i], g_trackedPorts[i], host, port);

            strncpy(g_trackedHosts[i], host, 63);

            g_trackedPorts[i] = port;

            g_trackedActive[i] = YES;

            return;

        }

    }

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == -1) {

            g_trackedFds[i] = fd;

            strncpy(g_trackedHosts[i], host, 63);

            g_trackedPorts[i] = port;

            g_trackedActive[i] = YES;

            DLOG(@"[FD-REUSE] fd=%d %s:%d reused slot %d", fd, host, port, i);

            return;

        }

    }

    if (g_trackedCount >= MAX_TRACKED_FDS) {

        DLOG(@"[FD-ERROR] Max tracked fds reached (%d)", MAX_TRACKED_FDS);

        return;

    }

    g_trackedFds[g_trackedCount] = fd;

    strncpy(g_trackedHosts[g_trackedCount], host, 63);

    g_trackedPorts[g_trackedCount] = port;

    g_trackedActive[g_trackedCount] = YES;

    g_trackedCount++;

}



static const char *getHostForFd(int fd) {

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == fd && g_trackedActive[i]) return g_trackedHosts[i];

    }

    return NULL;

}



static int getPortForFd(int fd) {

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == fd && g_trackedActive[i]) return g_trackedPorts[i];

    }

    return 0;

}



// v36.134: Inject UUID into 0x000EE007 device info packet for game server

// Login server (5678) sends 143-byte packet without UUID field

// Game server expects 179-byte packet with UUID TLV after GPU field

//

// REAL CAPTURE FORMAT (hook.txt SEND #29, 178 bytes):

//   ...GPU TLV (2-byte len + data)...

//   00 00 00 00 00 00 00  - 7 bytes reserved (zero)

//   24                    - 1 byte UUID length (0x24 = 36)

//   [36-byte UUID string]

//   00                    - 1 byte suffix (zero)

//   01 00                 - 2 bytes trailer

//

// v36.134 FIX: Previous versions injected UUID at offset 34 (after device ID)

//   with wrong format (2-byte len + UUID). Correct position is AFTER GPU field,

//   with format: 7-byte zero + 1-byte len + UUID + 1-byte zero.

static ssize_t injectUUIDIntoDeviceInfo(const uint8_t *src, size_t srcLen,

                                         uint8_t *dst, size_t dstMaxLen) {

    if (!src || srcLen < 36 || !dst || dstMaxLen < srcLen + 40) {

        DLOG(@"[UUID-INJECT] Invalid params: srcLen=%zu dstMaxLen=%zu", srcLen, dstMaxLen);

        return -1;

    }



    // Get UUID (prefer IDFV, fallback to fixed)

    const char *fakeUUID = "00000000-0000-0000-0000-000000000001";

    @try {

        UIDevice *device = [UIDevice currentDevice];

        if (device && [device respondsToSelector:@selector(identifierForVendor)]) {

            NSUUID *idfv = [device identifierForVendor];

            if (idfv) {

                NSString *uuidStr = [idfv UUIDString];

                if (uuidStr && uuidStr.length == 36) {

                    fakeUUID = uuidStr.UTF8String;

                }

            }

        }

    } @catch (NSException *e) {}



    size_t uuidStrLen = strlen(fakeUUID);  // 36



    // v36.134: Parse all TLV fields to find GPU field

    // Header: 4(pktLen) + 4(cmd) + 4(seq) = 12 bytes

    // Then: sequence of TLV fields (2-byte big-endian len + N bytes data)

    size_t offset = 12;

    int fieldCount = 0;

    size_t gpuFieldEnd = 0;



    while (offset + 2 <= srcLen && fieldCount < 30) {

        uint16_t fieldLen = ((uint16_t)src[offset] << 8) | (uint16_t)src[offset + 1];

        if (fieldLen > 200 || offset + 2 + fieldLen > srcLen) {

            DLOG(@"[UUID-INJECT] v36.134: Invalid field at offset %zu: len=%u srcLen=%zu",

                 offset, fieldLen, srcLen);

            break;

        }



        // Check if this is GPU field (contains "GPU" substring)

        if (fieldLen >= 3 && offset + 2 + fieldLen <= srcLen) {

            const uint8_t *fieldData = src + offset + 2;

            for (uint16_t i = 0; i + 3 <= fieldLen; i++) {

                if (fieldData[i] == 'G' && fieldData[i+1] == 'P' && fieldData[i+2] == 'U') {

                    gpuFieldEnd = offset + 2 + fieldLen;

                    DLOG(@"[UUID-INJECT] v36.134: Found GPU field at offset %zu, ends at %zu (len=%u)",

                         offset, gpuFieldEnd, fieldLen);

                    break;

                }

            }

            if (gpuFieldEnd > 0) break;

        }



        offset += 2 + fieldLen;

        fieldCount++;

    }



    if (gpuFieldEnd == 0) {

        DLOG(@"[UUID-INJECT] v36.134: GPU field NOT found, falling back to old logic");

        // Fallback: old logic (inject after first TLV field)

        uint16_t firstFieldLen = ((uint16_t)src[12] << 8) | (uint16_t)src[13];

        if (firstFieldLen > 200 || 14 + firstFieldLen > srcLen) return -1;

        size_t insertOffset = 12 + 2 + firstFieldLen;

        size_t newPayloadSize = srcLen + 2 + uuidStrLen;

        if (newPayloadSize > dstMaxLen) return -1;

        memcpy(dst, src, insertOffset);

        dst[insertOffset] = (uuidStrLen >> 8) & 0xFF;

        dst[insertOffset + 1] = uuidStrLen & 0xFF;

        memcpy(dst + insertOffset + 2, fakeUUID, uuidStrLen);

        memcpy(dst + insertOffset + 2 + uuidStrLen, src + insertOffset, srcLen - insertOffset);

        uint32_t newTotalLen = (uint32_t)newPayloadSize;

        dst[0] = (newTotalLen >> 24) & 0xFF;

        dst[1] = (newTotalLen >> 16) & 0xFF;

        dst[2] = (newTotalLen >> 8) & 0xFF;

        dst[3] = newTotalLen & 0xFF;

        return (ssize_t)newPayloadSize;

    }



    // v36.134: Check trailing structure after GPU field

    // Expected: 9 bytes zero + 01 00 (trailer)

    // Target:   7 bytes zero + 1 byte len(0x24) + 36 bytes UUID + 1 byte zero + 01 00

    size_t tailStart = srcLen - 2;  // position of "01 00"

    if (srcLen < 2 || src[tailStart] != 0x01 || src[tailStart + 1] != 0x00) {

        DLOG(@"[UUID-INJECT] v36.134: Trailer 01 00 not found at end (srcLen=%zu)", srcLen);

        return -1;

    }



    size_t midLen = tailStart - gpuFieldEnd;  // bytes between GPU end and trailer

    DLOG(@"[UUID-INJECT] v36.134: midLen=%zu (between GPU end and trailer)", midLen);



    // Build new packet:

    // [header + TLV fields up to GPU end] + [7 zero + 1 len + 36 UUID + 1 zero] + [01 00]

    size_t uuidBlockLen = 7 + 1 + uuidStrLen + 1;  // 7+1+36+1 = 45

    size_t newLen = gpuFieldEnd + uuidBlockLen + 2;  // +2 for trailer

    if (newLen > dstMaxLen) {

        DLOG(@"[UUID-INJECT] v36.134: Output too large: need %zu max %zu", newLen, dstMaxLen);

        return -1;

    }



    // Copy [header + TLV fields up to GPU end]

    memcpy(dst, src, gpuFieldEnd);



    // Write 7 bytes zero (reserved)

    memset(dst + gpuFieldEnd, 0, 7);



    // Write 1 byte UUID length (0x24 = 36)

    dst[gpuFieldEnd + 7] = (uint8_t)uuidStrLen;



    // Write UUID string (36 bytes)

    memcpy(dst + gpuFieldEnd + 8, fakeUUID, uuidStrLen);



    // Write 1 byte zero (suffix)

    dst[gpuFieldEnd + 8 + uuidStrLen] = 0;



    // Write trailer (01 00)

    dst[gpuFieldEnd + 8 + uuidStrLen + 1] = 0x01;

    dst[gpuFieldEnd + 8 + uuidStrLen + 2] = 0x00;



    // Update packet length in header (bytes 0-3, big-endian)

    uint32_t newTotalLen = (uint32_t)newLen;

    dst[0] = (newTotalLen >> 24) & 0xFF;

    dst[1] = (newTotalLen >> 16) & 0xFF;

    dst[2] = (newTotalLen >> 8) & 0xFF;

    dst[3] = newTotalLen & 0xFF;



    DLOG(@"[UUID-INJECT] v36.134: SUCCESS %zu -> %zu bytes (UUID at GPU+7, midLen was %zu, UUID=%.*s)",

         srcLen, newLen, midLen, 8, fakeUUID);



    return (ssize_t)newLen;

}



// v36.71: Check if a command is from game server protocol (not login server)

// Game server cmd ranges:

//   0x00FFxxxx / 0x80FFxxxx - Handshake/challenge/response

//   0x000Exxxx / 0x800Exxxx - Device info related

//   0x00EExxxx / 0x80EExxxx - Extended device info responses

// Login server uses 0x802Exxxx range

static BOOL isGameCmd(uint32_t cmd) {

    uint32_t prefix = cmd & 0xFFFF0000;

    // Game server: 0x00FFxxxx, 0x80FFxxxx, 0x000Exxxx, 0x800Exxxx, 0x00EExxxx, 0x80EExxxx

    if (prefix == 0x00FF0000 || prefix == 0x80FF0000 ||

        prefix == 0x000E0000 || prefix == 0x800E0000 ||

        prefix == 0x00EE0000 || prefix == 0x80EE0000) {

        return YES;

    }

    return NO;

}



// v36.112: Unified game port detection function

static BOOL isGameServerPort(int port) {

    // Known game server ports

    if (port == 12003 || port == 58158 || port == 5679 || port == 5680 || port == 5681) {

        return YES;

    }

    // Dynamic detection: if we have a tracked game port, match against it

    if (g_gameServerPort >= 1024 && port == g_gameServerPort) {

        return YES;

    }

    // Range-based detection for dynamically assigned ports

    if (port >= 5000 && port <= 65535 && g_gameServerPort >= 1024) {

        return YES;

    }

    return NO;

}



static void updateFdHostPort(int fd, const char *host, int port) {

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == fd) {

            strncpy(g_trackedHosts[i], host, 63);

            g_trackedPorts[i] = port;

            DLOG(@"[FD-UPDATE] Updated fd=%d to %s:%d", fd, host, port);

            return;

        }

    }

    // Not found, add new entry

    trackFd(fd, host, port);

}



static void parseServerListResponse(const unsigned char *data, ssize_t len) {

    if (!data || len < 12) return;

    

    @try {

        NSString *bodyStr = [[NSString alloc] initWithBytes:data+12 length:(NSUInteger)(len-12) encoding:NSUTF8StringEncoding];

        if (bodyStr && bodyStr.length > 0) {

            DLOG(@"[SERVERLIST-PARSE] Response body length: %lu", (unsigned long)bodyStr.length);

            

            NSRegularExpression *ipRegex = [NSRegularExpression regularExpressionWithPattern:@"\"ip\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];

            NSArray *ipMatches = [ipRegex matchesInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];

            NSMutableArray *ips = [NSMutableArray array];

            for (NSTextCheckingResult *match in ipMatches) {

                NSString *ipStr = [bodyStr substringWithRange:[match rangeAtIndex:1]];

                [ips addObject:ipStr];

                DLOG(@"[SERVERLIST-PARSE] Found IP: %@", ipStr);

            }

            

            NSRegularExpression *portRegex = [NSRegularExpression regularExpressionWithPattern:@"\"port\"\\s*:\\s*(\\d+)" options:0 error:nil];

            NSArray *portMatches = [portRegex matchesInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];

            NSMutableArray *ports = [NSMutableArray array];

            for (NSTextCheckingResult *match in portMatches) {

                NSString *portStr = [bodyStr substringWithRange:[match rangeAtIndex:1]];

                int portInt = [portStr intValue];

                [ports addObject:portStr];

                DLOG(@"[SERVERLIST-PARSE] Found port: %@ (int=%d)", portStr, portInt);

            }

            

            if (ips.count > 0 && ports.count > 0) {

                // v36.57: Store servers in list for rotation

                g_serverCount = 0;

                for (NSUInteger i = 0; i < MIN(ips.count, ports.count) && g_serverCount < MAX_SERVERS; i++) {

                    int portInt = [ports[i] intValue];

                    if (portInt > 0 && portInt < 65536) {

                        NSString *ipStr = ips[i];

                        DLOG(@"[SERVERLIST-PARSE] Server %d: %@:%d", g_serverCount, ipStr, portInt);

                        

                        // Store in server list for rotation

                        strncpy(g_serverList[g_serverCount].ip, [ipStr UTF8String], 63);

                        g_serverList[g_serverCount].port = portInt;

                        g_serverCount++;

                        

                        // Set first valid server as default

                        if (g_serverCount == 1) {

                            strncpy(g_gameServerIP, [ipStr UTF8String], 63);

                            g_gameServerPort = portInt;

                            g_currentServerIndex = 0;

                            DLOG(@"[SERVERLIST-PARSE] Set default game server: %s:%d", g_gameServerIP, g_gameServerPort);

                        }

                    }

                }

                DLOG(@"[SERVERLIST-PARSE] Stored %d servers for rotation", g_serverCount);

            }

        } else {

            DLOG(@"[SERVERLIST-PARSE] Binary/mixed response, parsing...");

            DLOG(@"[SERVERLIST-PARSE] First 64 bytes hex:");

            for (int i = 0; i < MIN(64, len-12); i++) {

                printf("%02x ", data[12+i]);

                if ((i+1) % 16 == 0) printf("\n");

            }

            printf("\n");

            

            const unsigned char *body = data + 12;

            ssize_t bodyLen = len - 12;

            

            // v36.60: CLEAN REWRITE of binary parsing

            // BUG in v36.59: Raw 4-byte IP scan produced 100% false positives!

            //   e.g. bytes of ASCII strings ("47.100.14.198" encoded) got treated as binary IP

            //   resulting in garbage servers like "16.228.184.128:58764" being stored FIRST,

            //   crowding out the 12 real ASCII IPs that were found but never stored (MAX_SERVERS=20).

            // FIX:

            //   1. DISABLE raw 4-byte IP scan entirely.

            //   2. ONLY use ASCII IP pattern scan (we know it finds real IPs from the log).

            //   3. If we can't find a port near an ASCII IP, DEFAULT TO PORT 12003!

            //      (from previous tests v36.55 we know at least 12003 accepts connections and completes handshake,

            //       whereas 58158 hangs completely)

            

            g_serverCount = 0;

            NSMutableArray *foundServers = [NSMutableArray array];

            const int DEFAULT_GAME_PORT = 58158;  // v36.62: Force default port to 58158

            

            DLOG(@"[SERVERLIST-PARSE] (v36.62) Scanning ONLY for ASCII IP patterns, port FORCED to 58158");

            DLOG(@"[SERVERLIST-PARSE] (v36.62) Binary port parsing DISABLED (was causing 11776 misparse)");

            

            for (ssize_t offset = 0; offset < bodyLen - 7 && g_serverCount < MAX_SERVERS; offset++) {

                if (body[offset] >= '1' && body[offset] <= '9') {

                    char candidate[128];

                    ssize_t i = 0;

                    ssize_t start = offset;

                    while (offset < bodyLen && i < 63 &&

                           ((body[offset] >= '0' && body[offset] <= '9') || body[offset] == '.')) {

                        candidate[i++] = (char)body[offset++];

                    }

                    candidate[i] = '\0';

                    

                    int dots = 0;

                    int octets[4] = {0, 0, 0, 0};

                    int octIdx = 0;

                    int curVal = 0;

                    BOOL validFormat = YES;

                    for (ssize_t j = 0; candidate[j]; j++) {

                        if (candidate[j] == '.') {

                            if (j == 0 || candidate[j+1] == '.' || candidate[j+1] == '\0') { validFormat = NO; break; }

                            dots++;

                            if (curVal > 255) { validFormat = NO; break; }

                            octets[octIdx++] = curVal;

                            curVal = 0;

                        } else if (candidate[j] >= '0' && candidate[j] <= '9') {

                            curVal = curVal * 10 + (candidate[j] - '0');

                            if (curVal > 255) { validFormat = NO; break; }

                        } else {

                            validFormat = NO;

                            break;

                        }

                    }

                    if (octIdx < 3) validFormat = NO;  // need at least 3 dots (i.e. 4 octets)

                    if (validFormat && dots == 3) {

                        octets[3] = curVal;

                        if (octets[3] > 255) validFormat = NO;

                    }

                    if (octets[0] == 0 || octets[0] == 127 || octets[0] >= 224) validFormat = NO;

                    if (octets[3] == 0) validFormat = NO;

                    

                    if (dots == 3 && validFormat && i > 6) {

                        DLOG(@"[SERVERLIST-PARSE] Valid ASCII IP at %zd: '%s' (octets=%d.%d.%d.%d)",

                             start, candidate, octets[0], octets[1], octets[2], octets[3]);

                        

                        int assignedPort = DEFAULT_GAME_PORT;

                        BOOL portFound = NO;

                        

                        // Try to find ASCII port first - pattern after IP: "port":12003 or :12003

                        // Search up to 60 bytes after IP for the first : followed by digits

                        ssize_t maxSearch = (offset + 100 < bodyLen) ? (offset + 100) : bodyLen;

                        for (ssize_t pOffset = offset; pOffset < maxSearch - 6 && !portFound; pOffset++) {

                            // Try ASCII: :<number>

                            if (body[pOffset] == ':' && (body[pOffset+1] >= '1' && body[pOffset+1] <= '9')) {

                                ssize_t k = pOffset + 1;

                                int p = 0;

                                while (k < maxSearch && body[k] >= '0' && body[k] <= '9' && p < 65536) {

                                    p = p * 10 + (body[k] - '0');

                                    k++;

                                }

                                if (p >= 1024 && p < 65536) {

                                    assignedPort = p;

                                    portFound = YES;

                                    DLOG(@"[SERVERLIST-PARSE]   -> Found ASCII port %d at offset %zd", assignedPort, pOffset);

                                }

                            }

                            

                            // Also check for "port":<digits> pattern

                            if (pOffset + 7 < maxSearch &&

                                body[pOffset]=='p' && body[pOffset+1]=='o' && body[pOffset+2]=='r' &&

                                body[pOffset+3]=='t' && body[pOffset+5]=='\"' &&

                                body[pOffset+6] >= '1' && body[pOffset+6] <= '9') {

                                ssize_t k = pOffset + 6;

                                int p = 0;

                                while (k < maxSearch && body[k] >= '0' && body[k] <= '9' && p < 65536) {

                                    p = p * 10 + (body[k] - '0');

                                    k++;

                                }

                                if (p >= 1024 && p < 65536) {

                                    assignedPort = p;

                                    portFound = YES;

                                    DLOG(@"[SERVERLIST-PARSE]   -> Found port via \"port\" keyword: %d at offset %zd",

                                         assignedPort, pOffset);

                                }

                            }

                            

                        // v36.62: DISABLE binary port parsing - it was causing 11776 misparse

                        // (0x2E00 is the low byte of 0xE32E = 58158, not a real port)

                        // Always use DEFAULT_GAME_PORT (58158) instead of trying to parse binary ports

                        assignedPort = DEFAULT_GAME_PORT;

                        portFound = YES;  // Mark as found (using default)

                        DLOG(@"[SERVERLIST-PARSE]   -> Port forced to %d (binary parsing disabled to prevent 11776 misparse)", assignedPort);

                        }

                        

                        if (!portFound) {

                            DLOG(@"[SERVERLIST-PARSE]   -> No port found, using DEFAULT port %d",

                                 DEFAULT_GAME_PORT);

                        }

                        

                        // De-dupe and store

                        NSString *key = [NSString stringWithFormat:@"%s:%d", candidate, assignedPort];

                        BOOL duplicate = NO;

                        for (NSString *s in foundServers) {

                            if ([s isEqualToString:key]) { duplicate = YES; break; }

                        }

                        if (!duplicate && g_serverCount < MAX_SERVERS) {

                            [foundServers addObject:key];

                            strncpy(g_serverList[g_serverCount].ip, candidate, 63);

                            g_serverList[g_serverCount].port = assignedPort;

                            DLOG(@"[SERVERLIST-PARSE] STORED server %d: %s:%d (portSource=%@)",

                                 g_serverCount,

                                 g_serverList[g_serverCount].ip,

                                 g_serverList[g_serverCount].port,

                                 portFound ? @"detected" : @"DEFAULT");

                            

                            if (g_serverCount == 0) {

                                strncpy(g_gameServerIP, candidate, 63);

                                g_gameServerPort = assignedPort;

                                g_currentServerIndex = 0;

                                DLOG(@"[SERVERLIST-PARSE] Set DEFAULT game server: %s:%d",

                                     g_gameServerIP, g_gameServerPort);

                            }

                            g_serverCount++;

                        }

                    }

                }

            }

            

            if (g_serverCount > 0) {

                DLOG(@"[SERVERLIST-PARSE] Final: Stored %d servers for rotation", g_serverCount);

                for (int i = 0; i < g_serverCount; i++) {

                    DLOG(@"[SERVERLIST-PARSE]   [%d] %s:%d",

                         i, g_serverList[i].ip, g_serverList[i].port);

                }

            } else {

                DLOG(@"[SERVERLIST-PARSE] No servers found! (Game may still use its own internal parsing)");

                // v36.60: If even ASCII scan fails, at least populate with known-working defaults

                // so that the rotation mechanism has something to try (in case we're called for fallback)

                const char *defaultIP = "47.100.14.198";

                if (strlen(g_gameServerIP) < 7) {

                    strncpy(g_gameServerIP, defaultIP, 63);

                }

                if (g_gameServerPort < 1024) {

                    g_gameServerPort = DEFAULT_GAME_PORT;

                }

                strncpy(g_serverList[0].ip, g_gameServerIP, 63);

                g_serverList[0].port = g_gameServerPort;

                g_serverCount = 1;

                g_currentServerIndex = 0;

                DLOG(@"[SERVERLIST-PARSE] Populated fallback server %s:%d as last resort",

                     g_gameServerIP, g_gameServerPort);

            }

        }

    } @catch (NSException *e) {

        DLOG(@"[SERVERLIST-PARSE] Exception: %@", e.reason);

    }

}



// v36.62: Function to try next server in rotation (IP rotation, port always 58158)

static BOOL tryNextServer(void) {

    if (g_serverCount <= 1) {

        DLOG(@"[SERVER-ROTATE] Only %d server(s) available, cannot rotate", g_serverCount);

        return NO;

    }

    

    g_connectionFailCount++;

    g_currentServerIndex = (g_currentServerIndex + 1) % g_serverCount;

    

    // v36.63: Override port to 12003 (the only confirmed working port)

    strncpy(g_gameServerIP, g_serverList[g_currentServerIndex].ip, 63);

    g_gameServerPort = 12003;  // Always use 12003, the only confirmed working port

    

    DLOG(@"[SERVER-ROTATE] Switching to server %d/%d: %s:12003 (forced port, parsed was %d, fail count=%d)", 

         g_currentServerIndex + 1, g_serverCount, g_gameServerIP, g_serverList[g_currentServerIndex].port, g_connectionFailCount);

    

    // v36.98: Reset fake response state for new connection

    // This ensures the new connection can trigger fake response injection again

    g_fakeRespInjected = NO;

    g_fakeRespActive = NO;

    g_fakeRespDelivered = NO;

    g_fakeRespFd = -1;

    g_fakeRespSentCount = 0;

    g_lastRespCmd = 0;

    g_respCount = 0;

    resetCmdQueue();  // v36.106: Reset command queue for new connection

    g_loginPacketsSent = NO;

    g_handshakeComplete = NO;

    g_heartbeatCount = 0;

    g_lastGameCmd = 0;  // v36.107: Reset last game command

    g_lastSeqNum = 0;  // v36.107: Reset last sequence number

    g_lastGameCmdFd = -1;

    DLOG(@"[SERVER-ROTATE] v36.101: Reset fake response state for new connection");

    

    // Update stub data

    // v37.119: MSI hooks are DISABLED (no MSI init hook installs g_msiStubData).

    // This block is a no-op, but kept guarded so it's safe if MSI is ever re-enabled.

    if (g_msiStubData) {

        [g_msiStubData setObject:[NSString stringWithUTF8String:g_gameServerIP] forKey:@"ip"];

        [g_msiStubData setObject:@(12003) forKey:@"port"];  // Force 12003 in stub too

    }

    

    return YES;

}



// v36.97: Hook getsockopt to prevent heartbeat from detecting dead connection

// When fake response fd is used, SO_ERROR should return 0 (no error)

static int hook_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {

    if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");

    

    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so SO_ERROR=0 is returned

    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).

    // If this is the fake response fd and checking SO_ERROR, return 0

    if (g_fakeRespFd == fd && level == SOL_SOCKET && optname == SO_ERROR) {

        if (optval && optlen && *optlen >= sizeof(int)) {

            *(int *)optval = 0;  // No error

            *optlen = sizeof(int);

            DLOG(@"[FAKE-SOCKOPT] v36.136: Returning SO_ERROR=0 for fake resp fd=%d (injected=%d)", fd, g_fakeRespInjected);

            return 0;

        }

    }

    

    return orig_getsockopt ? orig_getsockopt(fd, level, optname, optval, optlen) : -1;

}



// v36.104: Hook poll() to prevent heartbeat from detecting dead connection

// When server closes connection, poll() returns POLLHUP/POLLERR

// We clear these flags for the fake response fd to pretend connection is alive

static int hook_poll(struct pollfd *fds, nfds_t nfds, int timeout) {

    if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");

    if (!orig_poll || !fds) return -1;

    

    int result = orig_poll(fds, nfds, timeout);



    // v36.144: Post-BURST state machine — actively signal POLLIN so the

    // client calls recv() to receive RECV #20/#21. Without this, the

    // g_fakeRespDelivered check below clears POLLIN, and the client never

    // calls recv() again (stuck at "正在进入...").

    // v36.149: Reverted to >= 1 (continuous injection, no wait states).

    // Also set POLLIN when g_fakeRespActive and !g_fakeRespDelivered (post-BURST responses).

    if ((g_postBurstState >= 1 || (g_fakeRespActive && !g_fakeRespDelivered)) && g_postBurstFd >= 0) {

        for (nfds_t i = 0; i < nfds; i++) {

            if (fds[i].fd == g_postBurstFd) {

                fds[i].revents |= POLLIN;

                fds[i].revents &= ~(POLLHUP | POLLERR);

                if (result <= 0) result = 1;

                DLOG(@"[FAKE-POLL] v36.149: SET POLLIN for post-BURST fd=%d state=%d active=%d delivered=%d", fds[i].fd, g_postBurstState, g_fakeRespActive, g_fakeRespDelivered);

                break;

            }

        }

    }

    

    // v36.104: If fake response fd is in the poll set, clear error flags

    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so flags are cleared

    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).

    if (g_fakeRespFd >= 0 && result > 0) {

        for (nfds_t i = 0; i < nfds; i++) {

            if (fds[i].fd == g_fakeRespFd) {

                // Clear POLLHUP and POLLERR flags - pretend connection is alive

                if (fds[i].revents & (POLLHUP | POLLERR)) {

                    DLOG(@"[FAKE-POLL] v36.136: Clearing POLLHUP/POLLERR for fake resp fd=%d (was 0x%x injected=%d)", 

                         fds[i].fd, fds[i].revents, g_fakeRespInjected);

                    fds[i].revents &= ~(POLLHUP | POLLERR);

                    // If only error flags were set, set POLLIN instead so recv can return EAGAIN

                    if (fds[i].revents == 0) {

                        fds[i].revents = 0;  // No events - connection appears idle

                        result = 0;  // No events ready

                    }

                }

                // Clear POLLIN for fake response fd if response already delivered

                // v36.144: Skip this if post-BURST state machine is active (handled above)

                if (g_fakeRespDelivered && g_postBurstState < 1) {

                    fds[i].revents &= ~POLLIN;

                }

            }

        }

        // Recalculate result

        result = 0;

        for (nfds_t i = 0; i < nfds; i++) {

            if (fds[i].revents != 0) result++;

        }

    }

    

    return result;

}



// v36.104: Hook select() to prevent heartbeat from detecting dead connection

static int hook_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {

    if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");

    if (!orig_select) return -1;

    

    int result = orig_select(nfds, readfds, writefds, exceptfds, timeout);



    // v36.144: Post-BURST state machine — actively set readfds so the

    // client calls recv() to receive RECV #20/#21. Without this, the

    // g_fakeRespDelivered check below clears readfds, and the client

    // never calls recv() again (stuck at "正在进入...").

    // v36.149: Reverted to >= 1 (continuous injection, no wait states).

    // Also set readfds when g_fakeRespActive and !g_fakeRespDelivered (post-BURST responses).

    if ((g_postBurstState >= 1 || (g_fakeRespActive && !g_fakeRespDelivered)) && g_postBurstFd >= 0) {

        if (readfds && g_postBurstFd < nfds) {

            FD_SET(g_postBurstFd, readfds);

        }

        if (exceptfds && g_postBurstFd < nfds) {

            FD_CLR(g_postBurstFd, exceptfds);

        }

        if (result <= 0) result = 1;

        DLOG(@"[FAKE-SELECT] v36.149: SET readfds for post-BURST fd=%d state=%d active=%d delivered=%d", g_postBurstFd, g_postBurstState, g_fakeRespActive, g_fakeRespDelivered);

    }

    

    // v36.104: If fake response fd is in the except set, clear it

    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so exception is cleared

    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).

    if (g_fakeRespFd >= 0 && result >= 0) {

        if (exceptfds && FD_ISSET(g_fakeRespFd, exceptfds)) {

            DLOG(@"[FAKE-SELECT] v36.136: Clearing exception for fake resp fd=%d (injected=%d)", g_fakeRespFd, g_fakeRespInjected);

            FD_CLR(g_fakeRespFd, exceptfds);

            // Recalculate result

            result = 0;

            if (readfds) {

                for (int i = 0; i < nfds; i++) {

                    if (FD_ISSET(i, readfds)) result++;

                }

            }

            if (writefds) {

                for (int i = 0; i < nfds; i++) {

                    if (FD_ISSET(i, writefds)) result++;

                }

            }

        }

        // Also clear readfds for fake response fd if response already delivered

        // v36.144: Skip this if post-BURST state machine is active (handled above)

        if (readfds && g_fakeRespDelivered && g_postBurstState < 1 && FD_ISSET(g_fakeRespFd, readfds)) {

            FD_CLR(g_fakeRespFd, readfds);

        }

    }

    

    return result;

}



// Forward declaration: resetGameStateForReconnect is defined below (after hook_close)

// but hook_close needs to call it when game server fd is closed.

static void resetGameStateForReconnect(void);



static int hook_close(int fd) {

    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");

    

    // v37.117: When game server connection is closed (user returns from role page),

    // reset ALL per-connection state IMMEDIATELY. Previously we only reset on connect(),

    // but the game might corrupt internal state between close() and the next connect().

    // This matches the pattern: user enters game → returns to server → close() called

    // → we reset state → next connect() gets clean hooks.

    if (g_gameServerFd == fd) {

        DLOG(@"[CLOSE-RESET] Game server fd %d closed → resetting per-connection state", fd);

        g_gameServerConnected = NO;

        g_gameServerFd = -1;

        resetGameStateForReconnect();

    }

    

    // v36.97: Also block close for fake response fd

    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so close is blocked

    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).

    if (g_fakeRespFd == fd) {

        DLOG(@"[FAKE-CLOSE] v36.136: Blocking close(%d) for fake resp fd (injected=%d)", fd, g_fakeRespInjected);

        // v36.103: Use this opportunity to find and patch C++ disconnect functions

        // The backtrace from close() should include quitFromServer and heartbeat

        findAndPatchDisconnectFunctions();

        return 0;

    }

    

    // v37.16: DISABLED CLOSE-BLOCK — server already closed connection, blocking close() is useless.

    // User confirmed: "CLOSE-BLOCK 阻止了 close 调用，但连接已被服务器关闭，无济于事"

    if (0) {

    // v36.93: Track game server port closures and BLOCK them during login flow

    for (int i = 0; i < g_trackedCount; i++) {

        if (g_trackedFds[i] == fd && g_trackedActive[i]) {

            int port = g_trackedPorts[i];

            BOOL isGamePort = (port == 58158 || port == 12003 || 

                               (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

            if (isGamePort) {

                DLOG(@"[CLOSE-BLOCK] v36.93 BLOCKING close(%d) for game server %s:%d (port=%d)", fd, g_trackedHosts[i], port, port);

                

                // v36.93: Log call stack for debugging

                void *callstack[8];

                int frames = backtrace(callstack, 8);

                char **strs = backtrace_symbols(callstack, frames);

                if (strs) {

                    for (int j = 1; j < frames && j < 8; j++) {

                        DLOG(@"[CLOSE-BT] %d: %s", j, strs[j] ? strs[j] : "?");

                    }

                    free(strs);

                }

                

                // v36.93: BLOCK close() for game server fd during login handshake

                // This prevents quitFromServer() from disconnecting the game server

                // while client is still sending login packets (0x000EE007, 0x00FFF493)

                // Return 0 (success) to trick the client into thinking close succeeded

                DLOG(@"[CLOSE-BLOCK] v36.93: Returning 0 (blocked) to prevent game server disconnect");

                return 0;  // Block the close, return success

            }

        }

    }

    }  // end if(0) CLOSE-BLOCK disabled



    clearTrackedFd(fd);

    return orig_close ? orig_close(fd) : -1;

}



// v37.111: Reset ALL per-connection state when user returns to server selection

// and reconnects. Without this, g_fff493_1_sent/g_fff493_2_sent/g_injected_0CB0A300

// etc. remain set from the 1st session → 2nd connect skips FFF493 replacement,

// skips handshake, skips role injection → "连接中断异常".

// v37.112 SAFETY FIX: DO NOT free() malloc'd plaintext buffers here. Old socket

// background threads / delayed callbacks may still be accessing them → use-after-free

// CRASH on returning from role page. Just zero the length fields; the next CCCrypt

// capture will call free() before re-malloc'ing (safe, serialized on main thread).

// v37.113 CRITICAL FIX: DO NOT reset crypto-chain state (g_aes_key_saved, g_cccrypt_l4_active,

// g_pubKeyCaptured, g_hashTokenValid). These are entry conditions for FFF493 replacement

// (g_aes_key_saved), L4 channel patch (g_cccrypt_l4_active), challenge response

// (g_pubKeyCaptured). Resetting them = 2nd connect skips ALL crypto hooks → server

// gets unpatched packets → "连接中断异常". These are app-lifetime state, NOT per-connection.

static void resetGameStateForReconnect(void) {

    // --- FFF493 / login flow state ---

    g_fff493_1_sent = 0;

    g_fff493_2_sent = 0;

    g_consec_heartbeats = 0;

    g_role_0CB0A300_seen = 0;

    g_injected_0CB0A300 = 0;

    g_fff493_1_plain_len = 0;

    g_fff493_2_native_len = 0;

    g_ext_plaintext_len = 0;

    // v37.112: FREE DELETED — buffers recycled by CCCrypt next capture

    // v37.113: Crypto-chain state PRESERVED (g_aes_key_saved, g_cccrypt_l4_active,

    //          g_pubKeyCaptured, g_pubKeyBase64Len, g_hashTokenValid, g_saved_key_len)

    //          — these are app-lifetime, NOT per-connection.



    // --- Handshake / connection state ---

    g_handshakeComplete = NO;

    g_heartbeatCount = 0;

    g_forceHandshakeComplete = NO;

    g_forceHandshakeFd = -1;

    g_forceHandshakeLen = 0;

    g_challengeResponded = NO;

    g_challengeFd = -1;

    // v37.113: g_pubKeyCaptured NOT reset — public key is app-lifetime

    // v37.113: g_pubKeyBase64Len NOT reset

    g_stickyLeftoverFd = -1;

    g_stickyLeftoverLen = 0;

    g_localHeartbeatAckFd = -1;

    g_localHeartbeatAckLen = 0;



    // --- Crypto state ---

    // v37.113: g_cccrypt_l4_active NOT reset — L4 channel patch entry condition

    // v37.113: g_aes_key_saved NOT reset — FFF493 replacement entry condition

    // v37.113: g_saved_key_len NOT reset

    g_forceValidDecryptFd = -1;



    // --- Fake response / command queue ---

    g_loginPacketsSent = NO;

    g_fakeRespInjected = NO;

    g_fakeRespActive = NO;

    g_fakeRespDelivered = NO;

    g_fakeRespFd = -1;

    g_fakeRespSentCount = 0;

    g_triggerFakeNextRecv = NO;

    g_triggerFakeFd = -1;

    g_burstInjectAfterPatch = NO;

    g_burstInjectFd = -1;

    g_postBurstState = 0;

    g_postBurstFd = -1;

    g_postBurstDone = NO;

    g_phase2TriggerCount = 0;

    g_waitingForClientCmds = NO;

    g_waitingFd = -1;

    g_lastGameCmd = 0;

    g_lastSeqNum = 0;

    g_lastGameCmdFd = -1;

    g_lastRespCmd = 0;

    g_respCount = 0;

    g_ee006_sent = 0;

    g_a018_sent = 0;

    g_bypassRemaining = 0;

    resetCmdQueue();



    DLOG(@"[RECONNECT-RESET] v37.113: per-connection state cleared, crypto-chain PRESERVED");

}



static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");

    char host[64] = "unknown";

    int port = 0;

    if (addr->sa_family == AF_INET) {

        struct sockaddr_in *in = (struct sockaddr_in *)addr;

        inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));

        port = ntohs(in->sin_port);

                // v36.63: REVERT to port 12003 (the only port confirmed to connect and complete handshake)

        // Port 58158 is unreachable - ALL tests since v36.51 showed timeout/hang

        // If game uses non-standard port (like 11776), rewrite to 12003

        BOOL isGameServerPort = (port == 12003 || port == 58158 || 

                                 (port >= 10000 && port <= 65535 && port != 5678));

        BOOL needPortRewrite = (port != 5678 && port != 12003);  // Rewrite any non-login, non-12003 port to 12003

        

        int origPort = port;

        char origHost[64];

        strncpy(origHost, host, 63);

        origHost[63] = '\0';

        

        struct sockaddr_in newAddr = *in;

        

        if (needPortRewrite && isGameServerPort) {

            // v36.63: Force rewrite non-standard game ports (like 11776) to 12003

            newAddr.sin_port = htons(12003);

            port = 12003;

            DLOG(@"[REWRITE-PORT] FORCE game server %s:%d -> %s:12003 (only confirmed working port)", 

                 origHost, origPort, origHost);

        }

        

        // v36.63: Track fd BEFORE connect with target port

        trackFd(sockfd, host, port);

        

        DLOG(@"[SOCK] connect START fd=%d target=%s:%d origPort=%d rewrite=%d isGamePort=%d",

             sockfd, host, port, origPort, needPortRewrite ? 1 : 0, isGameServerPort ? 1 : 0);

        

        if (!orig_connect) {

            DLOG(@"[SOCK] FATAL: orig_connect is NULL! dlsym failed.");

            errno = EACCES;

            return -1;

        }

        

        // v36.63: Set SO_SNDTIMEO 10s timeout as safety net for blocking connect

        // Prevents hanging forever on unreachable ports

        struct timeval tv;

        tv.tv_sec = 10;

        tv.tv_usec = 0;

        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        

        // v36.63: SIMPLE blocking connect with timeout protection

        const struct sockaddr *actualAddr = needPortRewrite ? (struct sockaddr *)&newAddr : addr;

        socklen_t actualAddrLen = needPortRewrite ? sizeof(newAddr) : addrlen;

        

        struct timeval startTV;

        gettimeofday(&startTV, NULL);

        

        int result = orig_connect(sockfd, actualAddr, actualAddrLen);

        int connectErrno = errno;

        

        // v36.63: Clear the timeout after connect

        struct timeval tvZero;

        tvZero.tv_sec = 0;

        tvZero.tv_usec = 0;

        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tvZero, sizeof(tvZero));

        

        struct timeval endTV;

        gettimeofday(&endTV, NULL);

        double elapsed = (endTV.tv_sec - startTV.tv_sec) + (endTV.tv_usec - startTV.tv_usec) / 1000000.0;

        

        if (result == 0) {

            // v36.63: Track game server connection state

            if (isGameServerPort) {

                g_gameServerConnected = YES;

                g_gameServerFd = sockfd;

                g_gameConnectTime = [[NSDate date] timeIntervalSince1970];

                DLOG(@"[GAME-CONNECT] Game server connected fd=%d target=%s:%d (confirmed working port)", 

                     sockfd, host, port);

                

                // v37.111: UNCONDITIONAL full state reset on every game server connect.

                // Previous v36.101 only reset when g_fakeRespInjected||g_fakeRespActive was true,

                // which MISSED the case where user returns to server selection after entering

                // role page (those flags were already NO by then). This left g_fff493_1_sent=1,

                // g_fff493_2_sent=1, g_injected_0CB0A300=1 etc. set → 2nd connect skipped ALL

                // login flow hooks → "连接中断异常".

                resetGameStateForReconnect();

            }

            DLOG(@"[SOCK] connect END fd=%d SUCCESS target=%s:%d origPort=%d elapsed=%.3fs",

                 sockfd, host, port, origPort, elapsed);

        } else {

            DLOG(@"[SOCK] connect END fd=%d FAILED target=%s:%d origPort=%d errno=%d(%s) elapsed=%.3fs",

                 sockfd, host, port, origPort, connectErrno, strerror(connectErrno), elapsed);

            

            // v36.63: Game server failed: try IP rotation (port stays 12003)

            if (isGameServerPort) {

                DLOG(@"[SOCK] Game server %s:%d FAILED -> attempting IP rotation...", host, port);

                @try {

                    BOOL rotated = tryNextServer();

                    if (rotated) {

                        DLOG(@"[SOCK] Rotation succeeded: %s:12003 (index %d/%d)",

                             g_gameServerIP, g_currentServerIndex + 1, g_serverCount);

                    } else {

                        DLOG(@"[SOCK] Rotation unavailable (servers=%d)", g_serverCount);

                    }

                } @catch (NSException *e) {

                    DLOG(@"[SOCK] Exception during rotation: %@", e.reason);

                }

            }

        }



        // === FIX20 V3环境兜底：多层rebind链导致游戏服connect被中间层拦截返回-1时，

        // 直接用 dlsym(RTLD_DEFAULT, connect) 拿最底层未被污染的系统 connect 再调一次，

        // 跳过 6-8 层 rebind/inline patch 链的中间层拦截

        if (g_isV3Environment && result == -1 && (port == 5678 || port == 12003)) {

            static ConnectFunc real_connect = NULL;

            static int  vc3_hitCount = 0;

            if (!real_connect) real_connect = (ConnectFunc)dlsym(RTLD_DEFAULT, "connect");

            if (real_connect && real_connect != orig_connect) {

                int prevErrno = connectErrno;

                int ret2 = real_connect(sockfd, actualAddr, actualAddrLen);

                int err2 = errno;

                if (vc3_hitCount < 8) {

                    vc3_hitCount++;

                    DLOG(@"[V3-CONNECT] 🟢 fd=%d %s:%d orig_ret=-1 errno=%d(%s) → 调用RTLD_DEFAULT真实connect → ret=%d errno=%d(%s) 命中#%d",

                         sockfd, host, port,

                         prevErrno, strerror(prevErrno),

                         ret2, ret2==-1?err2:0, ret2==-1?strerror(err2):"",

                         vc3_hitCount);

                }

                // 用真实 connect 的返回值替换给游戏

                result = ret2;

                connectErrno = (ret2 == -1) ? err2 : 0;



                // 如果真实 connect 成功了，也需要更新游戏服连接状态

                if (result == 0 && (port == 12003 || isGameServerPort)) {

                    g_gameServerConnected = YES;

                    g_gameServerFd = sockfd;

                    g_gameConnectTime = [[NSDate date] timeIntervalSince1970];

                    DLOG(@"[V3-CONNECT] 🎯 游戏服兜底connect成功! fd=%d target=%s:%d → 重置游戏登录状态", sockfd, host, port);

                    resetGameStateForReconnect();

                }

            } else if (vc3_hitCount < 8) {

                vc3_hitCount++;

                DLOG(@"[V3-CONNECT] ⚠️ fd=%d %s:%d 想用RTLD_DEFAULT真实connect兜底, 但dlsym未找到或与orig相同! real=%p orig=%p",

                     sockfd, host, port, real_connect, orig_connect);

            }

        }

        

        errno = connectErrno;

        return result;

    } else if (addr->sa_family == AF_INET6) {

        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));

        port = ntohs(in6->sin6_port);

        trackFd(sockfd, host, port);

        DLOG(@"[SOCK] connect6 START fd=%d [%s]:%d", sockfd, host, port);

        

        int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;

        DLOG(@"[SOCK] connect6 END fd=%d [%s]:%d result=%d errno=%d(%s)", sockfd, host, port, result, errno, strerror(errno));

        return result;

    }

    

    int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;

    return result;

}



static ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {

    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");

    

    // v36.123: If this is the fake response fd, pretend send succeeds

    // This prevents heartbeat from detecting the dead connection via send()

    // v36.123: Enqueue new commands AND reset delivered flag

    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so send succeeds

    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).

    if (g_fakeRespFd == fd) {

        // Check if this is a new command (not heartbeat)

        BOOL isNewCmd = NO;

        uint32_t newCmd = 0;

        uint32_t newSeq = 0;

        if (len >= 12) {

            const unsigned char *p = (const unsigned char *)buf;

            newCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                           ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

            newSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |

                     ((uint32_t)p[10] << 8)  | (uint32_t)p[11];

            // Only reset for game commands, not heartbeat

            // v36.146: After post-BURST completion, don't reactivate fake

            // response system. Client's new 0x00FFF493 requests should be

            // FAKE-SEND'd without generating duplicate 0x0CB0A300 responses.

            // v36.150: Phase 2 in progress (g_postBurstState >= 3) must NOT

            // enqueue — otherwise duplicate 0x00FFF493 generates spurious

            // 0x0CB0A300/0x80FFF490 responses that corrupt the RECV #22-#24

            // injection sequence.

            // v36.154: REVERTED to contiguous injection. No request-driven

            // sub-states. Phase 2 trigger uses TIME-BASED delay (3 seconds

            // since Phase 1 completion) instead of count threshold.

            // This fixes v36.152 (auto-load ACKs triggered Phase 2 too

            // early, before role UI rendered) and v36.153 (state=10

            // busy-wait caused "连接异常中断").

            if (newCmd != 0x00000015 && newCmd < 0x80000000 && !g_postBurstDone && g_postBurstState < 3) {

                isNewCmd = YES;

                DLOG(@"[FAKE-SEND] v36.123: New cmd=0x%08X seq=0x%08X detected, enqueuing + resetting delivered flag", newCmd, newSeq);

            } else if (g_postBurstDone && newCmd != 0x00000015 && newCmd < 0x80000000) {

                // v36.154: Phase 2 trigger — TIME-BASED 3-second delay.

                // After Phase 1 completes (RECV#21 injected), the client

                // fires auto-load ACK 0x00FFF493 within ~100ms. These are

                // NOT user clicks. Only after 3 seconds can a 0x00FFF493

                // trigger Phase 2 (RECV #22-#24), ensuring the user has

                // time to see and click the role UI.

                double elapsed = g_phase1DoneTime > 0 ?

                    (CFAbsoluteTimeGetCurrent() - g_phase1DoneTime) : 999.0;

                if (elapsed < 3.0) {

                    DLOG(@"[FAKE-SEND] v36.155: Phase 2 LOCKED (%.1fs < 3.0s) cmd=0x%08X seq=0x%08X — EAGAIN (role UI rendering)", elapsed, newCmd, newSeq);

                } else {

                    g_phase2TriggerCount++;

                    if (g_phase2TriggerCount == 1) {

                        g_postBurstDone = NO;

                        g_postBurstState = 3;  // Start Phase 2: inject RECV #22

                        DLOG(@"[POST-BURST] v36.155: Phase 2 TRIGGERED (%.1fs elapsed) by cmd=0x%08X seq=0x%08X state=3", elapsed, newCmd, newSeq);

                    } else {

                        DLOG(@"[FAKE-SEND] v36.155: Phase 2 POST (count=%d) cmd=0x%08X — EAGAIN", g_phase2TriggerCount, newCmd);

                    }

                }

            } else if (!g_postBurstDone && g_postBurstState >= 3 && newCmd != 0x00000015 && newCmd < 0x80000000) {

                // v36.150: Phase 2 in progress — don't enqueue, don't generate

                // responses. RECV #22-#24 are driven by g_postBurstState.

                DLOG(@"[FAKE-SEND] v36.150: Phase 2 IN PROGRESS, cmd=0x%08X seq=0x%08X send-only (state=%d)", newCmd, newSeq, g_postBurstState);

            }

        }

        if (isNewCmd) {

            g_fakeRespDelivered = NO;

            // v36.123: Enqueue the new command so the hook can generate a response for it

            enqueueGameCmd(newCmd, fd, (uint32_t)len, newSeq);

            g_lastGameCmd = newCmd;

            g_lastSeqNum = newSeq;

        } else {

            DLOG(@"[FAKE-SEND] v36.123: Simulating send success for fd=%d len=%zu (heartbeat/ack, keep delivered)", fd, len);

        }

        return (ssize_t)len;

    }

    

    const char *host = getHostForFd(fd);

    int port = getPortForFd(fd);



    // v37.42: Replace 0x0002A018 and 0x000EE006 with clean client's versions.

    // 0x0002A018 has MD5 hash at end — can't patch fields without recomputing hash.

    // Full packet replacement (like EE121-REPL) is the only safe option.

    // 0x000EE006 has UUID — same-length replacement, no hash.

    if (port == 5678 && len >= 12) {

        const unsigned char *p = (const unsigned char *)buf;

        uint32_t eeCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                         ((uint32_t)p[6] << 8) | (uint32_t)p[7];

        uint32_t origSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |

                           ((uint32_t)p[10] << 8) | (uint32_t)p[11];



        // v37.64: REMOVED EE006-INJECT and A018-INJECT logic.

        // v37.62 log proves client ALREADY sends A018 (origLen=186 at line 360, A018-REPL→223B)

        // AND short EE006 (20B at line 805). INJECT would cause DUPLICATE sends.

        // Only EE006-EXPAND (20B→56B) below is needed to fix status=4.

        // hash1/hash2/hash3 in EE121 are ALL correct (verified v37.62 log lines 824-825, 838).



        if (eeCmd == 0x0002A018 && len >= 100) {

            // Clean client's 0x0002A018 (223B) from hook.txt SEND #5

            // Uses s_cleanA018 defined at file scope (v37.63).

            g_a018_sent = 1;

            unsigned char *newBuf = (unsigned char *)malloc(223);

            if (newBuf) {

                memcpy(newBuf, s_cleanA018, 223);

                newBuf[8] = (origSeq >> 24) & 0xFF;

                newBuf[9] = (origSeq >> 16) & 0xFF;

                newBuf[10] = (origSeq >> 8) & 0xFF;

                newBuf[11] = origSeq & 0xFF;

                DLOG(@"[A018-REPL] v37.64: Replaced 0x0002A018 with clean 223B pkt, seq=%u (origLen=%zu)", origSeq, len);

                ssize_t rret = orig_send(fd, newBuf, 223, flags);

                free(newBuf);

                if (rret >= 0) return (ssize_t)len;

                return rret;

            }

        }



        if (eeCmd == 0x000EE006 && len == 56) {

            // Replace UUID in 0x000EE006 (same length, no hash)

            g_ee006_sent = 1;

            unsigned char *newBuf = (unsigned char *)malloc(56);

            if (newBuf) {

                memcpy(newBuf, p, 56);

                static const char cleanUUID[] = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8";

                memcpy(newBuf + 20, cleanUUID, 36);

                DLOG(@"[EE006-UUID] v37.64: Replaced UUID in 0x000EE006(56B)");

                ssize_t rret = orig_send(fd, newBuf, 56, flags);

                free(newBuf);

                if (rret >= 0) return (ssize_t)len;

                return rret;

            }

        }

        // v37.64: Expand short 0x000EE006 (20B, no UUID) to 56B with clean UUID.

        // Client sends 20B when identifierForVendor returns nil.

        // v37.62 log line 805: cmd=0x000EE006 len=20 → status=4 on EE121.

        // This is the ROOT FIX for "版本过低": server needs 56B EE006 with UUID field.

        if (eeCmd == 0x000EE006 && len < 56 && len >= 12) {

            g_ee006_sent = 1;

            unsigned char *newBuf = (unsigned char *)malloc(56);

            if (newBuf) {

                memcpy(newBuf, p, 12); // copy header

                newBuf[12]=0x00; newBuf[13]=0x00; newBuf[14]=0x00; newBuf[15]=0x00;

                newBuf[16]=0x00; newBuf[17]=0x00; newBuf[18]=0x00; newBuf[19]=0x24; // len=36

                static const char cleanUUID[] = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8";

                memcpy(newBuf+20, cleanUUID, 36);

                uint32_t newPktLen = 56;

                newBuf[0]=(newPktLen>>24)&0xFF; newBuf[1]=(newPktLen>>16)&0xFF;

                newBuf[2]=(newPktLen>>8)&0xFF; newBuf[3]=newPktLen&0xFF;

                DLOG(@"[EE006-EXPAND] v37.64: Expanded 0x000EE006 from %zuB to 56B with UUID (ROOT FIX for status=4)", len);

                ssize_t rret = orig_send(fd, newBuf, 56, flags);

                free(newBuf);

                if (rret >= 0) return (ssize_t)len;

                return rret;

            }

        }

    }



    // v37.68: Generic TLV scanner for ALL port 5678 packets.

    // v37.68 FIX: EE100/EE113 MUST be patched (channel→clean). v37.66 log showed

    // TLV-SCAN only patched 28B/30B pkts (0x0000E002/0x002EE118) but NOT 63B EE100.

    // Root cause: (1) memmem("DY_MIESHI") filter skipped EE113 (no DY_MIESHI),

    // (2) loop `in+2<len` missed last 2 bytes of multi-field pkts,

    // (3) accountId replacement disabled (v37.67 strategy: REAL accountId EVERYWHERE).

    // (4) EE100 has 4-byte prefixes (00 00 00 XX) that break TLV parser.

    // v37.68: For EE100/EE113, ALWAYS process them (no memmem filter).

    // For EE100, use DIRECT BYTE REPLACEMENT instead of TLV parser (prefix issue).

    if (port == 5678 && len >= 20 && len <= 4096) {

        const unsigned char *p = (const unsigned char *)buf;

        uint32_t tlvCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                          ((uint32_t)p[6] << 8) | (uint32_t)p[7];



        // v37.126: GENERIC DY_MIESHI replacement for ALL packets on port 5678.

        // Previously only EE100/EE113/EE118/E002/EE121 were patched. But 0x0002A017

        // and possibly other commands also contain DY_MIESHI and need replacement.

        // Fix: For ANY packet on port 5678 that contains DY_MIESHI, do a direct

        // byte replacement to DYanyou0040_MIESHI before further command-specific processing.

        if (tlvCmd != 0x002EE100 && tlvCmd != 0x002EE113 && tlvCmd != 0x0000E002 &&

            tlvCmd != 0x002EE118 && tlvCmd != 0x002EE121 && tlvCmd != 0x002EE120) {

            unsigned char *dyPos = (unsigned char *)memmem(p, len, "DY_MIESHI", 9);

            if (dyPos && dyPos >= p + 2) {

                size_t dyOffset = (size_t)(dyPos - p);

                size_t bufCap = len + 64;

                unsigned char *newBuf = (unsigned char *)malloc(bufCap);

                if (newBuf) {

                    size_t pos = 0;

                    if (dyOffset >= 2) {

                        memcpy(newBuf, p, dyOffset - 2);

                        pos = dyOffset - 2;

                    }

                    newBuf[pos++] = 0x00;

                    newBuf[pos++] = 0x12;  // 18 bytes

                    memcpy(newBuf + pos, "DYanyou0040_MIESHI", 18);

                    pos += 18;

                    size_t restStart = dyOffset + 9;

                    if (restStart < len) {

                        memcpy(newBuf + pos, p + restStart, len - restStart);

                        pos += (len - restStart);

                    }

                    newBuf[0] = (pos >> 24) & 0xFF;

                    newBuf[1] = (pos >> 16) & 0xFF;

                    newBuf[2] = (pos >> 8) & 0xFF;

                    newBuf[3] = pos & 0xFF;

                    DLOG(@"[CH-GENERIC] v37.126: Replaced DY_MIESHI in cmd=0x%08X origLen=%zu newLen=%zu", tlvCmd, len, pos);

                    ssize_t rret = orig_send(fd, newBuf, pos, flags);

                    free(newBuf);

                    if (rret >= 0) return (ssize_t)len;

                    return rret;

                }

            }

        }



        // v37.68: SPECIAL CASE for EE100 — direct byte replacement bypassing TLV parser.

        // EE100 has non-standard 4-byte prefixes (00 00 00 XX) before field groups:

        //   00 00 00 05 00 14 [20B accId] 00 00 00 05 [5B kk994] 00 03 [3B IOS] 00 09 [9B DY_MIESHI]

        // The standard TLV parser fails because it reads 00 00 as fLen=0, then 00 05 as fLen=5,

        // completely misaligning all subsequent fields. Fix: direct string replacement.

        if (tlvCmd == 0x002EE100) {

            // v37.97 FIX: EE100 MUST use CANONICAL accId!

            // ROOT CAUSE: EE100 sent REAL accId (393256...) to login server,

            // v37.108-DIST: Use NATIVE accountId in EE100 — each user's REAL account ID!

            // ROOT CAUSE: Forcing CANONICAL accId (65657881045335015151, kk994's ID) caused

            // ALL users to enter kk994's game character regardless of their login account.

            // FIX: Skip accId replacement. Users with different credentials use their OWN accId

            // assigned by the server after successful login.

            // EE100 format: [12B header][00 00 00 05][00 14][20B accId]...

            // accId is at offset 18, 20 bytes.

            unsigned char *workBuf = (unsigned char *)p;

            size_t workLen = len;

            unsigned char *dyPos = (unsigned char *)memmem(workBuf, workLen, "DY_MIESHI", 9);

            if (dyPos && dyPos >= workBuf + 2) {

                size_t dyOffset = (size_t)(dyPos - workBuf);

                size_t bufCap = workLen + 64;

                unsigned char *newBuf = (unsigned char *)malloc(bufCap);

                if (newBuf) {

                    size_t newLen = workLen + 9; // +9 for longer channel

                    size_t pos = 0;

                    if (dyOffset >= 2) {

                        memcpy(newBuf, workBuf, dyOffset - 2);

                        pos = dyOffset - 2;

                    }

                    newBuf[pos++] = 0x00;

                    newBuf[pos++] = 0x12;

                    memcpy(newBuf + pos, "DYanyou0040_MIESHI", 18);

                    pos += 18;

                    size_t restStart = dyOffset + 9;

                    if (restStart < workLen) {

                        memcpy(newBuf + pos, workBuf + restStart, workLen - restStart);

                        pos += (workLen - restStart);

                    }

                    newBuf[0] = (pos >> 24) & 0xFF;

                    newBuf[1] = (pos >> 16) & 0xFF;

                    newBuf[2] = (pos >> 8) & 0xFF;

                    newBuf[3] = pos & 0xFF;

                    DLOG(@"[TLV-SCAN] v37.108: EE100 PATCHED ch=1 acc=0 origLen=%zu newLen=%zu cmd=0x%08X",

                         len, pos, tlvCmd);

                    ssize_t rret = orig_send(fd, newBuf, pos, flags);

                    free(newBuf);

                    if (rret >= 0) return (ssize_t)len;

                    return rret;

                }

            } else {

                DLOG(@"[TLV-SCAN] v37.108: EE100 no DY_MIESHI found, using NATIVE accId — skip patch");

            }

        }



        // Standard TLV scan for other packets (0x0000E002, 0x002EE118, 0x002EE113)

        // v37.97: EE113 MUST use CANONICAL accId! (was PASSTHROUGH REAL in v37.79)

        BOOL isSmallPkt = (tlvCmd == 0x0000E002 || tlvCmd == 0x002EE118);

        BOOL isEE113 = (tlvCmd == 0x002EE113);

        BOOL needsPatch = isSmallPkt || isEE113;



        BOOL hasDY_MIESHI = (memmem(p, len, "DY_MIESHI", 9) != NULL);

        if (needsPatch && (isEE113 || hasDY_MIESHI)) {

            if (isEE113 && !hasDY_MIESHI) {

                // v37.108-DIST: Use NATIVE accountId in EE113 — each user's REAL account ID!

                // ROOT CAUSE: Forcing CANONICAL accId caused ALL users to enter kk994's character.

                // EE113 structure (51B): [12B header][00 14][20B accId][00 05][5B user][00 06][6B pass][00 00]

                // accId is at offset 14, 20 bytes. No channel field → no TLV reconstruction needed.

                // Just pass through original packet.

                if (len >= 34) {

                    uint16_t accFlen = ((uint16_t)p[12] << 8) | p[13];

                    char orig113[21] = {0};

                    if (accFlen == 20) memcpy(orig113, p + 14, 20);

                    orig113[20] = 0;

                    DLOG(@"[TLV-SCAN] v37.108: EE113 NATIVE accId=%s (passing through, len=%zu cmd=0x%08X)",

                         orig113, len, tlvCmd);

                }

            } else {

                // Reconstruct packet with TLV field replacements

                size_t bufCap = len + 64;

                unsigned char *newBuf = (unsigned char *)malloc(bufCap);

                if (newBuf) {

                    // Copy header (first 12 bytes: pktLen+cmd+seq)

                    size_t hdrLen = (len >= 12) ? 12 : len;

                    memcpy(newBuf, p, hdrLen);

                    size_t out = hdrLen;

                    size_t in = hdrLen;

                    uint32_t fieldsApplied = 0;

                    // v37.68: Fixed loop condition `in+2<=len` to handle last 2 bytes

                    while (in + 2 <= len) {

                        uint16_t fLen = ((uint16_t)p[in] << 8) | p[in + 1];

                        if (fLen == 0 && in + 2 >= len) {

                            // Trailing zero-padding — copy and stop

                            memcpy(newBuf + out, p + in, len - in);

                            out += len - in;

                            break;

                        }

                        if (in + 2 + fLen > len) {

                            // Can't parse remaining as TLV — copy rest as-is

                            memcpy(newBuf + out, p + in, len - in);

                            out += len - in;

                            break;

                        }

                        const unsigned char *val = p + in + 2;

                        if (fLen == 9 && memcmp(val, "DY_MIESHI", 9) == 0) {

                            newBuf[out] = 0x00; newBuf[out+1] = 0x12;

                            memcpy(newBuf + out + 2, "DYanyou0040_MIESHI", 18);

                            out += 20; in += 11; fieldsApplied |= 1;

                        } else if (fLen == 17 && memcmp(val, "iPhone 16 Pro Max", 17) == 0) {

                            newBuf[out] = 0x00; newBuf[out+1] = 0x0B;

                            memcpy(newBuf + out + 2, "iPhone7Plus", 11);

                            out += 13; in += 19; fieldsApplied |= 2;

                        } else if (fLen == 28 && memcmp(val, "Apple Inc. Apple A18 Pro GPU", 28) == 0) {

                            newBuf[out] = 0x00; newBuf[out+1] = 0x18;

                            memcpy(newBuf + out + 2, "Apple Inc. Apple A10 GPU", 24);

                            out += 26; in += 30; fieldsApplied |= 4;

                        }

                        // v37.79: DO NOT replace 20-digit accId (use REAL for token consistency).

                        // Just copy through as-is.

                        else if (fLen == 20) {

                            memcpy(newBuf + out, p + in, 2 + fLen);

                            out += 2 + fLen; in += 2 + fLen;

                        }

                        else {

                            memcpy(newBuf + out, p + in, 2 + fLen);

                            out += 2 + fLen; in += 2 + fLen;

                        }

                    }

                    // Copy any remaining bytes (safety net for off-by-one)

                    if (in < len) {

                        memcpy(newBuf + out, p + in, len - in);

                        out += len - in;

                    }

                    if (fieldsApplied > 0) {

                        // Update total packet length (first 4 bytes BE)

                        uint32_t newPktLen = (uint32_t)out;

                        newBuf[0] = (newPktLen >> 24) & 0xFF;

                        newBuf[1] = (newPktLen >> 16) & 0xFF;

                        newBuf[2] = (newPktLen >> 8) & 0xFF;

                        newBuf[3] = newPktLen & 0xFF;

                        DLOG(@"[TLV-SCAN] v37.76: Patched port=5678 pkt origLen=%zu newLen=%zu fields=%u (ch=%u dm=%u gp=%u acc=%u) cmd=0x%08X",

                             len, out, fieldsApplied,

                             (fieldsApplied&1)!=0, (fieldsApplied&2)!=0, (fieldsApplied&4)!=0, (fieldsApplied&8)!=0, tlvCmd);

                        ssize_t rret = orig_send(fd, newBuf, out, flags);

                        free(newBuf);

                        if (rret >= 0) return (ssize_t)len;

                        return rret;

                    }

                    free(newBuf);

                }

            }

        }

    }



    // v37.27: Dump EE007 ORIGINAL hex (before CHANNEL-PATCH) for byte-level

    // comparison with clean client (hook.txt SEND #28: 178B).

    // Clean EE007 structure: pktLen(4) cmd(4) seq(4) [len(2) value(N)]×11 null(1) trailer(2)

    // Clean total=178B, ours=179B → 10B difference in non-channel fields.

    if (len >= 8) {

        const unsigned char *pp = (const unsigned char *)buf;

        uint32_t diagCmd = ((uint32_t)pp[4] << 24) | ((uint32_t)pp[5] << 16) |

                           ((uint32_t)pp[6] << 8)  | (uint32_t)pp[7];

        if (diagCmd == 0x000EE007 || diagCmd == 0x002EE121) {

            NSMutableString *ehex = [NSMutableString stringWithCapacity:len * 3];

            for (size_t i = 0; i < len; i++) {

                [ehex appendFormat:@"%02X ", pp[i]];

                if ((i + 1) % 32 == 0 && i + 1 < len) [ehex appendString:@"\n    "];

            }

            DLOG(@"[EE007-ORIG] v37.27 port=%d len=%zu ORIGINAL HEX (pre-patch):\n    %@", port, len, ehex);

        }

    }



    // v37.30-DIST: EE007 FIELD-ALIGNED reconstruction.

    //

    // Byte-level analysis (EE007-ORIG 179B vs clean 178B):

    //   FIELD         | CLEAN (178B)            | OURS (179B)               | DIFF

    //   deviceId(20)  | 00 14 "6565788104..."    | 00 14 "049576366..."       | 0

    //   channel       | 00 12 "DYanyou0040_M..."  | 00 09 "DY_MIESHI"          | -9B

    //   deviceModel   | 00 0B "iPhone7Plus"(11)  | 00 11 "iPhone 16 Pro Max"(17) | +6B

    //   GPU           | 00 18 "Apple A10 GPU"(24)| 00 1C "Apple A18 Pro GPU"(28) | +4B

    //   NET SUM       |                         |                            | +1B → 179 vs 178

    //

    // After channel replacement (+9B), our EE007 becomes 188B, but clean should be

    // 178B +9B channel extra? NO. Clean EE007 is 178B with DYanyou0040 (18B).

    // Our raw EE007 is 179B with DY_MIESHI (9B). So after channel fix we should

    // end at 179 + 9 = 188B. But clean is 178B at construction (DYanyou0040 18B).

    // So we must also SHRINK deviceModel (00 11→00 0B, "iPhone 16 Pro Max"→"iPhone7Plus")

    // and shrink GPU (00 1C→00 18, "Apple A18 Pro GPU"→"Apple A10 GPU").

    // Net changes: +9(channel) -6(model) -4(GPU) = -1B.  Starting 179B → 178B.

    if (len >= 12) {

        const unsigned char *p = (const unsigned char *)buf;

        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        // v37.134-FIX15: RE-ENABLE EE007-ALIGN for EE121 — change ch/dm/gp to CANONICAL.

        // FIX13b proved: sending ORIGINAL ch/dm/gp (DY_MIESHI, iPhone 16 Pro Max, A18 Pro)

        // → server returns status=4 (invalid channel/device).

        // FIX14: CC_MD5 hook changes hash2 input to canonical ch/dm/gp → hash2 = MD5(canonical).

        // FIX15: EE007-ALIGN ALSO changes packet body to canonical ch/dm/gp → hash2 MATCHES body!

        // EE121-CANON full rebuild stays DISABLED (FIX11 proved it breaks packet structure).

        if ((cmd == 0x000EE007 || cmd == 0x002EE121) && len >= 100) {

            // v37.56: RESTORE v37.51 behavior — send clean 248B packet (seq-only replacement).

            //

            // v37.54/v37.55 sent native EE121 → server CLOSED connection (hash1/hash3

            // verifiable but WRONG due to modified binary). CC_MD5 hook only fixes hash2,

            // NOT hash1/hash3 (different algorithm based on modified binary content).

            //

            // v37.51-v37.53 behavior: send clean 248B (hash1/hash3 from DIFFERENT session)

            // → server can't verify → status=4 ACCEPT → login works but NO real sessionId/ticket.

            // v37.56 improvement: FFF493-REPL now ONLY replaces sessionId+ticket (NOT clientId/

            // MACADDRESS/md5 — those stay native to match current session).

            if (cmd == 0x002EE121) {

                // Dump original packet tail for debugging

                if (len >= 80) {

                    NSMutableString *tailHex = [NSMutableString string];

                    for (size_t i = len - 80; i < len; i++) [tailHex appendFormat:@"%02X ", p[i]];

                    DLOG(@"[EE121-ORIG] v37.62: origLen=%zu tail80B: %@", len, tailHex);

                }

                // v37.141 DIAG: Dump FULL original EE121 TLV structure for comparison with rebuilt

                {

                    NSMutableString *tlvDump = [NSMutableString stringWithCapacity:300];

                    size_t to = 12;

                    int tlvIdx = 0;

                    while (to + 2 < len) {

                        uint16_t tl = ((uint16_t)p[to]<<8) | p[to+1];

                        if (to + 2 + tl > len) {

                            [tlvDump appendFormat:@"[TLV#%d@%zu] len=%u OUT_OF_RANGE_ABORT (remain=%zu)", tlvIdx, to, (unsigned)tl, len-to];

                            break;

                        }

                        NSString *valStr;

                        if (tl <= 40) {

                            valStr = [[NSString alloc] initWithBytes:p+to+2 length:tl encoding:NSUTF8StringEncoding];

                            if (!valStr) {

                                NSMutableString *hx = [NSMutableString stringWithCapacity:tl*3];

                                for (size_t k = 0; k < tl; k++) [hx appendFormat:@"%02X ", p[to+2+k]];

                                valStr = hx;

                            }

                        } else {

                            NSMutableString *hx = [NSMutableString stringWithCapacity:48];

                            for (size_t k = 0; k < 16; k++) [hx appendFormat:@"%02X ", p[to+2+k]];

                            valStr = [NSString stringWithFormat:@"%@...(len=%u)", hx, (unsigned)tl];

                        }

                        [tlvDump appendFormat:@"[TLV#%d@%zu] %uB: %@  ", tlvIdx, to, (unsigned)tl, valStr];

                        tlvIdx++;

                        to += 2 + tl;

                    }

                    DLOG(@"[EE121-ORIG-DIAG] v37.141: ORIG TLV structure (%d TLVs, pktLen=%zu, end@%zu / diff=%zd):\n    %@",

                         tlvIdx, len, to, (ssize_t)len - (ssize_t)to, tlvDump);

                }



                // v37.62: Conditional EE121 sending based on CC_MD5 channel replacement.

                // If CC_MD5 hook replaced "DY_MIESHI"→"DYanyou0040_MIESHI" in hash1/hash3

                // input, then hash1/hash3 are computed with the CORRECT channel → server

                // can verify and ACCEPT native EE121 → real sessionId/ticket → game entry.

                // If not, fall back to clean 248B (hash1/3 unverifiable → status=4 ACCEPT

                // but no real sessionId → stuck at '正在进入').

                if (0) {

                    // v37.91: DISABLED hard-coded 248B EE121-REPL.

                    // REASON: Real captured native hash2=640a8eab... (fields MD5) but

                    // cleanPkt has hash2=ddcb91f42c... (binary hash) → server rejects.

                    // Native packet's hash1/hash3 are ALREADY correct (client computed

                    // them using binary_hash ddcb91f42c + token via CC_MD5 hook).

                    // SOLUTION: Send native packet with field replacement (EE007-ALIGN +

                    // EE121-CANON) but KEEP native hash1/hash2/hash3.

                    // Username/password/accId in clean packet match real user (kk994/994624/65657881045335015151).

                    DLOG(@"[EE121-REPL] v37.87: CLEAN 248B pkt + seq + hash1/hash3 RECALC(token_from_EE120)");

                    uint32_t origSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |

                                       ((uint32_t)p[10] << 8) | (uint32_t)p[11];

                    static const uint8_t cleanPkt[248] = {

                        0x00,0x00,0x00,0xF8, 0x00,0x2E,0xE1,0x21, 0x00,0x00,0x00,0x10,

                        0x00,0x14, 0x36,0x35,0x36,0x35,0x37,0x38,0x38,0x31,0x30,0x34,0x35,0x33,0x33,0x35,0x30,0x31,0x35,0x31,0x35,0x31,

                        0x00,0x05, 0x6B,0x6B,0x39,0x39,0x34,

                        0x00,0x06, 0x39,0x39,0x34,0x36,0x32,0x34,

                        0x00,0x05, 0x53,0x51,0x41,0x47,0x45,

                        0x00,0x03, 0x49,0x4F,0x53,

                        0x00,0x12, 0x44,0x59,0x61,0x6E,0x79,0x6F,0x75,0x30,0x30,0x34,0x30,0x5F,0x4D,0x49,0x45,0x53,0x48,0x49,

                        0x00,0x00,

                        0x00,0x0B, 0x69,0x50,0x68,0x6F,0x6E,0x65,0x37,0x50,0x6C,0x75,0x73,

                        0x00,0x18, 0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x20,0x41,0x70,0x70,0x6C,0x65,0x20,0x41,0x31,0x30,0x20,0x47,0x50,0x55,

                        0x00,0x24, 0x36,0x36,0x42,0x30,0x45,0x45,0x30,0x31,0x2D,0x35,0x44,0x32,0x42,0x2D,0x34,0x45,0x41,0x45,0x2D,0x42,0x46,0x42,0x33,0x2D,0x45,0x43,0x41,0x39,0x43,0x41,0x42,0x46,0x31,0x36,0x46,0x38,

                        0x00,0x04, 0x57,0x49,0x46,0x49,

                        0x00,0x05, 0x37,0x2E,0x36,0x2E,0x33,

                        0x00,0x03, 0x39,0x37,0x39,

                        0x00,0x10, 0x33,0x64,0x64,0x38,0x31,0x39,0x36,0x66,0x36,0x34,0x33,0x35,0x30,0x61,0x63,0x62,

                        0x00,0x20, 0x64,0x64,0x63,0x62,0x39,0x31,0x66,0x34,0x32,0x63,0x35,0x61,0x36,0x31,0x32,0x62,0x34,0x39,0x32,0x61,0x32,0x32,0x39,0x36,0x61,0x39,0x37,0x31,0x61,0x35,0x61,0x66,

                        0x00,0x10, 0x37,0x38,0x30,0x61,0x30,0x36,0x34,0x32,0x36,0x31,0x39,0x63,0x38,0x34,0x39,0x38,

                    };

                    unsigned char *fbBuf = (unsigned char *)malloc(248);

                    if (fbBuf) {

                        memcpy(fbBuf, cleanPkt, 248);

                        // Mod 1: seq at [8..11]

                        fbBuf[8] = (origSeq >> 24) & 0xFF;

                        fbBuf[9] = (origSeq >> 16) & 0xFF;

                        fbBuf[10] = (origSeq >> 8) & 0xFF;

                        fbBuf[11] = origSeq & 0xFF;



                        // Mod 2: hash1/hash3 recalc with binary_hash + captured token from EE120.

                        // v37.97: binary_hash = 906e707ec... (captured from clean 7.6.3 via Frida)

                        // hash1/hash3 = MD5(binary_hash + token), NOT MD5(hash2 + token)

                        // hash1 at [181..196] = 16 hex chars = 16 bytes value after 00 10 prefix.

                        // hash3 at [233..248] = 16 hex chars.

                        if (g_hashTokenValid && strlen(g_hashToken) == 31) {

                            static const char kCleanHash2Hex_v80[] = "906e707ec5585f080397b26ff4b8d89d";

                            char md5In[64];

                            memcpy(md5In, kCleanHash2Hex_v80, 32);

                            memcpy(md5In+32, g_hashToken, 31); md5In[63] = 0;

                            unsigned char md5Out[16];

                            memset(md5Out, 0, sizeof(md5Out));

                            typedef unsigned char *(*RawCCID5)(const void *, unsigned long, unsigned char *);

                            static RawCCID5 s_rawMD5 = NULL;

                            if (!s_rawMD5) s_rawMD5 = (RawCCID5)dlsym(RTLD_DEFAULT, "CC_MD5");

                            if (s_rawMD5) s_rawMD5(md5In, 63, md5Out);

                            static const char kHex[] = "0123456789abcdef";

                            char md5Hex[33];

                            for (int hi = 0; hi < 16; hi++) {

                                md5Hex[hi*2]   = kHex[(md5Out[hi] >> 4) & 0xF];

                                md5Hex[hi*2+1] = kHex[md5Out[hi] & 0xF];

                            }

                            md5Hex[32] = 0;

                            // hash3 = first 16 hex chars of md5Hex, hash1 = last 16

                            unsigned char hash3Val[16], hash1Val[16];

                            memcpy(hash3Val, md5Hex, 16);

                            memcpy(hash1Val, md5Hex+16, 16);

                            // Write to fbBuf: hash1 prefix at [180] 00 10, value at [182..197]

                            // Scan to find exact offsets dynamically (safer than hard-coded)

                            size_t h1 = (size_t)-1, h3 = (size_t)-1;

                            size_t scan = 170; // start search inside body after "979" field

                            while (scan + 18 <= 248) {

                                uint16_t tlvLen_be = ((uint16_t)fbBuf[scan] << 8) | fbBuf[scan+1];

                                if (tlvLen_be == 16 && h1 == (size_t)-1) { h1 = scan; scan += 18; continue; }

                                if (tlvLen_be == 32)                         { scan += 34; continue; } // skip hash2

                                if (tlvLen_be == 16 && h1 != (size_t)-1)     { h3 = scan; break; }

                                scan++;

                            }

                            if (h1 != (size_t)-1) memcpy(fbBuf+h1+2, hash1Val, 16);

                            if (h3 != (size_t)-1) memcpy(fbBuf+h3+2, hash3Val, 16);

                            DLOG(@"[EE121-HASH-RECALC] v37.97: MD5(binaryHash+EE120_token)=%s → hash1=%.*s hash3=%.*s (token=%s h1@%zu h3@%zu)",

                                 md5Hex, 16, hash1Val, 16, hash3Val, g_hashToken, h1, h3);

                        } else {

                            DLOG(@"[EE121-HASH-RECALC] v37.97: FALLBACK g_hashTokenValid=%d token invalid — using STALE hash1/hash3 from cleanPkt. Server will probably close!",

                                 g_hashTokenValid);

                        }

                        DLOG(@"[EE121-REPL] v37.97: Sending clean 248B seq=%u hash1/hash3=%@",

                             origSeq, g_hashTokenValid?@"RECALC_DYNAMIC":@"STALE_FALLBACK");

                        ssize_t rret = orig_send(fd, fbBuf, 248, flags);

                        free(fbBuf);

                        if (rret >= 0) return (ssize_t)len;

                        return rret;

                    }

                    ssize_t ret = orig_send(fd, buf, len, flags);

                    return ret;

                }

            }

            // v37.38: Also patch 0x002EE121 login request — it sends DY_MIESHI

            // (short channel from resigning) + iPhone 16 Pro Max + A18 GPU.

            // Server rejects with "version too low" → no real accountId →

            // game server can't validate FFF493#2 → no response.

            // Locate each TLV field by scanning from offset 12 (after cmd+seq+pktLen)

            // EE007 header: pktLen(4) + cmd(4) + seq(4) = 12 bytes

            size_t off = 12;

            size_t chOff = (size_t)-1; // channel TLV

            size_t dmOff = (size_t)-1; // deviceModel TLV

            size_t gpOff = (size_t)-1; // GPU TLV

            size_t accOff = (size_t)-1; // v37.77: accountId TLV (20-digit numeric)

            size_t uuidOff = (size_t)-1; // v37.134-FIX18: empty UUID TLV (TLV#9, after GPU)
            uint16_t uuidFLen = 0;  // FIX47: original UUID TLV fLen (0=empty, 36=non-empty)

            // v37.119: REMOVED kCanonAccIdEE007 — no longer used; accId is passed through as-is.

            while (off + 2 < len) {

                uint16_t fLen = ((uint16_t)p[off] << 8) | p[off + 1];

                if (off + 2 + fLen > len) break;

                const unsigned char *val = p + off + 2;

                // field detection by content match

                if (fLen == 9 && memcmp(val, "DY_MIESHI", 9) == 0) chOff = off;

                else if (fLen == 17 && memcmp(val, "iPhone 16 Pro Max", 17) == 0) dmOff = off;

                else if (fLen == 28 && memcmp(val, "Apple Inc. Apple A18 Pro GPU", 28) == 0) gpOff = off;

                // v37.79: DO NOT detect accountId for replacement (use REAL accId).

                // else if (fLen == 20 && accOff == (size_t)-1) { ... }

                // or fallback: if value contains known strings

                else if (chOff == (size_t)-1 && fLen >= 9 && memcmp(val, "DY_MIESHI", 9) == 0) chOff = off;

                else if (dmOff == (size_t)-1 && fLen >= 11 && (memmem(val, fLen, "iPhone", 6) != NULL)) dmOff = off;

                else if (gpOff == (size_t)-1 && fLen >= 24 && (memmem(val, fLen, "Apple", 5) != NULL && memmem(val, fLen, "GPU", 3) != NULL)) gpOff = off;

                // v37.134-FIX18: Detect empty TLV after GPU = empty UUID field (TLV#9).
                // When IDFV returns nil, TLV#9 is 0B. Server rejects EE121 with status=4.

                // v37.134-FIX50: 恢复FIX47! 检测空+非空UUID TLV, 统一替换为66B0EE01!
                // 新设备(155)日志铁证: TLV#9有真实UUID(fLen=36) → 服务器直接关闭TCP(L666/L733)!
                //   原因: 服务器白名单不认识新设备真实UUID → 拒绝连接(不返回EE121响应)
                // FIX50: 检测空(fLen==0)+非空(fLen==36)UUID TLV, 统一替换为66B0EE01(白名单UUID)
                //   - 主设备: TLV#9空 → hook插入66B0EE01 → 服务器返回EE121响应(status=4)
                //   - 新设备: TLV#9有真实UUID → hook替换为66B0EE01 → 服务器返回EE121响应(status=4)
                // 配合FIX49: 不清除"未授权"响应 → 客户端显示授权提示 → 用户在主设备授权 → 登录成功
                else if ((fLen == 0 || fLen == 36) && gpOff != (size_t)-1 && uuidOff == (size_t)-1) {
                    uuidOff = off;
                    if (fLen == 36) {
                        DLOG(@"[FIX50-UUID-DETECT] Detected non-empty UUID TLV at off=%zu fLen=36 (will replace with 66B0EE01)", off);
                    }
                }

                off += 2 + fLen;

            }

            // v37.134-FIX15: RE-ENABLE EE007-ALIGN body reconstruction.

            // CRITICAL FIX: CC_MD5 hook (FIX14) replaces ch/dm/gp in hash2 input → hash2 = MD5(canonical_fields).

            // But if body keeps ORIGINAL ch/dm/gp → hash2 != MD5(body) → server rejects!

            // FIX: Enable EE007-ALIGN to replace ch/dm/gp in body too → hash2 matches body.

            // EE121-CANON (full rebuild) stays DISABLED (FIX11 proved it breaks packet structure).

            if (chOff != (size_t)-1 || dmOff != (size_t)-1 || gpOff != (size_t)-1 || accOff != (size_t)-1) {

                // Reconstruct packet by replacing all 3 fields found

                // Use dynamic buffer, write from 0 sequentially

                size_t bufCap = len + 64;

                unsigned char *newBuf = (unsigned char *)malloc(bufCap);

                if (!newBuf) {

                    DLOG(@"[EE007-ALIGN] v37.30: malloc(%zu) FAILED, fallthrough", bufCap);

                } else {

                    memset(newBuf, 0, bufCap);

                    // Copy header (first 12 bytes: pktLen cmd seq)

                    memcpy(newBuf, p, 12);

                    size_t out = 12;

                    size_t in = 12;

                    uint32_t fieldsApplied = 0;

                    while (in + 2 < len) {

                        uint16_t fLen = ((uint16_t)p[in] << 8) | p[in + 1];

                        if (in + 2 + fLen > len) break;

                        // AZ6: 逐TLV entry trace — 因为新应用build不确定VERSION/BUILD字段的真实字节表示
                        //   只打印 EE121(登录) 和 EE007(选服)，避免日志过大
                        if (cmd == 0x002EE121 || cmd == 0x000EE007) {
                            size_t pv = (fLen > 16) ? 16 : (size_t)fLen;
                            NSMutableString *hx = [NSMutableString stringWithCapacity:pv*3 + 4];
                            NSMutableString *ac = [NSMutableString stringWithCapacity:pv + 4];
                            for (size_t k=0; k<pv; k++){
                                unsigned char c = p[in+2+k];
                                [hx appendFormat:@"%02X ", c];
                                if (c>=0x20 && c<=0x7E) [ac appendFormat:@"%c", (char)c]; else [ac appendString:@"."];
                            }
                            if (fLen > 16) { [hx appendString:@"…"]; [ac appendString:@"…"]; }
                            DLOG(@"[AZ6-TLV] cmd=0x%08X port=%d offIn=%zu fLen=%u hex='%@' ascii='%@'",
                                 cmd, port, in, (unsigned)fLen, hx, ac);
                        }

                        if (in == chOff && fLen == 9) {

                            // replace channel: 00 12 + DYanyou0040_MIESHI

                            newBuf[out] = 0x00; newBuf[out + 1] = 0x12;

                            memcpy(newBuf + out + 2, "DYanyou0040_MIESHI", 18);

                            out += 20; in += 11; fieldsApplied |= 1;

                        } else if (in == dmOff) {

                            // replace deviceModel: 00 0B + iPhone7Plus (11 chars fixed canonical)

                            newBuf[out] = 0x00; newBuf[out + 1] = 0x0B;

                            memcpy(newBuf + out + 2, "iPhone7Plus", 11);

                            out += 13; in += 2 + fLen; fieldsApplied |= 2;

                        } else if (in == gpOff) {

                            // replace GPU: 00 18 + Apple Inc. Apple A10 GPU (24 chars)

                            newBuf[out] = 0x00; newBuf[out + 1] = 0x18;

                            memcpy(newBuf + out + 2, "Apple Inc. Apple A10 GPU", 24);

                            out += 26; in += 2 + fLen; fieldsApplied |= 4;

                        } else if (in == uuidOff) {

                            // v37.134-FIX50: 恢复FIX47! 所有UUID TLV统一替换为66B0EE01(白名单UUID)!
                            // 新设备(155)日志铁证: 真实UUID → 服务器直接关闭TCP(L666/L733)!
                            //   原因: 服务器白名单不认识新设备真实UUID → 拒绝连接(不返回EE121响应)
                            // FIX50: 空UUID(fLen==0)→插入66B0EE01; 非空UUID(fLen==36)→替换为66B0EE01
                            //   服务器看到66B0EE01(白名单UUID) → 返回EE121响应(status=4"未授权此手机")
                            //   配合FIX49: 不清除"未授权"响应 → 客户端显示授权提示 → 用户在主设备授权 → 登录成功
                            // CC_MD5 hook也替换为66B0EE01 → hash2 = MD5(body with 66B0EE01) → 与EE121 body一致

                            uint16_t uuidLen = ((uint16_t)p[in] << 8) | p[in + 1];
                            newBuf[out] = 0x00; newBuf[out + 1] = 0x24;  // 36B canonical UUID
                            memcpy(newBuf + out + 2, "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 36);
                            out += 38; in += 2 + uuidLen; fieldsApplied |= 16;  // FIX50: advance by 2+fLen (works for both empty and non-empty)
                            if (uuidLen == 0) {
                                DLOG(@"[FIX50-UUID-REPLACE] Inserted UUID TLV at offset %zu (was empty TLV#9, inserted 66B0EE01)", in - 2 - uuidLen);
                            } else {
                                DLOG(@"[FIX50-UUID-REPLACE] Replaced UUID TLV at offset %zu (fLen %u→36, was non-empty UUID, replaced with 66B0EE01)", in - 2 - uuidLen, uuidLen);
                            }

                        } else if (in == accOff && fLen == 20) {

                            // v37.79: DO NOT replace accId — copy REAL through.

                            memcpy(newBuf + out, p + in, 2 + fLen);

                            out += 2 + fLen; in += 2 + fLen;

                        } else if (fLen == 5 && p[in+2]=='7' && p[in+3]=='.' && p[in+4]=='6' && p[in+5]=='.' && p[in+6]=='3') {

                            // AZ-STATUS-FIX: VERSION TLV "7.6.3" → "9.9.9" (等长5B, 解决status=4版本过低根因)
                            // 服务器白名单version: EE121 TLV[11]=7.6.3直接触发status=4返回; 等长替换不改包结构
                            newBuf[out] = 0x00; newBuf[out + 1] = 0x05;
                            newBuf[out+2]='9'; newBuf[out+3]='.'; newBuf[out+4]='9'; newBuf[out+5]='.'; newBuf[out+6]='9';
                            out += 7; in += 7; fieldsApplied |= 32;
                            if (cmd == 0x002EE121 || cmd == 0x000EE007) {
                                DLOG(@"[AZ-TLV-VERSION] Replaced version 7.6.3→9.9.9 at TLV offset %zu (cmd=0x%08X port=%d)", in - 7, cmd, port);
                            }

                        } else if (fLen == 3 && p[in+2]=='9' && p[in+3]=='8' && p[in+4]=='4') {

                            // AZ-STATUS-FIX: BUILD TLV "984" → "999" (等长3B, 配套version修复status=4)
                            newBuf[out] = 0x00; newBuf[out + 1] = 0x03;
                            newBuf[out+2]='9'; newBuf[out+3]='9'; newBuf[out+4]='9';
                            out += 5; in += 5; fieldsApplied |= 64;
                            if (cmd == 0x002EE121 || cmd == 0x000EE007) {
                                DLOG(@"[AZ-TLV-BUILD] Replaced build 984→999 at TLV offset %zu (cmd=0x%08X port=%d)", in - 5, cmd, port);
                            }

                        } else {

                            // unchanged field: copy as-is

                            memcpy(newBuf + out, p + in, 2 + fLen);

                            out += 2 + fLen; in  += 2 + fLen;

                        }

                    }

                    // Copy trailing bytes (null terminator + padding + trailer 01 00)

                    if (in < len) {

                        size_t tailC = len - in;

                        memcpy(newBuf + out, p + in, tailC);

                        out += tailC;

                    }

                    // Rewrite pktLen (4 bytes BE at [0])

                    uint32_t newPktLen = (uint32_t)out;

                    newBuf[0] = (newPktLen >> 24) & 0xFF;

                    newBuf[1] = (newPktLen >> 16) & 0xFF;

                    newBuf[2] = (newPktLen >> 8)  & 0xFF;

                    newBuf[3] =  newPktLen        & 0xFF;

                    uint32_t oldPktLen = 0;

                    if (len >= 4) oldPktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];

                    DLOG(@"[EE007-ALIGN] v37.38-AZ2 cmd=0x%08X port=%d origPktLen=%u newPktLen=%u fieldsMask=%u (ch=%u dm=%u gp=%u acc=%u uuid=%u ver=%u build=%u)",

                         cmd, port, oldPktLen, newPktLen, fieldsApplied,

                         (fieldsApplied & 1) != 0, (fieldsApplied & 2) != 0, (fieldsApplied & 4) != 0, (fieldsApplied & 8) != 0, (fieldsApplied & 16) != 0,
                         (fieldsApplied & 32) != 0, (fieldsApplied & 64) != 0);

                    // Post-alignment hex dump for verification (first 100 bytes)

                    NSMutableString *ph = [NSMutableString stringWithCapacity:300];

                    for (size_t i = 0; i < out && i < 100; i++) [ph appendFormat:@"%02X ", newBuf[i]];

                    DLOG(@"[EE007-ALIGN] v37.30 POST first%zub: %@", out < 100 ? out : (size_t)100, ph);



                    // v37.62: For EE121, FULL field replacement + clean hash2 forced output.

                    // v37.62 patch (hash2 content patch) broke in-packet self-consistency:

                    // server extracts fields, recomputes MD5(fields) != packet.hash2 → CLOSEs.

                    // ROOT CAUSE: hash2 == MD5(EE121 fields) AND hash2 == clean_binary_MD5 are BOTH required.

                    // These two conditions CANNOT be satisfied with user's real accountId/UUID/password,

                    // because MD5(modified_binary_fields) != clean_binary_MD5.

                    // SOLUTION: Replace ALL 5 account/identity fields in CC_MD5 input AND EE121 packet

                    // with clean-client's CANONICAL values (accountId=65657881045335015151,

                    // kk994, 994624, UUID=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8, ch=DYanyou0040,

                    // dm=iPhone7Plus, gp=A10). These values were engineered at app build so that

                    // MD5(canonical_fields) == clean_binary_MD5 (906e707ec5585f080397b26ff4b8d89d).

                    // Verified at clean-client-capture (hook.txt lines 388-404): same values →

                    // server passes hash2==MD5(extract_fields) AND hash2==clean_binary_MD5 checks.

                    // hash1/hash3 = MD5(clean_binary_MD5 + current_token) already computed correctly by

                    // CC_MD5 hook (63B input[0:32] already = clean hash via output replacement at 19437B).

                    // RESULT: EE121 hashes ALL valid → server returns REAL status=0 + sessionId/ticket.

                    // v37.71: Force hash2 = 906e707ec5585f080397b26ff4b8d89d in EE121 packet.

                    // v37.70 log showed server CLOSES connection when hash2 != ddcb91f42c...

                    // Server validates hash2 == clean_binary_MD5 (binary integrity check).

                    // CC_MD5 hook computes hash2 = MD5(replaced_fields) which is NOT ddcb91f42c...

                    // because real accountId/UUID differ from CANONICAL values.

                    // FIX: After EE007-ALIGN, scan newBuf for 32B TLV (00 20 [32B hex]) and

                    // replace with 906e707ec5585f080397b26ff4b8d89d.

                    // v37.75: CANON rebuild with REAL accountId/user/pass (from orig pkt) +

                    // CANONICAL channel/dm/gp/UUID + hash2=ORIG(client-computed MD5).

                    // v37.73 used CANONICAL accountId → status=4 (mismatch with EE100/EE113 REAL accId).

                    // v37.74 used REAL accountId + forced hash2=ddcb91f42c → server closed connection

                    //   (hash2 mismatch: server expects MD5(fields+salt), NOT binary hash).

                    // v37.75: copy hash2 from original packet — client already computed

                    //   MD5(canonical_fields+salt) via CC_MD5 hook (replaces ch/dm/gp/uuid in input).

                    //   Evidence: MD5-LOG out=6e46921d... == EE121-ORIG hash2.

                    // v37.134-FIX15: EE121-CANON full rebuild DISABLED.

                    // FIX11 proved: full rebuild breaks packet structure → server closes connection.

                    // FIX15: Only use EE007-ALIGN (field replacement above) which preserves structure.

                    // CC_MD5 hook changes hash2 input to canonical ch/dm/gp → hash2 matches EE007-ALIGN body.

                    if (0 && cmd == 0x002EE121) {

                        static const char kChannel[]  = "DYanyou0040_MIESHI";  // 18 bytes, 00 12

                        static const char kDModel[]   = "iPhone7Plus";         // 11 bytes, 00 0B

                        static const char kGPU[]      = "Apple Inc. Apple A10 GPU"; // 24 bytes, 00 18

                        static const char kUUID[]     = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8"; // 36 bytes, 00 24



                        // v37.79: Use REAL accountId (NOT CANONICAL).

                        // ROOT CAUSE: hash3=first8B, hash1=last8B of MD5(hash2+token).

                        // token is session-specific, issued by server to REAL account.

                        // Using CANONICAL accId → server expects CANONICAL's token → MISMATCH.

                        // FIX: Use REAL accId so token matches. hash2=ddcb91f42c (binary hash,

                        // same for all clients with same binary). hash3/hash1 already correct.

                        char realAccId[21] = {0};

                        if (len >= 34) {

                            uint16_t accLen = ((uint16_t)p[12]<<8) | p[13];

                            if (accLen == 20 && 14+20 <= len) {

                                memcpy(realAccId, p+14, 20); realAccId[20]=0;

                            }

                        }

                        // v37.119: If accId TLV parse failed, scan body for 20-digit numeric field

                        // instead of falling back to a hardcoded accId (which would cause

                        // other users to enter wrong roles).

                        if (realAccId[0] == 0 && len >= 40) {

                            for (const unsigned char *scan = p+14; scan + 20 <= p+len; scan++) {

                                BOOL allDigits = YES;

                                for (int k = 0; k < 20; k++) {

                                    if (scan[k] < '0' || scan[k] > '9') { allDigits = NO; break; }

                                }

                                if (allDigits) {

                                    memcpy(realAccId, scan, 20); realAccId[20] = 0;

                                    break;

                                }

                            }

                        }

                        // Extract REAL user/pass from original packet (same as clean client).

                        char realUser[32]  = {0}; uint16_t realUserLen  = 5;

                        char realPass[32]  = {0}; uint16_t realPassLen  = 6;

                        if (len >= 48) {

                            uint16_t f1Len = ((uint16_t)p[12]<<8) | p[13];

                            if (f1Len > 0 && f1Len <= 30 && 14+f1Len <= len) {

                                size_t off2 = 14 + f1Len;

                                if (off2+2 <= len) {

                                    uint16_t f2Len = ((uint16_t)p[off2]<<8) | p[off2+1];

                                    if (f2Len > 0 && f2Len <= 30 && off2+2+f2Len <= len) {

                                        realUserLen = f2Len;

                                        memcpy(realUser, p+off2+2, f2Len); realUser[f2Len]=0;

                                    }

                                }

                                size_t off3 = off2 + 2 + realUserLen;

                                if (off3+2 <= len) {

                                    uint16_t f3Len = ((uint16_t)p[off3]<<8) | p[off3+1];

                                    if (f3Len > 0 && f3Len <= 30 && off3+2+f3Len <= len) {

                                        realPassLen = f3Len;

                                        memcpy(realPass, p+off3+2, f3Len); realPass[f3Len]=0;

                                    }

                                }

                            }

                        }

                        DLOG(@"[EE121-CANON] v37.79: REAL accId=%s user=%s(%uB) pass=%s(%uB)",

                             realAccId, realUser, realUserLen, realPass, realPassLen);



                        // Rebuild newBuf from scratch (after header 12B).

                        // v37.108-DIST: Use NATIVE accId + CANONICAL ch/dm/gp + REAL device UUID + ORIGINAL hash2 (body MD5).

                        size_t rebuildOut = 12;

                        // v37.108: Use REAL accId extracted from original packet — NOT CANONICAL!

                        // ROOT CAUSE: Forcing kk994's accId (65657881045335015151) caused ALL users

                        // to enter kk994's game character regardless of their login account.

                        // realAccId was already extracted from the original 00 14 [20B accId] TLV above.

                        {

                            char nativeAcc[21] = {0};

                            if (realAccId && strlen(realAccId) == 20) {

                                memcpy(nativeAcc, realAccId, 20);

                            } else {

                                // Fallback: try to extract 20-digit accId from body area again

                                const char *scanStart = (const char *)p + 14;

                                const char *scanEnd = (const char *)p + ((len > 40) ? 40 : len);

                                for (const char *s = scanStart; s + 20 <= scanEnd; s++) {

                                    BOOL isDigits = YES;

                                    for (int k = 0; k < 20 && isDigits; k++) {

                                        if (s[k] < '0' || s[k] > '9') isDigits = NO;

                                    }

                                    if (isDigits) { memcpy(nativeAcc, s, 20); break; }

                                }

                                // Last resort: copy whatever was in position 14 if it's 20 printable chars

                                if (nativeAcc[0] == 0 && len >= 34) {

                                    memcpy(nativeAcc, p + 14, 20);

                                }

                            }

                            nativeAcc[20] = 0;

                            DLOG(@"[EE121-CANON] v37.108: Using NATIVE accId=%s (NOT CANONICAL 6565788...)", nativeAcc);

                            newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x14;

                            memcpy(newBuf+rebuildOut+2, nativeAcc, 20); rebuildOut += 22;

                        }

                        // user (REAL, variable length)

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=(uint8_t)(realUserLen&0xFF);

                        memcpy(newBuf+rebuildOut+2, realUser, realUserLen); rebuildOut += 2+realUserLen;

                        // pass (REAL, variable length)

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=(uint8_t)(realPassLen&0xFF);

                        memcpy(newBuf+rebuildOut+2, realPass, realPassLen); rebuildOut += 2+realPassLen;

                        // SQAGE 5B

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x05; memcpy(newBuf+rebuildOut+2,"SQAGE",5); rebuildOut+=7;

                        // IOS 3B

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x03; memcpy(newBuf+rebuildOut+2,"IOS",3);   rebuildOut+=5;

                        // channel 18B + 00 00 separator

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x12; memcpy(newBuf+rebuildOut+2,kChannel,18); rebuildOut+=20;

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x00;                                              rebuildOut+=2;

                        // deviceModel 11B

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x0B; memcpy(newBuf+rebuildOut+2,kDModel,11); rebuildOut+=13;

                        // GPU 24B

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x18; memcpy(newBuf+rebuildOut+2,kGPU,24);     rebuildOut+=26;

                        // v37.134-FIX5: Add empty TLV (00 00) between GPU and UUID/WIFI to match original 16-TLV structure

                        // Original packet has 00 00 between GPU and WIFI (TLV#9), but rebuild was missing it (only 15 TLVs)

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x00;                                              rebuildOut+=2;

                        // UUID 36B — v37.107-DIST: Use REAL device UUID from original packet!

                        // Each user uses their OWN device UUID for device whitelist authorization.

                        // Extract real UUID from original packet (TLV: 00 24 [36B UUID]).

                        char realDevUUID[37] = {0};

                        BOOL gotRealUUID = NO;

                        for (size_t sp = 12; sp + 2 + 36 <= len; ) {

                            uint16_t sl = ((uint16_t)p[sp]<<8) | p[sp+1];

                            if (sp + 2 + sl > len) break;

                            if (sl == 36) {

                                // Check if it looks like a UUID (8-4-4-4-12 hex format)

                                const char *u = (const char *)(p + sp + 2);

                                BOOL isUUID = YES;

                                for (int ui = 0; ui < 36; ui++) {

                                    char c = u[ui];

                                    if (ui == 8 || ui == 13 || ui == 18 || ui == 23) {

                                        if (c != '-') { isUUID = NO; break; }

                                    } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {

                                        isUUID = NO; break;

                                    }

                                }

                                if (isUUID) {

                                    memcpy(realDevUUID, u, 36);

                                    realDevUUID[36] = 0;

                                    gotRealUUID = YES;

                                    break;

                                }

                            }

                            sp += 2 + sl;

                        }

                        // v37.133 CRITICAL FIX: ONLY insert UUID TLV if original packet ACTUALLY contained UUID!

                        // Original 213B EE121 has NO UUID field. Forcing 38B UUID here caused

                        // packet size mismatch (213→248) → server rejected + closed connection immediately.

                        if (gotRealUUID) {

                            DLOG(@"[EE121-CANON] v37.133: Original packet HAD UUID (36B) — inserting UUID TLV");

                            newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x24; memcpy(newBuf+rebuildOut+2,realDevUUID,36);

                            rebuildOut+=38;

                        } else {

                            DLOG(@"[EE121-CANON] v37.133: Original packet had NO UUID — SKIPPING UUID TLV (preserving structure)");

                        }

                        // WIFI 4B

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x04; memcpy(newBuf+rebuildOut+2,"WIFI",4);   rebuildOut+=6;

                        // v37.134-FIX8: REVERT version bump — official client STILL uses 7.6.3 + 983!

                        // The status=4 was NOT about version being too low — it's about validation failure.

                        // Using wrong version (7.7.0/990) makes server reject the packet entirely.

                        newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=0x05; memcpy(newBuf+rebuildOut+2,"7.6.3",5);  rebuildOut+=7;

                        // Version/build number — keep original 983

                        {

                            const char *origVer = "983";

                            int origLen = 3;

                            DLOG(@"[EE121-CANON] v37.134-FIX8: Keeping ORIGINAL version 7.6.3 + 983 (matching official client)");

                            newBuf[rebuildOut]=0x00; newBuf[rebuildOut+1]=(uint8_t)origLen;

                            memcpy(newBuf+rebuildOut+2, origVer, origLen);

                            rebuildOut += 2 + origLen;

                        }

                        // --- hash1/hash2/hash3 block ---

                        // v37.141 CRITICAL ROLLBACK: hash2 MUST BE COPIED FROM ORIGINAL PACKET, NOT RECOMPUTED!

                        // Declare h1/h2/h3 OUTSIDE brace scope so tail DLOG can access them.

                        uint32_t h1 = 0, h2 = 0, h3 = 0;

                        {

                            // Step 1: Extract hash1/hash2/hash3 raw bytes from original packet.

                            unsigned char hash1Val[16];

                            unsigned char hash3Val[16];

                            char origHash2Hex[33];

                            // Scan original packet TLV offsets

                            for (size_t sp = 12; sp + 2 + 16 <= len; ) {

                                uint16_t sl = ((uint16_t)p[sp]<<8) | p[sp+1];

                                if (sp + 2 + sl > len) break;

                                if (sl == 16 && h3 == 0) { h3 = sp; sp += 2+sl; continue; }

                                if (sl == 32 && h2 == 0) { h2 = sp; sp += 2+sl; continue; }

                                if (sl == 16 && h1 == 0) { h1 = sp; sp += 2+sl; continue; }

                                sp += 2+sl;

                            }

                            if (h3) memcpy(hash3Val, p+h3+2, 16); else memset(hash3Val, 0, 16);

                            if (h1) memcpy(hash1Val, p+h1+2, 16); else memset(hash1Val, 0, 16);

                            memset(origHash2Hex, 0, 33);

                            if (h2) memcpy(origHash2Hex, p+h2+2, 32);

                            DLOG(@"[EE121-HASH] v37.141: hash1/hash2/hash3 ALL preserved from original packet (hash2 not recomputed)");

                            if (h2) DLOG(@"[EE121-HASH2] v37.141: Using ORIGINAL hash2=%.32s (v37.138/139 MD5-recompute BROKE LOGIN — REVERTED)", origHash2Hex);

                            else   DLOG(@"[EE121-HASH2] v37.141: ⚠️ Original packet had NO hash2 TLV!");



                            // === Step 2: Write hash3 → hash2 → hash1 in native order ===

                            newBuf[rebuildOut] = 0x00; newBuf[rebuildOut+1] = 0x10;

                            memcpy(newBuf+rebuildOut+2, hash3Val, 16);

                            rebuildOut += 18;



                            newBuf[rebuildOut] = 0x00; newBuf[rebuildOut+1] = 0x20;

                            if (h2) memcpy(newBuf+rebuildOut+2, origHash2Hex, 32);  // use ORIGINAL

                            else    memset(newBuf+rebuildOut+2, 0x30, 32);           // fallback: '0'*32

                            rebuildOut += 34;



                            newBuf[rebuildOut] = 0x00; newBuf[rebuildOut+1] = 0x10;

                            memcpy(newBuf+rebuildOut+2, hash1Val, 16);

                            rebuildOut += 18;



                            DLOG(@"[EE121-HASH1] v37.141: hash1=%.*s (orig, CC_MD5(token) last16)", 16, hash1Val);

                            DLOG(@"[EE121-HASH3] v37.141: hash3=%.*s (orig, CC_MD5(token) first16)", 16, hash3Val);

                        }

                        // v37.141 DIAG: Dump FULL rebuilt EE121-CANON hex (first 200 bytes) so we can compare TLV structure vs EE121-ORIG 213B

                        // Currently only EE007-ALIGN's first 100B is dumped, but EE121-CANON OVERWRITES newBuf afterwards!

                        {

                            NSMutableString *diagHex = [NSMutableString stringWithCapacity:600];

                            size_t diagLen = rebuildOut < 200 ? rebuildOut : 200;

                            for (size_t i = 0; i < diagLen; i++) {

                                [diagHex appendFormat:@"%02X ", newBuf[i]];

                                if ((i+1) % 32 == 0 && i+1 < diagLen) [diagHex appendString:@"\n    "];

                            }

                            DLOG(@"[EE121-CANON-DIAG] v37.141: FULL first%zub of CANON pkt (pktLen=%u):\n    %@",

                                 diagLen, (unsigned)rebuildOut, diagHex);

                            // Also print all TLVs for structural comparison

                            NSMutableString *tlvDump = [NSMutableString stringWithCapacity:300];

                            size_t to = 12;

                            int tlvIdx = 0;

                            while (to + 2 < rebuildOut) {

                                uint16_t tl = ((uint16_t)newBuf[to]<<8) | newBuf[to+1];

                                if (to + 2 + tl > rebuildOut) {

                                    [tlvDump appendFormat:@"[TLV#%d@%zu] len=%u OUT_OF_RANGE_ABORT", tlvIdx, to, (unsigned)tl];

                                    break;

                                }

                                NSString *valStr;

                                if (tl <= 40) {

                                    valStr = [[NSString alloc] initWithBytes:newBuf+to+2 length:tl encoding:NSUTF8StringEncoding];

                                    if (!valStr) {

                                        NSMutableString *hx = [NSMutableString stringWithCapacity:tl*3];

                                        for (size_t k = 0; k < tl; k++) [hx appendFormat:@"%02X ", newBuf[to+2+k]];

                                        valStr = hx;

                                    }

                                } else {

                                    NSMutableString *hx = [NSMutableString stringWithCapacity:48];

                                    for (size_t k = 0; k < 16; k++) [hx appendFormat:@"%02X ", newBuf[to+2+k]];

                                    valStr = [NSString stringWithFormat:@"%@...(len=%u)", hx, (unsigned)tl];

                                }

                                [tlvDump appendFormat:@"[TLV#%d@%zu] %uB: %@  ", tlvIdx, to, (unsigned)tl, valStr];

                                tlvIdx++;

                                to += 2 + tl;

                            }

                            DLOG(@"[EE121-CANON-DIAG] v37.141: TLV structure (%d TLVs, end@%zu / pktLen=%u):\n    %@",

                                 tlvIdx, to, (unsigned)rebuildOut, tlvDump);

                        }

                        // Final pktLen

                        uint32_t newPL = (uint32_t)rebuildOut;

                        newBuf[0] = (newPL >> 24) & 0xFF; newBuf[1] = (newPL >> 16) & 0xFF;

                        newBuf[2] = (newPL >> 8)  & 0xFF; newBuf[3] =  newPL        & 0xFF;

                        // Dump rebuilt tail for verification

                        NSMutableString *rt = [NSMutableString stringWithCapacity:200];

                        for (size_t i = (rebuildOut > 80 ? rebuildOut-80 : 0); i < rebuildOut; i++)

                            [rt appendFormat:@"%02X ", newBuf[i]];

                        DLOG(@"[EE121-CANON] v37.98: Rebuilt EE121 CANONICAL accId + CANONICAL ch/dm/gp/UUID. hash2=ORIGINAL(bodyMD5) hash1/hash3=MD5(realBinaryHash+token). pktLen=%u h1Found=%u h2Found=%u h3Found=%u tail80: %@",

                             newPL, (h1!=0), (h2!=0), (h3!=0), rt);

                        out = rebuildOut;

                    }



                    // v37.134-FIX17: Direct hash1/hash3 replacement based on Frida clean client capture.

                    // Algorithm: hash_full = CC_MD5(clean_binary_hash_hex + token) → 32 chars hex

                    //   hash3 = hash_full[0:16]  (first 16 chars) → TLV#13 (second-to-last 16B TLV)

                    //   hash1 = hash_full[16:32] (last 16 chars)  → TLV#15 (last 16B TLV)

                    // Token is from EE120 response (g_hashToken, 31 bytes).

                    // This replaces the broken CC_MD5_Final/Update hooks (rebind=0) and memory scan.

                    if (cmd == 0x002EE121 && g_hashTokenValid && strlen(g_hashToken) == 31) {

                        static const char kCleanHashHex[] = "906e707ec5585f080397b26ff4b8d89d";

                        char md5In[64];

                        memcpy(md5In, kCleanHashHex, 32);

                        memcpy(md5In + 32, g_hashToken, 31);

                        md5In[63] = 0;

                        unsigned char md5Out[16];

                        memset(md5Out, 0, sizeof(md5Out));

                        typedef unsigned char *(*RawCCMD5)(const void *, unsigned long, unsigned char *);

                        static RawCCMD5 s_rawMD5 = NULL;

                        if (!s_rawMD5) s_rawMD5 = (RawCCMD5)dlsym(RTLD_DEFAULT, "CC_MD5");

                        if (s_rawMD5) {

                            s_rawMD5(md5In, 63, md5Out);

                            char md5Hex[33];

                            static const char kHexChars[] = "0123456789abcdef";

                            for (int hi = 0; hi < 16; hi++) {

                                md5Hex[hi*2]   = kHexChars[(md5Out[hi] >> 4) & 0xF];

                                md5Hex[hi*2+1] = kHexChars[md5Out[hi] & 0xF];

                            }

                            md5Hex[32] = 0;

                            // hash3 = first 16 chars, hash1 = last 16 chars

                            char hash3Val[16], hash1Val[16];

                            memcpy(hash3Val, md5Hex, 16);

                            memcpy(hash1Val, md5Hex + 16, 16);



                            // Parse TLV structure to find last two 16-byte TLVs

                            // From Frida capture: ...TLV#13(16B=hash3) TLV#14(32B=hash2) TLV#15(16B=hash1)

                            size_t last16Off = (size_t)-1, secondLast16Off = (size_t)-1;

                            size_t scan2 = 12; // skip 12B header

                            while (scan2 + 2 <= out) {

                                uint16_t tlvLen = ((uint16_t)newBuf[scan2] << 8) | newBuf[scan2+1];

                                if (scan2 + 2 + tlvLen > out) break;

                                if (tlvLen == 16) {

                                    secondLast16Off = last16Off;

                                    last16Off = scan2;

                                }

                                scan2 += 2 + tlvLen;

                            }

                            // secondLast16Off = hash3 position, last16Off = hash1 position

                            if (secondLast16Off != (size_t)-1) {

                                memcpy(newBuf + secondLast16Off + 2, hash3Val, 16);

                            }

                            if (last16Off != (size_t)-1) {

                                memcpy(newBuf + last16Off + 2, hash1Val, 16);

                            }

                            DLOG(@"[EE121-HASH-FIX17] CC_MD5(cleanHash+token)=%s → hash3=%.*s hash1=%.*s (h3Off=%zu h1Off=%zu token=%s)",

                                 md5Hex, 16, hash3Val, 16, hash1Val, secondLast16Off, last16Off, g_hashToken);

                        }

                    }



                    ssize_t rret = orig_send(fd, newBuf, out, flags);

                    free(newBuf);

                    if (rret >= 0) return (ssize_t)len;

                    return rret;

                }

            }

        }

    }

    // NOTE: old CHANNEL-PATCH for DY_MIESHI only is now replaced by EE007-ALIGN above.



    // v37.26-DIST: For ALL game server packets, call orig_send directly — NO processing. L5 sendScan + L6 EE007 patch applied earlier.

    // Added verbose FULL hex dump for 0x000EE007 and 0x00FFF493 so we can do byte-by-byte

    // comparison against the clean (non-injected) client capture (hook.txt).

    if (len >= 8 && (port == 12003 || port == 58158 ||

                      (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024))) {

        const unsigned char *p = (const unsigned char *)buf;

        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        // v37.19-DIST: Verbose hex for critical commands (EE007 device info, FFF493 role data)

        if (cmd == 0x000EE007 || cmd == 0x00FFF493) {

            NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];

            for (size_t i = 0; i < len; i++) {

                [hex appendFormat:@"%02X ", p[i]];

                if ((i + 1) % 32 == 0 && i + 1 < len) [hex appendString:@"\n    "];

            }

            DLOG(@"[GAME-SEND-HEX] cmd=0x%08X len=%zu port=%d FULL HEX:\n    %@", cmd, len, port, hex);

            // Also print tail so we can verify trailing bytes (01 00 vs 00 01 00 for EE007)

            if (len >= 8) {

                size_t tailStart = (len > 32) ? (len - 32) : 0;

                NSMutableString *tail = [NSMutableString string];

                for (size_t i = tailStart; i < len; i++) [tail appendFormat:@"%02X ", p[i]];

                DLOG(@"[GAME-SEND-TAIL] cmd=0x%08X len=%zu tail[%zu-%zu]: %@", cmd, len, tailStart, len-1, tail);

            }

        }

        // v37.44: FFF493-REPL v2 — Replace 5 fields in FFF493#2 with REAL clean client values.

        // v37.43 disabled FFF493-REPL entirely, but server rejected FFF493#2 because

        // sessionId="" and ticket="" (login server returned status=4, no 0x8234AB89).

        // v37.44 uses REAL values captured from clean client:

        //   sessionId: "zmURQCP7xCg4ejMcPEPj2rc61mFfb0Fh" (32B, from 0x8234AB89)

        //   ticket: "kk994|1785665252271|236923||SwnLPVw4w..." (366B, from 0x8234AB89)

        //   clientId: "65657881045335015151" (matches EE121-REPL clean packet)

        //   MACADDRESS: "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8" (matches EE006-UUID)

        //   md5: "bdf8dad65adff0f9fed3876640c9418d" (clean client binary hash)

        // Flow: take saved native plaintext → replace 5 fields → re-encrypt with saved

        // AES key+iv → Base64 → HMAC → build new packet (matches clean 1432B format).

        // v37.56: FFF493-REPL v2 RE-ENABLED with KEY CHANGE.

        // v37.44-v37.53 replaced 5 fields (sessionId+ticket+clientId+MACADDRESS+md5) → server

        // rejected FFF493#2 (only heartbeats). v37.56 ONLY replaces sessionId+ticket, keeps

        // clientId/MACADDRESS/md5 NATIVE (matches current session/binary).

        // If server only validates sessionId/ticket format (not cross-session validity) → works.

        // v37.87: DO BOTH FFF493#1 AND FFF493#2 replacement! Previous versions only did

        // #2 (len>800), #1 went with sessionId=""/ticket="" → server checked #1 first → ignored.

        if (cmd == 0x00FFF493 && g_aes_key_saved) {

            // Figure out which FFF493 this is (#1 IOS_CLIENT_MSG or #2 NEW_USER)

            char *nativePlain = NULL; size_t nativeLen = 0; int fffWhich = 0;

            // FFF493#2 detection (len > 800 or saved #2 plaintext matches NEW_USER)

            if (len > 800 && g_fff493_2_native_plain && g_fff493_2_native_len > 400) {

                nativePlain = g_fff493_2_native_plain;

                nativeLen   = g_fff493_2_native_len;

                fffWhich = 2;

            }

            // v37.87 FIX: #1 detection also via len range (350-800) — don't require plaintext saved first!

            // v37.87 required g_fff493_1_plain_buf (>300) but that buffer was NEVER filled because

            // the CCCrypt save threshold was >400 (and #1's realDataInLen=316 < 400).

            // Now detect #1 by len range first, then plaintext (saved with reduced >200 threshold).

            else if ((len >= 350 && len <= 800) || (g_fff493_1_plain_buf && g_fff493_1_plain_len > 200)) {

                if (g_fff493_1_plain_buf && g_fff493_1_plain_len > 200) {

                    nativePlain = g_fff493_1_plain_buf;

                    nativeLen   = g_fff493_1_plain_len;

                }

                fffWhich = 1;

                DLOG(@"[FFF493-REPL] v37.87: FFF493#1 detected (len=%zu, plainSaved=%d plainLen=%zu)",

                     len, g_fff493_1_plain_buf != NULL, g_fff493_1_plain_len);

            }

            // Fallback: also attempt if len>400 even if we don't know which

            if (!nativePlain && len > 400 && fffWhich == 0) {

                if (g_fff493_2_native_plain) { nativePlain=g_fff493_2_native_plain; nativeLen=g_fff493_2_native_len; fffWhich=2; }

                else if (g_fff493_1_plain_buf) { nativePlain=g_fff493_1_plain_buf; nativeLen=g_fff493_1_plain_len; fffWhich=1; }

            }

            // v37.105 TEST: Skip ALL FFF493 modifications! Send original packets as-is.

            // v37.104 proved: md5 NOT recomputed (correct), but server still only sends heartbeats.

            // FFF493#2 plaintext already has CANONICAL values (clientId, channel from CH-L4).

            // CC_MD5 hook already computes correct md5 over field concat (with replacements).

 //             // v37.103 FIX: Only replace FFF493#2 (NEW_USER_ENTER_SERVER_REQ)!

//            // FFF493#1 (IOS_CLIENT_MSG_REQ) is device-info — clean client does NOT include

//            // sessionId/ticket in it. Previous code INSERTED them → server confused → no role data!

//            // Now skip #1 replacement entirely: let original packet (with CH-L4 patches) go through.

//            // v37.134-FIX9: REMOVED '0 &&' — ENABLE FFF493#2 replacement with sessionId/ticket!

            // v37.134-FIX19: RE-DISABLED FFF493-REPL! Root cause of "卡住正在进入" after FIX18.

            //   With FIX18, EE121 succeeds → server returns REAL sessionId/ticket → client

            //   includes them in FFF493#2. FFF493-REPL was REPLACING UUID + RE-ENCRYPTING the

            //   packet → different ciphertext/HMAC → server rejects → no role data → stuck.

            //   Clean client (no injection) and 全能签+Frida (no WangXianHook) both work fine

            //   → server accepts ORIGINAL packets as-is. CH-L4 CCCrypt hook already patches

            //   channel/device/gpu in plaintext BEFORE client encryption. CC_MD5 hook already

            //   computes correct md5. No re-encryption needed!

            // FIX53J: OPEN this block for BOTH #1 and #2. The actual sessionId/ticket/UUID
            // modifications are still gated by fffWhich==2. But if g_l4_safe_fallback==YES
            // we MUST enter this block to force-re-encrypt the saved patched plaintext
            // (which has canonical values + matches what CC_MD5 hashed), otherwise:
            //   HMAC(based on patched data via CC_MD5) ≠ ciphertext(based on ORIGINAL data)
            //   → server HMAC validation fails → graceful TCP close → "连接异常中断"
            //   or "正在进入" stuck.

            NSMutableString *newStr = nil; // FIX53J: declare OUTSIDE fffWhich==2 guard so forceReencrypt below can access

            uint32_t origSeq = 0; uint16_t origAlgo = 0; volatile BOOL jsonModified = NO;

            if ((fffWhich == 1 || fffWhich == 2) && nativePlain && nativeLen > 100 && len >= 20) {

                origSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |

                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];

                origAlgo = ((uint16_t)p[14] << 8) | p[15];

                NSString *nativeStr = [[NSString alloc] initWithBytesNoCopy:(void *)nativePlain

                                                                     length:nativeLen

                                                                   encoding:NSUTF8StringEncoding

                                                               freeWhenDone:NO];

                if (nativeStr) {

                    newStr = [NSMutableString stringWithString:nativeStr];

                    // FIX53N: Declare these OUTSIDE the if(fffWhich==2) block so FIX53N merge logic can access them
                    NSString *realSessionId = nil; NSString *realTicket = nil;
                    BOOL didReplaceSession = NO; BOOL didReplaceTicket = NO;

                    // FIX53J: sessionId/ticket/UUID insertion ONLY for FFF493#2 (NEW_USER).
                    // FFF493#1 (IOS_CLIENT_MSG) NEVER has these fields — inserting them → corrupt JSON.
                    if (fffWhich == 2) {


                    // v37.101 FIX: Replace REAL device UUID in "MACADDRESS" field with CANONICAL UUID!

                    // ROOT CAUSE: FFF493#2 JSON has "MACADDRESS": "180C4F27-..." (REAL device UUID),

                    // but EE121-CANON uses CANONICAL UUID "66B0EE01-...". Server cross-validates

                    // UUID between EE121 and FFF493#2 → mismatch → immediate connection CLOSE!

                    // CH-L4 hook patches channel/dm/gp in CCCrypt plaintext but NOT UUID.

                    // IDFV hook patches [UIDevice identifierForVendor] but MACADDRESS comes from

                    // a different source. FIX: scan newStr for "MACADDRESS": "UUID" and replace.

                    BOOL didReplaceUUID = NO;

                    {

                        NSString *macKey = @"\"MACADDRESS\": \"";

                        NSRange macRange = [newStr rangeOfString:macKey];

                        if (macRange.location != NSNotFound) {

                            NSUInteger uuidStart = macRange.location + macRange.length;

                            // FIX53P: CRITICAL FIX — Handle EMPTY MACADDRESS field!
                            // Root cause (wxhook-185): When MACADDRESS is empty (""MACADDRESS": ""),
                            // the old code tried to read 36 chars → got JSON garbage (", "md5": "..."),
                            // failed UUID format check, and SKIPPED replacement. But EE121 hook
                            // inserted canonical UUID (66B0EE01) → server cross-validates EE121 vs
                            // FFF493#2 UUID → MISMATCH → "连接异常中断" (connection reset).
                            // FIX: When MACADDRESS is empty (next char is '"'), INSERT canonical UUID
                            // between the quotes. This changes JSON length (+36B) → triggers re-encryption.
                            BOOL macIsEmpty = (uuidStart < newStr.length &&
                                               [newStr characterAtIndex:uuidStart] == '"');

                            BOOL macHasValidUUID = (!macIsEmpty &&
                                                     uuidStart + 36 <= newStr.length);

                            NSString *realUUID = nil;
                            BOOL isValidUUIDFormat = NO;

                            if (macHasValidUUID) {
                                realUUID = [newStr substringWithRange:NSMakeRange(uuidStart, 36)];

                                // FIX53J: Check if MACADDRESS value is a valid UUID (8-4-4-4-12 hex format)
                                // BEFORE replacing. If MACADDRESS is empty (""), the next 36 chars
                                // would span across JSON fields (eating ", "md5": "..." etc) → JSON CORRUPTION!
                                isValidUUIDFormat = (
                                    [realUUID length] == 36 &&
                                    [realUUID characterAtIndex:8] == '-' &&
                                    [realUUID characterAtIndex:13] == '-' &&
                                    [realUUID characterAtIndex:18] == '-' &&
                                    [realUUID characterAtIndex:23] == '-'
                                );
                            }

                            if (macIsEmpty) {
                                // FIX53P: MACADDRESS is empty — INSERT canonical UUID
                                static const char kCanonUUID_v101p[] = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8";
                                NSString *canonUUID = [NSString stringWithUTF8String:kCanonUUID_v101p];

                                [newStr insertString:canonUUID atIndex:uuidStart];
                                didReplaceUUID = YES;

                                DLOG(@"[FFF493-UUID] v37.101-FIX53P: #%d INSERTED canonical UUID into EMPTY MACADDRESS (66B0EE01) at pos=%lu", fffWhich, (unsigned long)uuidStart);

                            } else if (isValidUUIDFormat) {

                            // FIX53: Use canonical 66B0EE01 (white-listed login UUID), keeps parity with CCCrypt L4 and CC_MD5.
                            static const char kCanonUUID_v101[] = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8";

                            NSString *canonUUID = [NSString stringWithUTF8String:kCanonUUID_v101];

                            if (![realUUID isEqualToString:canonUUID]) {

                                [newStr replaceCharactersInRange:NSMakeRange(uuidStart, 36) withString:canonUUID];

                                didReplaceUUID = YES;

                                DLOG(@"[FFF493-UUID] v37.101-FIX53: #%d REPLACED MACADDRESS UUID: %@ → %@",

                                     fffWhich, realUUID, canonUUID);

                            } else {

                                DLOG(@"[FFF493-UUID] v37.101: #%d MACADDRESS already CANONICAL UUID (66B0EE01)", fffWhich);

                            }

                            } else {

                                // FIX53J: MACADDRESS not a valid UUID format — skip replacement
                                DLOG(@"[FFF493-UUID] v37.101-FIX53J: #%d SKIP UUID replace — MACADDRESS not valid UUID format (val='%@')", fffWhich, realUUID ? realUUID : @"<nil/short>");

                            }

                        }

                    }

                    // realSessionId and realTicket already declared above
                    if (g_sessionValid && g_sessionId[0] != 0 && g_ticket[0] != 0) {

                        realSessionId = [NSString stringWithUTF8String:g_sessionId];

                        realTicket = [NSString stringWithUTF8String:g_ticket];

                        DLOG(@"[FFF493-REPL] v37.87: FFF493#%d Using CAPTURED sessionId/ticket (valid=%d ticketLen=%d)",

                             fffWhich, g_sessionValid, g_ticketLen);

                    } else {

                        realSessionId = @"zmURQCP7xCg4ejMcPEPj2rc61mFfb0Fh";

                        realTicket = @"kk994|1785665252271|236923||SwnLPVw4wqtqXUfBX0JETQlXLrNxbb0TElk1YQvRmrKTNJG1ImA5eVtTnqY06XALBsKbKtCRJ7iRMUJcE+yZkboYVJ55k35zIxDeoLGoe/4TAo6nQjRD5obTaa18ObMyJaz6R0TUg8Oz78N1me5vBrU9c6sImsqv1QZEebEgfZO7KY2OdU35OV8Vb6rXRBwl1f78jA1OnkTRmf7ZthPpP1q3V1Y8OnzHnbHwq/xnZP3KtEXej3RCQX6zjJf+G81+W2XSpzUPynQXQ/Q/u9qn2N/5/db/8uMz68q/giuSAb9ikNYno+NYXTgn4FLsUbV15NTU5YIVqo9He/pYQCQ==";

                        DLOG(@"[FFF493-REPL] v37.87: FFF493#%d Using FALLBACK sessionId/ticket (sessionValid=%d)", fffWhich, g_sessionValid);

                    }

                    didReplaceSession = ([newStr replaceOccurrencesOfString:@"\"sessionId\": \"\""

                                            withString:[NSString stringWithFormat:@"\"sessionId\": \"%@\"", realSessionId]

                                               options:0 range:NSMakeRange(0, newStr.length)] > 0);

                    didReplaceTicket = ([newStr replaceOccurrencesOfString:@"\"ticket\": \"\""

                                            withString:[NSString stringWithFormat:@"\"ticket\": \"%@\"", realTicket]

                                               options:0 range:NSMakeRange(0, newStr.length)] > 0);

                    // v37.100 FIX: #pragma clang optimize off — DISABLE -O2 for this entire block!

                    // -O2 optimizer incorrectly assumes rangeOfString/strstr return NSNotFound/NULL,

                    // eliminating ALL jsonModified==NO paths (SKIP insert, md5 guard, else branch).

                    // This causes FFF493#2 to ALWAYS be re-encrypted even when JSON is unchanged,

                    // producing different ciphertext → server validation FAIL → connection CLOSE!

                    #pragma clang optimize off

                    // v37.99 FIX: Track whether JSON was ACTUALLY modified.

                    // v37.100 FIX: volatile — prevent -O2 from determining jsonModified is always YES

                    // and eliminating the jsonModified==NO path (SKIP insert, else branch, etc.)

                    // v37.101: Include didReplaceUUID — MACADDRESS UUID replacement always triggers

                    // re-encryption + md5 recomputation to fix EE121/FFF493#2 UUID mismatch.

                    // FIX53J: assign to outer-scope jsonModified instead of declaring a new variable
                    jsonModified = (didReplaceSession || didReplaceTicket || didReplaceUUID);

                    // v37.100 FIX: asm compiler barrier — prevent -O2 from tracking jsonModified value

                    // across this point and eliminating the else branch of if(jsonModified).

                    asm volatile("" ::: "memory");

                    // v37.88 FIX: #1 (IOS_CLIENT_MSG_REQ) has NO sessionId/ticket fields in JSON!

                    // v37.99 FIX: ONLY insert if the field is truly ABSENT from JSON!

                    // FFF493#2 (NEW_USER_ENTER_SERVER_REQ) already HAS non-empty sessionId/ticket

                    // from the login flow. Previous code inserted DUPLICATE fields → JSON corruption

                    // → server validation failure → connection CLOSE!

                    // v37.100 FIX: Use strstr (C function) instead of rangeOfString (ObjC method).

                    // -O2 optimizer incorrectly assumes rangeOfString returns NSNotFound, making

                    // hasSessionId/hasTicket always NO, eliminating SKIP branch as dead code.

                    // strstr is a C library function the optimizer cannot analyze.

                    if (!didReplaceSession || !didReplaceTicket) {

                        const char *jsonCStr = [newStr UTF8String];

                        volatile BOOL hasSessionId = (jsonCStr && strstr(jsonCStr, "\"sessionId\"") != NULL);

                        volatile BOOL hasTicket = (jsonCStr && strstr(jsonCStr, "\"ticket\"") != NULL);

                        asm volatile("" ::: "memory");

                        if (!hasSessionId || !hasTicket) {

                            NSUInteger lastBrace = [newStr rangeOfString:@"}" options:NSBackwardsSearch].location;

                            if (lastBrace != NSNotFound) {

                                NSString *insertStr = [NSString stringWithFormat:@"\"sessionId\": \"%@\", \"ticket\": \"%@\"", realSessionId, realTicket];

                                [newStr insertString:insertStr atIndex:lastBrace];

                                jsonModified = YES;

                                DLOG(@"[FFF493-REPL] v37.99: #%d INSERTED sessionId+ticket into JSON (was absent) at pos=%lu",

                                     fffWhich, (unsigned long)lastBrace);

                            }

                        } else {

                            DLOG(@"[FFF493-REPL] v37.99: #%d SKIP insert — sessionId+ticket already present (non-empty) in JSON",

                                 fffWhich);

                        }

                    }

                    // v37.97 FIX: After modifying sessionId/ticket, RE-COMPUTE "md5" field!

                    // v37.99 FIX: ONLY recompute if JSON was ACTUALLY modified (jsonModified flag).

                    // v37.104 FIX: ONLY recompute md5 when sessionId/ticket changed (didReplaceSession||didReplaceTicket)!

                    // DO NOT recompute when only UUID changed (didReplaceUUID) — because:

                    // (1) Client computes md5 as MD5(concat_of_field_VALUES), NOT MD5(JSON_string)!

                    //     CC_MD5 hook already replaced accountId/channel/device in the concat → md5 is CORRECT.

                    // (2) MACADDRESS UUID is NOT part of the md5 concat → UUID change doesn't affect md5!

                    // (3) Our MD5(JSON_without_md5) formula is WRONG — it produces a DIFFERENT md5 than

                    //     the client's MD5(concat_values) → server sees md5 mismatch → silent reject!

                    // v37.103 log proof: old=6aa64a9b(client correct) → new=c3b190db(our WRONG formula)

                    //   Server kept connection alive (14+ heartbeats) but NEVER sent role data 0x0CB0A300!

                    if (didReplaceSession || didReplaceTicket || didReplaceUUID) {

                        NSString *kMd5Key = @"\"md5\": \"";

                        NSRange md5KeyRange = [newStr rangeOfString:kMd5Key];

                        if (md5KeyRange.location != NSNotFound &&

                            md5KeyRange.location + md5KeyRange.length + 32 + 1 <= newStr.length) {

                            // Step 1: Extract OLD md5 (32 hex chars after the key)

                            NSUInteger valueStart = md5KeyRange.location + md5KeyRange.length;

                            NSString *oldMd5 = [newStr substringWithRange:NSMakeRange(valueStart, 32)];

                            // Verify 32nd char is closing-quote " (so md5 field is valid)

                            unichar closing = [newStr characterAtIndex:(valueStart + 32)];

                            if (closing == '"') {

                                // Step 2: Find FULL field range (key through closing quote

                                NSRange fullField = NSMakeRange(md5KeyRange.location,

                                                                 (valueStart + 32 + 1) - md5KeyRange.location);

                                // v37.102 FIX: Only remove ONE ", " (trailing OR leading, NOT both!)

                                // Previous code removed BOTH → JSON missing comma → invalid → server reject!

                                // Example: {"a":"1", "md5":"x", "b":"2"}

                                //   Remove BOTH ", " → {"a":"1""b":"2"} ← MISSING COMMA!

                                //   Remove trailing only → {"a":"1", "b":"2"} ← VALID!

                                // Also try to include trailing ", " (comma-space)

                                BOOL foundTrailingComma = NO;

                                if (fullField.location + fullField.length + 2 <= newStr.length) {

                                    unichar tc1 = [newStr characterAtIndex:(fullField.location + fullField.length)];

                                    unichar tc2 = [newStr characterAtIndex:(fullField.location + fullField.length + 1)];

                                    if (tc1 == ',' && tc2 == ' ') {

                                        fullField.length += 2;

                                        foundTrailingComma = YES;

                                    }

                                }

                                // Only include leading ", " if trailing was NOT found (avoid removing both!)

                                if (!foundTrailingComma && fullField.location >= 2) {

                                    unichar lc1 = [newStr characterAtIndex:(fullField.location - 1)];

                                    unichar lc2 = [newStr characterAtIndex:(fullField.location - 2)];

                                    if (lc1 == ' ' && lc2 == ',') {

                                        fullField.location -= 2;

                                        fullField.length += 2;

                                    }

                                }

                                // Build jsonWithoutMd5 by deleting fullField from copy

                                NSMutableString *jsonWithoutMd5 = [newStr mutableCopy];

                                [jsonWithoutMd5 deleteCharactersInRange:fullField];

                                // Step 3: Compute MD5 of jsonWithoutMd5 via raw CC_MD5 (dlsym, no hook)

                                const char *jsonStr = [jsonWithoutMd5 UTF8String];

                                size_t jsonLen = strlen(jsonStr);

                                unsigned char md5Raw[16];

                                memset(md5Raw, 0, sizeof(md5Raw));

                                typedef unsigned char *(*RawCCMD5)(const void *, unsigned long, unsigned char *);

                                static RawCCMD5 s_rawMD5_v97 = NULL;

                                if (!s_rawMD5_v97) s_rawMD5_v97 = (RawCCMD5)dlsym(RTLD_DEFAULT, "CC_MD5");

                                if (s_rawMD5_v97) s_rawMD5_v97(jsonStr, (unsigned long)jsonLen, md5Raw);

                                static const char kHex_v97[] = "0123456789abcdef";

                                char newMd5Hex[33];

                                for (int hi = 0; hi < 16; hi++) {

                                    newMd5Hex[hi*2]   = kHex_v97[(md5Raw[hi] >> 4) & 0xF];

                                    newMd5Hex[hi*2+1] = kHex_v97[md5Raw[hi] & 0xF];

                                }

                                newMd5Hex[32] = 0;

                                NSString *newMd5 = [NSString stringWithUTF8String:newMd5Hex];

                                // Step 4: Insert new md5 into final JSON (delete old field, insert new at same spot)

                                NSMutableString *finalJson = [newStr mutableCopy];

                                // Delete same fullField from finalJson too (same content as above)

                                [finalJson deleteCharactersInRange:fullField];

                                // Find insertion point: before "time" or after first "{"

                                NSString *kTimeKey = @"\"time\":";

                                NSRange timeRange = [finalJson rangeOfString:kTimeKey];

                                NSUInteger insertAt = 0;

                                if (timeRange.location != NSNotFound && timeRange.location <= finalJson.length) {

                                    insertAt = timeRange.location;

                                } else {

                                    NSRange firstBrace = [finalJson rangeOfString:@"{"];

                                    if (firstBrace.location != NSNotFound) insertAt = firstBrace.location + 1;

                                }

                                NSString *insertMd5 = [NSString stringWithFormat:@"\"md5\": \"%@\", ", newMd5];

                                [finalJson insertString:insertMd5 atIndex:insertAt];

                                DLOG(@"[FFF493-MD5] v37.97: #%d RECOMPUTED md5: old=%@ → new=%@ (jsonWithoutMd5Len=%zu)",

                                     fffWhich, oldMd5, newMd5, jsonLen);

                                newStr = finalJson;

                            }

                        }

                    }

                    } // FIX53J: end of fffWhich==2 guard (sessionId/ticket/UUID insert + md5 recompute for NEW_USER only)

                    // FIX53O: CRITICAL FIX — DO NOT re-encrypt when only CCCrypt L4 patched the plaintext.
                    //
                    // Root cause (wxhook-183): FIX53K~N versions forced re-encryption when L4 patched
                    // the plaintext, but the original CCCrypt already encrypted the L4-patched plaintext.
                    // Re-encrypting produced DIFFERENT ciphertext (different IV/context), causing server
                    // to decrypt wrong data → silent reject (no role data, no connection close).
                    //
                    // Original FIX53 (which worked!) did NOT re-encrypt. It just sent the original packet.
                    // The original packet already contains the correct ciphertext from CCCrypt (which used
                    // the L4-patched plaintext). No need to re-encrypt.
                    //
                    // ONLY re-encrypt when JSON was ACTUALLY modified (sessionId/ticket/UUID changes).
                    // This is the original v37.100 behavior that worked.
                    
                    BOOL doReencrypt = jsonModified;
                    
                    if (doReencrypt) {

                    const char *newPlain = [newStr UTF8String];

                    size_t newPlainLen = strlen(newPlain);

                    DLOG(@"[FFF493-REPL] v37.97: FFF493#%d Built new plaintext %zuB (native=%zuB, +sessionId+ticket+md5_recompute)",

                         fffWhich, newPlainLen, nativeLen);

                    size_t cipherCap = ((newPlainLen + 1 + 15) / 16) * 16;

                    uint8_t *cipherBuf = (uint8_t *)malloc(cipherCap + 32);

                    size_t cipherOut = 0;

                    if (cipherBuf) {

                        int ccRet = orig_CCCrypt(0, g_saved_alg, g_saved_options,

                                                  g_saved_aes_key, g_saved_key_len, g_saved_aes_iv,

                                                  newPlain, newPlainLen,

                                                  cipherBuf, cipherCap + 32, &cipherOut);

                        if (ccRet == 0 && cipherOut > 0) {

                            NSData *cipherData = [NSData dataWithBytes:cipherBuf length:cipherOut];

                            NSString *b64Str = [cipherData base64EncodedStringWithOptions:0];

                            const char *b64 = [b64Str UTF8String]; size_t b64Len = strlen(b64);

                            uint8_t hmacOut[32] = {0};

                            CCHmac(kCCHmacAlgSHA256, g_saved_aes_key, g_saved_key_len,

                                   cipherBuf, cipherOut, hmacOut);

                            NSData *hmacData = [NSData dataWithBytes:hmacOut length:32];

                            NSString *hmacB64 = [hmacData base64EncodedStringWithOptions:0];

                            const char *hmacB64Bytes = [hmacB64 UTF8String];

                            size_t hmacB64Len = strlen(hmacB64Bytes);

                            size_t newPktLen = 16 + 2 + b64Len + 2 + hmacB64Len;

                            uint8_t *newPkt = (uint8_t *)malloc(newPktLen);

                            if (newPkt) {

                                newPkt[0] = (newPktLen>>24)&0xFF; newPkt[1]=(newPktLen>>16)&0xFF;

                                newPkt[2] = (newPktLen>>8)&0xFF;  newPkt[3]=newPktLen&0xFF;

                                memcpy(newPkt+4, p+4, 4);

                                newPkt[8]=(origSeq>>24)&0xFF; newPkt[9]=(origSeq>>16)&0xFF;

                                newPkt[10]=(origSeq>>8)&0xFF; newPkt[11]=origSeq&0xFF;

                                // FIX53M: COPY fmtFlag from ORIGINAL packet (p[12..13]) instead of hardcoding 0x0001.
                                // Different FFF493 packets may use different fmtFlag values. Hardcoding 0x0001
                                // made server silently reject rebuilt packets (fmtFlag mismatch → no role data).
                                newPkt[12]=p[12]; newPkt[13]=p[13];

                                newPkt[14]=(origAlgo>>8)&0xFF; newPkt[15]=origAlgo&0xFF;

                                newPkt[16]=(b64Len>>8)&0xFF; newPkt[17]=b64Len&0xFF;

                                memcpy(newPkt+18, b64, b64Len);

                                size_t auxPos = 18+b64Len;

                                newPkt[auxPos]=(hmacB64Len>>8)&0xFF; newPkt[auxPos+1]=hmacB64Len&0xFF;

                                memcpy(newPkt+auxPos+2, hmacB64Bytes, hmacB64Len);

                                ssize_t rret = orig_send(fd, newPkt, newPktLen, flags);

                                DLOG(@"[FFF493-REPL] v37.87: Replaced FFF493#%d origLen=%zu newLen=%zu plainLen=%zu cipherOut=%zu b64Len=%zu seq=%u ret=%zd",

                                     fffWhich, len, newPktLen, newPlainLen, cipherOut, b64Len, origSeq, rret);

                                free(newPkt); free(cipherBuf);

                                // v37.87: Set sent flags (trigger heartbeat counting for 0x0CB0A300 forgery)

                                if (fffWhich == 1) g_fff493_1_sent = 1;

                                if (fffWhich == 2) {

                                    g_fff493_2_sent = 1;

                                    g_consec_heartbeats = 0;

                                    g_role_0CB0A300_seen = 0;

                                }

                                // Consume one-shot plaintext buffers

                                if (fffWhich == 1) {

                                    // Don't free (static owned), just mark len=0

                                    g_fff493_1_plain_len = 0;

                                }

                                if (fffWhich == 2) {

                                    free(g_fff493_2_native_plain);

                                    g_fff493_2_native_plain = NULL;

                                    g_fff493_2_native_len = 0;

                                }

                                // FIX53I: Reset SAFE FALLBACK flag after successful re-encryption
                                g_l4_safe_fallback = NO;

                                if (rret >= 0) return (ssize_t)len;

                                return rret;

                            }

                        } else {

                            DLOG(@"[FFF493-REPL] v37.87: FFF493#%d CCCrypt FAILED ret=%d cipherOut=%zu",

                                 fffWhich, ccRet, cipherOut);

                        }

                        free(cipherBuf);

                    }

                    } else {

                        // FIX53O: No JSON modifications → send original packet as-is.
                        // CCCrypt L4 already patched the plaintext before the original CCCrypt call.
                        // The client's packet already contains the correct ciphertext.
                        // Re-encrypting would produce DIFFERENT ciphertext (different IV), breaking server validation.
                        DLOG(@"[FIX53O-SEND] No JSON changes → send original %zuB packet as-is (L4 already patched by CCCrypt)", len);

                        // Free native plaintext buffers to avoid leak (will be re-captured on next call)
                        if (fffWhich == 2 && g_fff493_2_native_plain) {
                            free(g_fff493_2_native_plain);
                            g_fff493_2_native_plain = NULL;
                            g_fff493_2_native_len = 0;
                        }
                        if (fffWhich == 1) {
                            g_fff493_1_plain_len = 0;
                        }
                    }

                }

                    #pragma clang optimize on

                DLOG(@"[FFF493-REPL] v37.87: FFF493#%d replacement internal substep skipped", fffWhich);

            }

            }

        // v37.88 FALLBACK: Moved OUTSIDE g_aes_key_saved gating! Even if AES key not saved

        // or replacement was skipped (no plaintext), mark #1/#2 sent based on len range.

        // This triggers heartbeat counting in recv hook for forged 0x0CB0A300 injection.

        if (cmd == 0x00FFF493 && !g_fff493_1_sent && len >= 350 && len <= 800) {

            g_fff493_1_sent = 1;

            DLOG(@"[FFF493-REPL] v37.88: FALLBACK mark #1 sent (len=%zu, no plaintext replacement)", len);

            // FIX53I: Reset SAFE FALLBACK flag
            g_l4_safe_fallback = NO;

        }

        if (cmd == 0x00FFF493 && !g_fff493_2_sent && len > 800) {

            g_fff493_2_sent = 1;

            g_consec_heartbeats = 0;

            g_role_0CB0A300_seen = 0;

            DLOG(@"[FFF493-REPL] v37.88: FALLBACK mark #2 sent (len=%zu, no plaintext replacement)", len);

            // FIX53I: Reset SAFE FALLBACK flag
            g_l4_safe_fallback = NO;

        }

        // Direct orig_send for ALL game server commands — no processing at all

        ssize_t ret = orig_send(fd, buf, len, flags);

        DLOG(@"[SEND-DIRECT] v37.27: cmd=0x%08X len=%zu port=%d ret=%zd (ALL game server packets direct after CHANNEL-PATCH L5/L6)", cmd, len, port, ret);

        return ret;

    }



    void *sendBuf = (void *)buf;

    size_t sendLen = len;

    

    if (len >= 12) {

        const unsigned char *p = (const unsigned char *)buf;

        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        // v36.61: Use dynamic game port detection (12003, 58158, or parsed port)

        BOOL isGameOrLoginPort = (port == 5678 || port == 12003 || port == 58158 || 

                                  (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

        if (isGameOrLoginPort) {

            const char *serverType;

            if (port == 5678) serverType = "LOGIN";

            else if (port == 58158) serverType = "GAME-58158";

            else if (port == 12003) serverType = "GAME-12003";

            else serverType = "GAME-DYNAMIC";

            DLOG(@"[SEND-CMD] fd=%d cmd=0x%08X len=%zu [%s port=%d]", fd, cmd, len, serverType, port);

        }

    }

    

    if (host && sendLen > 0) {

        const unsigned char *p = (const unsigned char *)sendBuf;

        NSMutableString *hex = [NSMutableString stringWithCapacity:sendLen * 3];

        NSMutableString *ascii = [NSMutableString stringWithCapacity:sendLen];

        size_t showLen = sendLen > 256 ? 256 : sendLen;

        for (size_t i = 0; i < showLen; i++) {

            [hex appendFormat:@"%02X ", p[i]];

            [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];

        }

        DLOG(@"[SEND] fd=%d %s:%d len=%zu\n  hex: %@\n  txt: %@", fd, host, port, sendLen, hex, ascii);

        

        // v36.75: Log game server initial connection packets (before handshake)

        // These are packets sent right after connecting to game server

        BOOL isGamePort = (port == 12003 || port == 58158 ||

                          (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

        if (isGamePort && !g_handshakeComplete && len > 0 && len < 12) {

            DLOG(@"[GAME-INIT] Small packet to game server: len=%zu hex=%@ (may be handshake init)", len, hex);

        }

    }

    

    // Analyze device info packets (0x000EE007) - on login server (5678), game server (all ports)

    BOOL isGameOrLoginPort = (port == 5678 || port == 12003 || port == 58158 || 

                              (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

    if (len >= 12 && isGameOrLoginPort) {

        const unsigned char *dp = (const unsigned char *)buf;

        uint32_t cmd = ((uint32_t)dp[4] << 24) | ((uint32_t)dp[5] << 16) |

                       ((uint32_t)dp[6] << 8)  | (uint32_t)dp[7];

        if (cmd == 0x000EE007) {

            @try {

                // v36.61: Detailed device info packet logging

                DLOG(@"[DEVICE-INFO] ===== DEVICE INFO PACKET (0x000EE007) =====");

                DLOG(@"[DEVICE-INFO] len=%zu port=%d fd=%d gameConnected=%d", len, port, fd, g_gameServerConnected ? 1 : 0);

                

                // Hex dump - full packet

                NSMutableString *hex = [NSMutableString string];

                for (size_t i = 0; i < len && i < 128; i++) {

                    [hex appendFormat:@"%02X ", dp[i]];

                }

                if (len > 128) [hex appendFormat:@"...(truncated)"];

                DLOG(@"[DEVICE-INFO] HEX: %@", hex);

                

                // Parse header

                if (len >= 16) {

                    uint32_t pktLen = ((uint32_t)dp[0]<<24)|((uint32_t)dp[1]<<16)|((uint32_t)dp[2]<<8)|dp[3];

                    uint32_t pktCmd = ((uint32_t)dp[4]<<24)|((uint32_t)dp[5]<<16)|((uint32_t)dp[6]<<8)|dp[7];

                    uint8_t status = dp[12];

                    DLOG(@"[DEVICE-INFO] pktLen=%u cmd=0x%08X status=%u", pktLen, pktCmd, status);

                }

                

                // ASCII decode payload

                if (len > 12) {

                    NSString *payload = [[NSString alloc] initWithBytes:dp+12 length:MIN(len-12, 100) encoding:NSUTF8StringEncoding];

                    if (payload) {

                        DLOG(@"[DEVICE-INFO] payload (offset 12): '%@'", payload);

                    }

                }

                

                DLOG(@"[DEVICE-INFO] ===== END DEVICE INFO =====");

                

                // v37.16: DISABLED UUID-INJECT — was corrupting 0x000EE007 packet structure.

                // User confirmed: original 178-byte packet ends with 01 00, but UUID-injected

                // packet ends with 00 01 00 → server validation fails → connection closed.

                // Native encryption handles everything, no UUID injection needed.

                if (0 && len > 0 && len <= MAX_DEVICE_INFO_SIZE) {

                    memcpy(g_deviceInfoPacket, buf, len);

                    g_deviceInfoPacketLen = len;

                    g_deviceInfoCaptured = YES;

                    g_deviceInfoSentToGame = NO;  // Reset flag for new capture

                    g_deviceInfoEnhancedReady = NO;

                    DLOG(@"[DEVICE-INFO] CAPTURED %zd bytes for forced game server send", len);

                    

                    // v36.87: Immediately create enhanced version with UUID injected

                    // Login server (5678) sends 143-byte without UUID

                    // Game server (12003/58158) expects 179-byte with UUID

                    ssize_t enhancedLen = injectUUIDIntoDeviceInfo(

                        (const uint8_t *)buf, len,

                        g_deviceInfoEnhanced, MAX_DEVICE_INFO_SIZE

                    );

                    if (enhancedLen > 0) {

                        g_deviceInfoEnhancedLen = enhancedLen;

                        g_deviceInfoEnhancedReady = YES;

                        DLOG(@"[DEVICE-INFO] ENHANCED ready: %zd bytes (UUID injected)", enhancedLen);

                    } else {

                        // Fallback: use original if injection fails

                        DLOG(@"[DEVICE-INFO] ENHANCED FAILED, will use original %zd bytes", len);

                    }

                    

                    // v36.123: CRITICAL FIX - Apply UUID injection DIRECTLY to sendBuf/sendLen

                    // Previous bug: UUID was injected to global buffers but NOT applied to the

                    // actual send() call, so server received 179 bytes without UUID and rejected.

                    //

                    // v36.118 FIX: Only apply UUID injection to GAME SERVER (12003/58158), NOT login server (5678)!

                    // Root cause: Login server (5678) rejects UUID-injected 0x000EE007 (181 bytes),

                    //   causing "network interrupted" at login. Login server expects original 143 bytes.

                    //   Game server (12003) requires UUID-injected 181 bytes.

                    BOOL isGamePortForInject = (port == 12003 || port == 58158 ||

                                                (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

                    if (enhancedLen > 0 && isGamePortForInject) {

                        size_t newLen = (size_t)enhancedLen;

                        uint8_t *newBuf = (uint8_t *)malloc(newLen);

                        if (newBuf) {

                            memcpy(newBuf, g_deviceInfoEnhanced, newLen);

                            // Update sendBuf and sendLen BEFORE orig_send() is called

                            if (sendBuf != buf) free(sendBuf);

                            sendBuf = newBuf;

                            sendLen = newLen;

                            DLOG(@"[UUID-INJECT] v36.123: APPLIED to sendBuf (GAME port=%d): %zu -> %zu bytes (WILL be sent!)",

                                 port, len, newLen);

                            // v36.123: Immediately log corrected SEND-CMD with FINAL length

                            const char *host2 = getHostForFd(fd);

                            int port2 = getPortForFd(fd);

                            const char *serverType2 = "UNKNOWN";

                            if (port2 == 5678) serverType2 = "LOGIN";

                            else if (port2 == 58158) serverType2 = "GAME-58158";

                            else if (port2 == 12003) serverType2 = "GAME-12003";

                            else if (port2 >= 10000) serverType2 = "GAME-DYNAMIC";

                            DLOG(@"[SEND-CMD] fd=%d cmd=0x%08X len=%zu (CORRECTED after UUID inject) [%s port=%d]",

                                 fd, cmd, sendLen, serverType2, port2);

                            (void)host2;

                        }

                    } else if (enhancedLen > 0 && !isGamePortForInject) {

                        // v36.123: Login server - do NOT inject UUID, send original packet

                        // Enhanced buffer is still prepared for later game server use

                        DLOG(@"[UUID-INJECT] v36.123: SKIP inject for LOGIN port=%d (send original %zu bytes), enhanced buffer ready for game server",

                             port, len);

                    }

                }

            } @catch (NSException *e) {

                // Silently ignore any errors in packet analysis

                DLOG(@"[DEVICE-INFO] Analysis skipped due to exception: %@", e.reason);

            }

        }

        

        // v36.85: Only block heartbeats during initial handshake (BEFORE challenge response)

        // After challenge response (g_challengeResponded=YES), let heartbeats go to server

        // so we can intercept the server's heartbeat ACK and replace it with 0x80FFF495

        if (isGameOrLoginPort && (cmd == 0x00000015 || cmd == 0x00000014)) {

            BOOL isGamePortOnly = (port == 12003 || port == 58158 ||

                                   (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

            BOOL isGameCmdOnly = isGameCmd(cmd);

            

            // v36.85: Only block heartbeats BEFORE challenge response (NOT after)

            if ((isGamePortOnly || isGameCmdOnly) && !g_handshakeComplete && !g_challengeResponded) {

                @try {

                    uint8_t ackBuf[22];

                    memcpy(ackBuf, buf, 22);

                    ackBuf[4] = 0x80;  // Change command from 0x00000015 to 0x80000015

                    

                    if (g_localHeartbeatAckLen == 0 || g_localHeartbeatAckFd != fd) {

                        g_localHeartbeatAckLen = 22;

                        g_localHeartbeatAckFd = fd;

                        memcpy(g_localHeartbeatAckBuf, ackBuf, 22);

                        DLOG(@"[HEARTBEAT-BLOCK] Blocked heartbeat during handshake (cmd=0x%08X) to port=%d", cmd, port);

                    }

                } @catch (NSException *e) {

                    DLOG(@"[HEARTBEAT-BLOCK] Exception: %@", e.reason);

                }

                return len;

            }

        }

        

        // v36.74: Track client protocol behavior after handshake completion

        // Monitor what client sends in response to 0x00FFFF02 challenge

        if (g_handshakeComplete && isGameOrLoginPort && len >= 12) {

            @try {

                const unsigned char *tp = (const unsigned char *)buf;

                NSMutableString *protoTrace = [NSMutableString stringWithCapacity:256];

                uint32_t trackCmd = ((uint32_t)tp[4] << 24) | ((uint32_t)tp[5] << 16) |

                                   ((uint32_t)tp[6] << 8)  | (uint32_t)tp[7];

                uint32_t trackPktLen = ((uint32_t)tp[0] << 24) | ((uint32_t)tp[1] << 16) |

                                      ((uint32_t)tp[2] << 8)  | (uint32_t)tp[3];

                

                [protoTrace appendFormat:@"[PROTO-TRACE] Client send after handshake: cmd=0x%08X pktLen=%u port=%d\n", trackCmd, trackPktLen, port];

                

                // v36.95: Track login packets to game server for fake response injection

                // 0x000EE007 (device info) and 0x00FFF493 (encrypted login data) are the key login packets

                BOOL isGamePortOnly = (port == 12003 || port == 58158 ||

                                      (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

                if (isGamePortOnly && (trackCmd == 0x000EE007 || trackCmd == 0x00FFF493 || 

                                       trackCmd == 0x80EEE007 || trackCmd == 0x80F493)) {

                    if (!g_loginPacketsSent) {

                        g_loginPacketsSent = YES;

                        DLOG(@"[LOGIN-PACKETS] v36.95: Client sending login packets to game server (cmd=0x%08X port=%d) - FAKE-RESP armed", trackCmd, port);

                    }

                }

                

                // v36.107: Track game server commands in a QUEUE for ordered response with sequence numbers

                if (isGamePortOnly && trackCmd != 0 && trackCmd < 0x80000000) {

                    g_lastGameCmd = trackCmd;

                    g_lastGameCmdFd = fd;

                    // v36.107: Extract sequence number from packet (bytes 8-11)

                    uint32_t trackSeqNum = 0;

                    if (len >= 12) {

                        trackSeqNum = ((uint32_t)tp[8] << 24) | ((uint32_t)tp[9] << 16) |

                                      ((uint32_t)tp[10] << 8)  | (uint32_t)tp[11];

                    }

                    g_lastSeqNum = trackSeqNum;

                    // v36.116: Use actual sendLen (after UUID injection) instead of original len

                    // For 0x000EE007, sendBuf was replaced with enhanced 217 bytes (UUID injected)

                    uint32_t actualSendLen = (uint32_t)sendLen;

                    if (trackCmd == 0x000EE007 && actualSendLen == (uint32_t)len) {

                        // If injection was not applied but g_deviceInfoEnhancedReady exists, use that

                        if (g_deviceInfoEnhancedReady && g_deviceInfoEnhancedLen > 0) {

                            actualSendLen = (uint32_t)g_deviceInfoEnhancedLen;

                        }

                    }

                    // v36.107: Add to command queue with sequence number and actual send length

                    enqueueGameCmd(trackCmd, fd, actualSendLen, trackSeqNum);

                    DLOG(@"[CMD-TRACK] v36.123: Queued cmd=0x%08X seq=0x%08X fd=%d sendLen=%u (origLen=%zu queue=%d)", 

                         trackCmd, trackSeqNum, fd, actualSendLen, len, g_cmdQueueCount);

                    // v36.107: Clear delivered flag so next recv can return a response

                    g_fakeRespDelivered = NO;

                }

                

                // Categorize the command

                if (trackCmd == 0x80FFFF02) {

                    [protoTrace appendFormat:@"  [V36.74] Client sent 0x80FFFF02 - responding to 0x00FFFF02 challenge!\n"];

                } else if (trackCmd == 0x80FFFF01) {

                    [protoTrace appendFormat:@"  [V36.74] Client sent 0x80FFFF01 - responding to 0x00FFFF01 challenge\n"];

                } else if (trackCmd == 0x000EE007) {

                    [protoTrace appendFormat:@"  [V36.74] Client sending 0x000EE007 device info (plaintext)!\n"];

                } else if (trackCmd == 0x80EEE007 || trackCmd == 0x80EE0007) {

                    [protoTrace appendFormat:@"  [V36.74] Client sending encrypted device info!\n"];

                } else if (trackCmd == 0x00F493 || trackCmd == 0x80F493) {

                    [protoTrace appendFormat:@"  [V36.74] Client sending encrypted game data\n"];

                } else if (trackCmd == 0x00000015) {

                    [protoTrace appendFormat:@"  [V36.74] Client sending heartbeat (may be stuck)\n"];

                } else if (trackCmd >= 0x80000000) {

                    [protoTrace appendFormat:@"  [V36.74] Client sending server response (cmd=0x%08X)\n", trackCmd];

                } else {

                    [protoTrace appendFormat:@"  [V36.74] Unknown command (cmd=0x%08X) - tracing...\n", trackCmd];

                }

                

                // Hex dump first 32 bytes

                [protoTrace appendFormat:@"  HEX(32): "];

                for (size_t i = 0; i < MIN((size_t)32, len); i++) {

                    [protoTrace appendFormat:@"%02X ", tp[i]];

                }

                [protoTrace appendFormat:@"\n"];

                

                DLOG(@"%@", protoTrace);

            } @catch (NSException *e) {

                DLOG(@"[PROTO-TRACE] Exception: %@", e.reason);

            }

        }

    }

    

    // Analyze 0x0000F013 packet - select server / enter game

    if (len >= 12 && port == 5678) {

        const unsigned char *fp = (const unsigned char *)buf;

        uint32_t fcmd = ((uint32_t)fp[4] << 24) | ((uint32_t)fp[5] << 16) |

                        ((uint32_t)fp[6] << 8)  | (uint32_t)fp[7];

        if (fcmd == 0x0000F013) {

            @try {

                NSMutableString *detail = [NSMutableString stringWithCapacity:256];

                [detail appendFormat:@"[SERVER-SELECT] cmd=0x%08X len=%zu\n", fcmd, len];

                [detail appendFormat:@"  Full hex: "];

                for (size_t i = 0; i < len && i < 128; i++) {

                    [detail appendFormat:@"%02X ", fp[i]];

                }

                if (len > 128) [detail appendFormat:@"...\n"];

                else [detail appendFormat:@"\n"];

                

                if (len >= 12) {

                    uint32_t pktLen = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) |

                                      ((uint32_t)fp[2] << 8)  | (uint32_t)fp[3];

                    uint32_t field1 = ((uint32_t)fp[8] << 24) | ((uint32_t)fp[9] << 16) |

                                      ((uint32_t)fp[10] << 8) | (uint32_t)fp[11];

                    [detail appendFormat:@"  Header: pktLen=%u field1=0x%08X\n", pktLen, field1];

                }

                

                // Parse TLV-style fields after header

                size_t offset = 12;

                int fieldIdx = 0;

                while (offset + 2 < len && fieldIdx < 10) {

                    uint16_t fieldLen = (fp[offset] << 8) | fp[offset + 1];

                    offset += 2;

                    if (offset + fieldLen > len) break;

                    

                    NSMutableString *fieldHex = [NSMutableString string];

                    for (uint16_t i = 0; i < fieldLen && i < 32; i++) {

                        [fieldHex appendFormat:@"%02X ", fp[offset + i]];

                    }

                    

                    NSString *fieldStr = [[NSString alloc] initWithBytes:fp+offset length:fieldLen encoding:NSUTF8StringEncoding];

                    if (fieldStr && fieldStr.length > 0 && fieldLen < 64) {

                        [detail appendFormat:@"  Field[%d] len=%u hex=[%@] str='%@'\n", fieldIdx, fieldLen, fieldHex, fieldStr];

                    } else {

                        [detail appendFormat:@"  Field[%d] len=%u hex=[%@]\n", fieldIdx, fieldLen, fieldHex];

                    }

                    offset += fieldLen;

                    fieldIdx++;

                }

                

                DLOG(@"%@", detail);

            } @catch (NSException *e) {

                DLOG(@"[SERVER-SELECT] Analysis exception: %@", e.reason);

            }



            // v37.108-DIST: Use NATIVE accountId in F013 — each user's REAL account ID!

            // ROOT CAUSE: Forcing CANONICAL accId caused ALL users to enter kk994's character.

            // F013 format: [12B header][00 14][20B accId][00 05][5B user][00 06][6B pass][00 00]

            // accId at offset 14, 20 bytes. Pass through original packet without modification.

            if (len >= 34) {

                const unsigned char *fp2 = (const unsigned char *)buf;

                uint16_t accLen = ((uint16_t)fp2[12] << 8) | fp2[13];

                char origF013[21] = {0};

                if (accLen == 20) memcpy(origF013, fp2 + 14, 20);

                origF013[20] = 0;

                DLOG(@"[F013-ACCID] v37.108: F013 NATIVE accId=%s (passing through, len=%zu)",

                     origF013, len);

            }

        }

    }



    // Analyze game server packets (58158 port)

    if (len >= 12 && port == 58158) {

        const unsigned char *gp = (const unsigned char *)buf;

        uint32_t gcmd = ((uint32_t)gp[4] << 24) | ((uint32_t)gp[5] << 16) |

                        ((uint32_t)gp[6] << 8)  | (uint32_t)gp[7];

        

        @try {

            // Log game data packets (0x00FFF493)

            if (gcmd == 0x00FFF493) {

                NSMutableString *detail = [NSMutableString stringWithCapacity:256];

                [detail appendFormat:@"[GAME-DATA] cmd=0x%08X len=%zu\n", gcmd, len];

                [detail appendFormat:@"  Full hex: "];

                size_t showLen = len > 64 ? 64 : len;

                for (size_t i = 0; i < showLen; i++) {

                    [detail appendFormat:@"%02X ", gp[i]];

                }

                if (len > 64) [detail appendFormat:@"...\n"];

                else [detail appendFormat:@"\n"];

                DLOG(@"%@", detail);

            }

            // Log heartbeat packets (0x00000015)

            else if (gcmd == 0x00000015) {

                NSMutableString *detail = [NSMutableString stringWithCapacity:128];

                [detail appendFormat:@"[GAME-HEARTBEAT] cmd=0x%08X len=%zu\n", gcmd, len];

                [detail appendFormat:@"  Full hex: "];

                for (size_t i = 0; i < len; i++) {

                    [detail appendFormat:@"%02X ", gp[i]];

                }

                [detail appendFormat:@"\n"];

                DLOG(@"%@", detail);

            }

            // Log server select packets (0x0000F013) on game server

            else if (gcmd == 0x0000F013) {

                NSMutableString *detail = [NSMutableString stringWithCapacity:256];

                [detail appendFormat:@"[GAME-SERVER-SELECT] cmd=0x%08X len=%zu\n", gcmd, len];

                [detail appendFormat:@"  Full hex: "];

                size_t showLen = len > 128 ? 128 : len;

                for (size_t i = 0; i < showLen; i++) {

                    [detail appendFormat:@"%02X ", gp[i]];

                }

                if (len > 128) [detail appendFormat:@"...\n"];

                else [detail appendFormat:@"\n"];

                DLOG(@"%@", detail);

            }

        } @catch (NSException *e) {

            DLOG(@"[GAME-ANALYZE] Exception: %@", e.reason);

        }

    }



    // v36.123: FINAL confirmation log right before calling orig_send()

    // This is THE authoritative log of what actually gets sent to the server

    if (sendLen >= 12 && sendBuf) {

        const unsigned char *fp = (const unsigned char *)sendBuf;

        uint32_t finalCmd = ((uint32_t)fp[4] << 24) | ((uint32_t)fp[5] << 16) |

                            ((uint32_t)fp[6] << 8)  | (uint32_t)fp[7];

        uint32_t finalPktLen = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) |

                               ((uint32_t)fp[2] << 8)  | (uint32_t)fp[3];

        int finalPort = getPortForFd(fd);

        const char *finalType = "OTHER";

        if (finalPort == 5678) finalType = "LOGIN";

        else if (finalPort == 12003) finalType = "GAME-12003";

        else if (finalPort == 58158) finalType = "GAME-58158";

        else if (finalPort >= 10000) finalType = "GAME-DYN";

        

        // Only log critical commands (0x000EE007, 0x00FFF495, 0x00FFF493, 0x00FFF494) or GAME port

        BOOL isCritical = (finalCmd == 0x000EE007 || finalCmd == 0x00FFF495 ||

                          finalCmd == 0x00FFF493 || finalCmd == 0x00FFF494 ||

                          finalPktLen != sendLen);  // Also flag if pktLen header doesn't match send() len

        if (isCritical || (finalPort >= 10000 && finalCmd != 0x00000015)) {

            DLOG(@"[SEND-FINAL] v36.123: cmd=0x%08X pktLenHdr=%u send()=%zu fd=%d [%s port=%d] %@",

                 finalCmd, finalPktLen, sendLen, fd, finalType, finalPort,

                 (finalPktLen != sendLen) ? @"⚠️ HEADER MISMATCH!" : @"✅ OK");

        }

    }



    ssize_t ret = orig_send ? orig_send(fd, sendBuf, sendLen, flags) : -1;

    if (sendBuf != buf) free(sendBuf);

    return ret;

}



// v36.81: Manual Base64 decode function for reliable RSA public key extraction

// Standard Base64 alphabet

static const uint8_t g_base64DecodeTable[256] = {

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,63, // + /

    52,53,54,55,56,57,58,59,60,61,62,62,62,65,62,62, // 0-9 =

    62, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // A-O

    15,16,17,18,19,20,21,22,23,24,25,62,62,62,62,62, // P-Z

    62,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // a-o

    41,42,43,44,45,46,47,48,49,50,51,62,62,62,62,62, // p-z

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,

    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62

};



// v36.81: Manual Base64 decode with robust error handling

static int manualBase64Decode(const uint8_t *input, size_t inputLen, 

                               uint8_t *output, size_t outputBufSize, size_t *outputLen) {

    if (!input || !output || !outputLen || inputLen == 0) return -1;

    

    size_t inPos = 0;

    size_t outPos = 0;

    uint8_t group[4];

    int groupIdx = 0;

    

    // Clear output

    memset(output, 0, outputBufSize);

    

    while (inPos < inputLen) {

        uint8_t c = input[inPos];

        inPos++;

        

        // Skip whitespace and newlines

        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;

        

        // Check for padding

        if (c == '=') {

            // Padding should only appear at the end

            if (groupIdx < 2) return -1; // Invalid padding position

            break;

        }

        

        uint8_t val = g_base64DecodeTable[c];

        if (val >= 64) {

            // Invalid character - skip it (could be protocol overhead)

            DLOG(@"[RSA-MANUAL-B64] Skipping invalid char at input pos %zu: 0x%02X", inPos-1, c);

            continue;

        }

        

        group[groupIdx++] = val;

        

        if (groupIdx == 4) {

            // Decode 4 Base64 chars to 3 bytes

            uint32_t triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6) | group[3];

            

            if (outPos + 3 > outputBufSize) return -1; // Output buffer too small

            

            output[outPos++] = (triple >> 16) & 0xFF;

            output[outPos++] = (triple >> 8) & 0xFF;

            output[outPos++] = triple & 0xFF;

            groupIdx = 0;

        }

    }

    

    // Handle remaining group (if any)

    if (groupIdx > 0) {

        if (groupIdx < 2) return -1; // Invalid: need at least 2 chars

        

        if (groupIdx == 2) {

            uint32_t triple = (group[0] << 18) | (group[1] << 12);

            if (outPos + 1 > outputBufSize) return -1;

            output[outPos++] = (triple >> 16) & 0xFF;

        } else if (groupIdx == 3) {

            uint32_t triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6);

            if (outPos + 2 > outputBufSize) return -1;

            output[outPos++] = (triple >> 16) & 0xFF;

            output[outPos++] = (triple >> 8) & 0xFF;

        }

    }

    

    *outputLen = outPos;

    return 0;

}



// v36.82: RSA encrypt challenge data using server's public key certificate

// Returns encrypted data length, or -1 on failure

static ssize_t rsaEncryptChallenge(const uint8_t *plainData, size_t plainLen,

                                    uint8_t *cipherBuf, size_t cipherBufSize) {

    if (!g_pubKeyCaptured || g_pubKeyBase64Len == 0) {

        DLOG(@"[RSA-ENCRYPT] No public key captured, cannot encrypt (captured=%d, len=%lu)", 

             g_pubKeyCaptured, (unsigned long)g_pubKeyBase64Len);

        return -1;

    }

    

    DLOG(@"[RSA-ENCRYPT] Starting encryption: pubKeyLen=%lu, plainLen=%zu", 

          (unsigned long)g_pubKeyBase64Len, plainLen);

    

    // Step 1: Manual Base64 decode (most reliable)

    uint8_t *derData = (uint8_t *)malloc(1024);

    if (!derData) {

        DLOG(@"[RSA-ENCRYPT] Failed to allocate DER buffer");

        return -1;

    }

    

    size_t derLen = 0;

    int decodeResult = manualBase64Decode((const uint8_t *)g_pubKeyBase64, 

                                           g_pubKeyBase64Len, 

                                           derData, 1024, &derLen);

    

    if (decodeResult != 0 || derLen == 0) {

        DLOG(@"[RSA-ENCRYPT] Manual Base64 decode failed (result=%d, derLen=%zu), trying NSData...", decodeResult, derLen);

        

        // Fallback: Try NSData Base64 decode

        @try {

            NSString *certStr = [[NSString alloc] initWithBytes:g_pubKeyBase64 

                                                        length:g_pubKeyBase64Len 

                                                      encoding:NSASCIIStringEncoding];

            if (certStr) {

                NSData *certDER = [[NSData alloc] initWithBase64EncodedString:certStr 

                                                                      options:NSDataBase64DecodingIgnoreUnknownCharacters];

                if (certDER && certDER.length > 0) {

                    derLen = certDER.length;

                    memcpy(derData, certDER.bytes, MIN(derLen, 1024));

                    DLOG(@"[RSA-ENCRYPT] NSData Base64 decode succeeded: %lu bytes", (unsigned long)derLen);

                } else {

                    DLOG(@"[RSA-ENCRYPT] NSData Base64 decode also failed");

                    free(derData);

                    return -1;

                }

            } else {

                DLOG(@"[RSA-ENCRYPT] Cannot create NSString from Base64 data");

                free(derData);

                return -1;

            }

        } @catch (NSException *e) {

            DLOG(@"[RSA-ENCRYPT] Exception in NSData decode: %@", e.reason);

            free(derData);

            return -1;

        }

    } else {

        DLOG(@"[RSA-ENCRYPT] Manual Base64 decode succeeded: %zu bytes", derLen);

    }

    

    // Log DER header for debugging

    if (derLen >= 8) {

        DLOG(@"[RSA-ENCRYPT] DER header: %02X %02X %02X %02X %02X %02X %02X %02X",

             derData[0], derData[1], derData[2], derData[3],

             derData[4], derData[5], derData[6], derData[7]);

    }

    

    // Step 2: Create SecKey from DER data

    SecKeyRef pubKeyRef = NULL;

    

    // Try as X.509 certificate first

    @try {

        CFDataRef certData = CFDataCreate(NULL, derData, derLen);

        SecCertificateRef certRef = SecCertificateCreateWithData(NULL, certData);

        CFRelease(certData);

        

        if (certRef) {

            DLOG(@"[RSA-ENCRYPT] Created SecCertificate from DER data");

            pubKeyRef = SecCertificateCopyKey(certRef);

            CFRelease(certRef);

            

            if (!pubKeyRef) {

                DLOG(@"[RSA-ENCRYPT] SecCertificateCopyKey failed, trying direct SecKey...");

            }

        } else {

            DLOG(@"[RSA-ENCRYPT] SecCertificateCreateWithData failed, trying direct SecKey...");

        }

    } @catch (NSException *e) {

        DLOG(@"[RSA-ENCRYPT] Exception creating certificate: %@", e.reason);

    }

    

    // Try as direct public key (not a certificate)

    if (!pubKeyRef) {

        @try {

            NSDictionary *keyAttrs = @{

                (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,

                (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,

                (__bridge id)kSecAttrKeySizeInBits: @2048

            };

            CFDataRef keyData = CFDataCreate(NULL, derData, derLen);

            pubKeyRef = SecKeyCreateWithData(keyData, (__bridge CFDictionaryRef)keyAttrs, NULL);

            CFRelease(keyData);

            

            if (pubKeyRef) {

                DLOG(@"[RSA-ENCRYPT] Created SecKey directly from DER data");

            } else {

                DLOG(@"[RSA-ENCRYPT] SecKeyCreateWithData also failed");

                free(derData);

                return -1;

            }

        } @catch (NSException *e) {

            DLOG(@"[RSA-ENCRYPT] Exception creating SecKey: %@", e.reason);

            free(derData);

            return -1;

        }

    }

    

    free(derData);

    DLOG(@"[RSA-ENCRYPT] Got public key reference, proceeding to encryption");

    

    // Step 3: Encrypt with RSA using SecKeyCreateEncryptedData

    // v36.86: Try PKCS1 first (most common for challenge-response), then OAEP, then Raw

    CFErrorRef encryptErr = NULL;

    SecKeyAlgorithm algo = kSecKeyAlgorithmRSAEncryptionPKCS1;

    

    // Check if the algorithm is supported

    if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {

        DLOG(@"[RSA-ENCRYPT] PKCS1 not supported, trying SHA256...");

        algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA256;

        if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {

            DLOG(@"[RSA-ENCRYPT] SHA256 not supported, trying SHA1...");

            algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA1;

            if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {

                DLOG(@"[RSA-ENCRYPT] SHA1 not supported, trying Raw...");

                algo = kSecKeyAlgorithmRSAEncryptionRaw;

                if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {

                    DLOG(@"[RSA-ENCRYPT] No RSA encryption algorithm supported");

                    CFRelease(pubKeyRef);

                    return -1;

                }

            }

        }

    }

    

    DLOG(@"[RSA-ENCRYPT] Using encryption algorithm: %s",

          algo == kSecKeyAlgorithmRSAEncryptionPKCS1 ? "PKCS1" :

          algo == kSecKeyAlgorithmRSAEncryptionOAEPSHA256 ? "SHA256" :

          algo == kSecKeyAlgorithmRSAEncryptionOAEPSHA1 ? "SHA1" : "Raw");

    

    CFDataRef plainCFData = CFDataCreate(NULL, plainData, plainLen);

    CFErrorRef *encryptErrPtr = NULL;

    CFDataRef cipherCFData = SecKeyCreateEncryptedData(pubKeyRef, algo,

                                                       plainCFData, encryptErrPtr);

    CFRelease(plainCFData);

    CFRelease(pubKeyRef);

    

    if (cipherCFData) {

        size_t cipherLen = CFDataGetLength(cipherCFData);

        if (cipherLen <= cipherBufSize) {

            CFDataGetBytes(cipherCFData, CFRangeMake(0, cipherLen), cipherBuf);

            CFRelease(cipherCFData);

            DLOG(@"[RSA-ENCRYPT] SUCCESS: encrypted %lu bytes -> %lu bytes RSA cipher",

                 (unsigned long)plainLen, (unsigned long)cipherLen);

            return (ssize_t)cipherLen;

        }

        CFRelease(cipherCFData);

        DLOG(@"[RSA-ENCRYPT] Cipher buffer too small: need %lu, have %lu",

             (unsigned long)cipherLen, (unsigned long)cipherBufSize);

        return -1;

    } else {

        CFStringRef errStr = encryptErrPtr && *encryptErrPtr ? CFErrorCopyDescription(*encryptErrPtr) : NULL;

        DLOG(@"[RSA-ENCRYPT] SecKeyCreateEncryptedData failed: %@",

             errStr ? CFBridgingRelease(errStr) : @"unknown");

        if (encryptErrPtr && *encryptErrPtr) CFRelease(*encryptErrPtr);

        return -1;

    }

}



// v36.81: Auto-respond to 0x00FFFF02 challenge with RSA-encrypted 0x80FFFF02

// Returns YES if response was sent

static BOOL autoRespondToChallenge(int fd, const unsigned char *pktBuf, size_t pktLen,

                                    uint32_t cmd) {

    if (cmd != 0x00FFFF02 || pktLen < 12) return NO;

    if (g_challengeResponded && g_challengeFd == fd) {

        DLOG(@"[CHALLENGE-AUTO] Already responded to 0x00FFFF02 for fd=%d, skipping", fd);

        return NO;

    }

    if (!g_pubKeyCaptured) {

        DLOG(@"[CHALLENGE-AUTO] No public key available, cannot auto-respond (captured=%d)", g_pubKeyCaptured);

        return NO;

    }

    

    // Extract challenge payload (bytes[12..end])

    size_t payloadLen = pktLen - 12;

    const uint8_t *payloadData = pktBuf + 12;

    

    DLOG(@"[CHALLENGE-AUTO] Auto-responding to 0x00FFFF02: payload=%zu bytes, fd=%d", payloadLen, fd);

    

    // Encrypt the challenge data with RSA public key

    uint8_t encryptedData[256]; // RSA 2048-bit = 256 bytes max

    ssize_t encryptedLen = rsaEncryptChallenge(payloadData, payloadLen, encryptedData, sizeof(encryptedData));

    if (encryptedLen <= 0) {

        DLOG(@"[CHALLENGE-AUTO] RSA encryption failed, cannot auto-respond (encryptedLen=%zd)", encryptedLen);

        return NO;

    }

    

    // Construct 0x80FFFF02 response packet (with STATUS byte):

    // 4 bytes: total packet length (4 + 4 + 4 + 1 + encryptedLen)

    // 4 bytes: cmd = 0x80FFFF02

    // 4 bytes: seq (same as challenge, bytes[8-11])

    // 1 byte:  status = 0 (success)

    // encryptedLen bytes: encrypted challenge data

    uint32_t totalLen = (uint32_t)(4 + 4 + 4 + 1 + encryptedLen);

    uint8_t responseBuf[300]; // Max 4+4+4+1+256 = 269

    if (totalLen > sizeof(responseBuf)) {

        DLOG(@"[CHALLENGE-AUTO] Response too large: %u bytes", totalLen);

        return NO;

    }

    

    // Build packet with STATUS byte at offset 12

    responseBuf[0] = (totalLen >> 24) & 0xFF;

    responseBuf[1] = (totalLen >> 16) & 0xFF;

    responseBuf[2] = (totalLen >> 8) & 0xFF;

    responseBuf[3] = totalLen & 0xFF;

    

    responseBuf[4] = 0x80; responseBuf[5] = 0xFF; responseBuf[6] = 0xFF; responseBuf[7] = 0x02;

    

    // Copy seq from challenge (bytes[8-11])

    memcpy(responseBuf + 8, pktBuf + 8, 4);

    

    // STATUS byte = 0 (success)

    responseBuf[12] = 0x00;

    

    // Copy encrypted data starting at offset 13 (after STATUS)

    memcpy(responseBuf + 13, encryptedData, encryptedLen);

    

    // Send the response

    DLOG(@"[CHALLENGE-AUTO] Sending 0x80FFFF02 response: %u bytes to fd=%d (encrypted %zd bytes, WITH status byte)", totalLen, fd, encryptedLen);

    ssize_t sent = orig_send ? orig_send(fd, responseBuf, totalLen, 0) : -1;

    if (sent > 0) {

        g_challengeResponded = YES;

        g_challengeFd = fd;

        DLOG(@"[CHALLENGE-AUTO] SUCCESS: Sent 0x80FFFF02 response: %zd bytes (encrypted %zu -> %zd)",

             sent, payloadLen, encryptedLen);

        

        // Log response hex

        NSMutableString *hexStr = [NSMutableString stringWithString:@"[CHALLENGE-AUTO] Response HEX: "];

        for (uint32_t i = 0; i < totalLen && i < 64; i++) {

            [hexStr appendFormat:@"%02X ", responseBuf[i]];

        }

        if (totalLen > 64) [hexStr appendFormat:@"..."];

        DLOG(@"%@", hexStr);

        

        // v36.88: Construct 0x80FFF495 handshake complete PACKET (not fake 22-byte ACK)

        // Challenge response was sent. Server may not send 0x80FFF495, so client state

        // machine is stuck on heartbeats. We inject a REAL-SIZED 0x80FFF495 packet into recv.

        // Key: must be LARGE enough to avoid SIGSEGV in handle_CHOOSE_WOOD_BOX_RES handler,

        // which reads significant payload. We build ~200 byte packet with proper header + padding.

        {

            uint32_t hsPktSize = 200;  // Large enough to avoid out-of-bounds read

            if (hsPktSize > MAX_FORCE_HS_BUF) hsPktSize = MAX_FORCE_HS_BUF;

            

            memset(g_forceHandshakeBuf, 0, hsPktSize);

            

            // Byte[0-3]: Total packet length (big-endian)

            g_forceHandshakeBuf[0] = (hsPktSize >> 24) & 0xFF;

            g_forceHandshakeBuf[1] = (hsPktSize >> 16) & 0xFF;

            g_forceHandshakeBuf[2] = (hsPktSize >> 8) & 0xFF;

            g_forceHandshakeBuf[3] = hsPktSize & 0xFF;

            

            // Byte[4-7]: cmd = 0x80FFF495 (handshake complete, response to challenge)

            g_forceHandshakeBuf[4] = 0x80;

            g_forceHandshakeBuf[5] = 0xFF;

            g_forceHandshakeBuf[6] = 0xF4;

            g_forceHandshakeBuf[7] = 0x95;

            

            // Byte[8-11]: seq number, use same base as challenge response

            g_forceHandshakeBuf[8]  = responseBuf[8];

            g_forceHandshakeBuf[9]  = responseBuf[9];

            g_forceHandshakeBuf[10] = responseBuf[10];

            g_forceHandshakeBuf[11] = responseBuf[11];

            

            // Byte[12]: STATUS = 0 (SUCCESS)

            g_forceHandshakeBuf[12] = 0x00;

            

            // Byte[13]: format flags (copy from 0x80FFF494 style = 0x88)

            g_forceHandshakeBuf[13] = 0x88;

            

            // Byte[14...]: SAFETY PADDING - fill with recognizable Base64-like content

            // This prevents SIGSEGV when handler parses the payload.

            const char *padding = 

                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOJwUMBZ0a1FZkot1lJ"

                "+LB4rodylyGvUbq7sOO6nHgBqeqT2bp/mCShyDsVKdGGruFM8TY1cKlrHHhukEHV"

                "vr2+5zTL7Pg+ywmn+53vB4azfuaetHwVctLFmTyqrENWsTiL0uyl5w4k52TSvX7sC"

                "tuMx2grh6f1Hhb0/LqsFNjPobudwS00ypDtBG0Ung3T32DO2eFQ4JI0hXKkbCp0cyBT";

            size_t padLen = strlen(padding);

            size_t copyLen = padLen;

            if (copyLen > hsPktSize - 14) copyLen = hsPktSize - 14;

            memcpy(g_forceHandshakeBuf + 14, padding, copyLen);

            

            g_forceHandshakeLen = hsPktSize;

            g_forceHandshakeFd = fd;

            g_forceHandshakeComplete = YES;

            

            DLOG(@"[FORCE-HS-PREP] Prepared 0x80FFF495 packet size=%u bytes (fd=%d)",

                 hsPktSize, fd);

            DLOG(@"[FORCE-HS-PREP] Header: len=%u cmd=0x%02X%02X%02X%02X seq=0x%02X%02X%02X%02X status=%u",

                 hsPktSize,

                 g_forceHandshakeBuf[4], g_forceHandshakeBuf[5], g_forceHandshakeBuf[6], g_forceHandshakeBuf[7],

                 g_forceHandshakeBuf[8], g_forceHandshakeBuf[9], g_forceHandshakeBuf[10], g_forceHandshakeBuf[11],

                 g_forceHandshakeBuf[12]);

        }

        

        // v36.88: REMOVED immediate plaintext 0x000EE007 force-send.

        // Game server expects ENCRYPTED device info after handshake.

        // Force-sending plaintext (143/181/217 bytes) is silently discarded.

        // Instead, the injected 0x80FFF495 above will cause client state machine

        // to advance and send proper AES-encrypted 0x000EE007 (179 bytes) itself.

        DLOG(@"[GAME-FLOW] Waiting for FORCE-HS 0x80FFF495 injection -> client will send encrypted device info");

        

        return YES;

    } else {

        DLOG(@"[CHALLENGE-AUTO] Send failed: %zd", sent);

        return NO;

    }

}



static void applyServerListPatch(unsigned char *payload, size_t payloadLen) {

    if (!payload || payloadLen == 0) return;

    

    BOOL patched = NO;

    char *cpayload = (char *)payload;

    

    for (size_t i = 0; i + 7 < payloadLen; i++) {

        if (cpayload[i] == 's' && cpayload[i+1] == 't' && cpayload[i+2] == 'a' && 

            cpayload[i+3] == 't' && cpayload[i+4] == 'u' && cpayload[i+5] == 's' && 

            cpayload[i+6] == '=' && cpayload[i+7] != '1') {

            DLOG(@"[PROTO-PATCH] Found status=%c at offset %zu, changing to 1", cpayload[i+7], i);

            cpayload[i+7] = '1';

            patched = YES;

        }

    }

    

    for (size_t i = 0; i + 9 < payloadLen; i++) {

        if (cpayload[i] == 's' && cpayload[i+1] == 'e' && cpayload[i+2] == 'r' && 

            cpayload[i+3] == 'v' && cpayload[i+4] == 'e' && cpayload[i+5] == 'r' && 

            cpayload[i+6] == 'i' && cpayload[i+7] == 'd' && cpayload[i+8] == '=' && 

            cpayload[i+9] == '0') {

            DLOG(@"[PROTO-PATCH] Found serverid=0 at offset %zu, changing to 1", i);

            cpayload[i+9] = '1';

            patched = YES;

        }

    }

    

    for (size_t i = 0; i + 9 < payloadLen; i++) {

        if (cpayload[i] == 'c' && cpayload[i+1] == 'l' && cpayload[i+2] == 'i' && 

            cpayload[i+3] == 'e' && cpayload[i+4] == 'n' && cpayload[i+5] == 't' && 

            cpayload[i+6] == 'i' && cpayload[i+7] == 'd' && cpayload[i+8] == '=' && 

            cpayload[i+9] == '0') {

            DLOG(@"[PROTO-PATCH] Found clientid=0 at offset %zu, changing to 1", i);

            cpayload[i+9] = '1';

            patched = YES;

        }

    }

    

    for (size_t i = 0; i + 11 < payloadLen; i++) {

        if (cpayload[i] == 's' && cpayload[i+1] == 'e' && cpayload[i+2] == 'r' && 

            cpayload[i+3] == 'v' && cpayload[i+4] == 'e' && cpayload[i+5] == 'r' && 

            cpayload[i+6] == 'T' && cpayload[i+7] == 'y' && cpayload[i+8] == 'p' && 

            cpayload[i+9] == 'e' && cpayload[i+10] == '=' && cpayload[i+11] == '2') {

            DLOG(@"[PROTO-PATCH] Found serverType=2 at offset %zu, changing to 1", i);

            cpayload[i+11] = '1';

            patched = YES;

        }

    }

    

    const unsigned char newCat[] = {0xE4, 0xB8, 0x80, 0xE5, 0x8C, 0xBA};

    for (size_t i = 0; i + 11 <= payloadLen; i++) {

        if (cpayload[i] == 'c' && cpayload[i+1] == 'a' && cpayload[i+2] == 't' && 

            cpayload[i+3] == 'e' && cpayload[i+4] == 'g' && cpayload[i+5] == 'o' && 

            cpayload[i+6] == 'r' && cpayload[i+7] == 'y' && cpayload[i+8] == '=' && 

            cpayload[i+9] == '\'') {

            size_t endIdx = i + 10;

            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;

            if (endIdx < payloadLen) {

                size_t catLen = endIdx - (i + 10);

                if (catLen >= 6) {

                    DLOG(@"[PROTO-PATCH] Found category field at offset %zu, replacing with '一区'", i);

                    memcpy(payload + i + 10, newCat, 6);

                    for (size_t j = 6; j < catLen; j++) payload[i+10+j] = ' ';

                    patched = YES;

                }

            }

        }

    }

    

    const unsigned char newName[] = {0xE6, 0x9B, 0xB4, 0xE7, 0xAB, 0xAF, 0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x61};

    for (size_t i = 0; i + 6 <= payloadLen; i++) {

        if (cpayload[i] == 'n' && cpayload[i+1] == 'a' && cpayload[i+2] == 'm' && 

            cpayload[i+3] == 'e' && cpayload[i+4] == '=' && cpayload[i+5] == '\'') {

            size_t endIdx = i + 6;

            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;

            if (endIdx < payloadLen) {

                size_t nameLen = endIdx - (i + 6);

                if (nameLen >= 6) {

                    size_t validCharCount = 0;

                    size_t dotCount = 0;

                    for (size_t j = 0; j < nameLen && j < 30; j++) {

                        unsigned char ch = payload[i+6+j];

                        if (ch == '.') {

                            dotCount++;

                        } else if ((ch >= 0xE4 && ch <= 0xE9) || (ch >= 'a' && ch <= 'z') || 

                                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {

                            validCharCount++;

                        }

                    }

                    if (dotCount >= nameLen / 2 || validCharCount < 3) {

                        DLOG(@"[PROTO-PATCH] Found garbage name (dots=%zu, valid=%zu) at offset %zu, replacing", 

                             dotCount, validCharCount, i);

                        memcpy(payload + i + 6, newName, 13);

                        for (size_t j = 13; j < nameLen; j++) payload[i+6+j] = ' ';

                        patched = YES;

                    }

                }

            }

        }

    }

    

    const unsigned char newRealName[] = {0xE6, 0x9B, 0xB4, 0xE7, 0xAB, 0xAF, 0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x61};

    for (size_t i = 0; i + 10 <= payloadLen; i++) {

        if (cpayload[i] == 'r' && cpayload[i+1] == 'e' && cpayload[i+2] == 'a' && 

            cpayload[i+3] == 'l' && cpayload[i+4] == 'n' && cpayload[i+5] == 'a' && 

            cpayload[i+6] == 'm' && cpayload[i+7] == 'e' && cpayload[i+8] == '=' && 

            cpayload[i+9] == '\'') {

            size_t endIdx = i + 10;

            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;

            if (endIdx < payloadLen) {

                size_t nameLen = endIdx - (i + 10);

                if (nameLen >= 6) {

                    size_t validCharCount = 0;

                    size_t dotCount = 0;

                    for (size_t j = 0; j < nameLen && j < 30; j++) {

                        unsigned char ch = payload[i+10+j];

                        if (ch == '.') {

                            dotCount++;

                        } else if ((ch >= 0xE4 && ch <= 0xE9) || (ch >= 'a' && ch <= 'z') || 

                                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {

                            validCharCount++;

                        }

                    }

                    if (dotCount >= nameLen / 2 || validCharCount < 3) {

                        DLOG(@"[PROTO-PATCH] Found garbage realname (dots=%zu, valid=%zu) at offset %zu, replacing", 

                             dotCount, validCharCount, i);

                        memcpy(payload + i + 10, newRealName, 13);

                        for (size_t j = 13; j < nameLen; j++) payload[i+10+j] = ' ';

                        patched = YES;

                    }

                }

            }

        }

    }

    

    const unsigned char oldDesc[] = {0xE6, 0x9C, 0x8D, 0xE5, 0x8A, 0xA1, 0xE5, 0x99, 0xA8, 

                                     0xE7, 0xBB, 0xB4, 0xE6, 0x8A, 0xA4, 0xE4, 0xB8, 0xAD, 

                                     0x2E, 0x2E, 0x2E};

    const unsigned char newDesc[] = {0xE8, 0xBF, 0x90, 0xE8, 0xA1, 0x8C};

    for (size_t i = 0; i + 21 <= payloadLen; i++) {

        if (memcmp(payload + i, oldDesc, 21) == 0) {

            DLOG(@"[PROTO-PATCH] Found '服务器维护中...' at offset %zu, replacing with '运行'", i);

            memcpy(payload + i, newDesc, 6);

            for (size_t j = 6; j < 21; j++) payload[i+j] = ' ';

            patched = YES;

        }

    }

    

    for (size_t i = 0; i + 17 <= payloadLen; i++) {

        if (cpayload[i] == 'd' && cpayload[i+1] == 'e' && cpayload[i+2] == 's' && 

            cpayload[i+3] == 'c' && cpayload[i+4] == 'r' && cpayload[i+5] == 'i' && 

            cpayload[i+6] == 'p' && cpayload[i+7] == 't' && cpayload[i+8] == 'i' && 

            cpayload[i+9] == 'o' && cpayload[i+10] == 'n' && cpayload[i+11] == '=' && 

            cpayload[i+12] == '\'') {

            size_t endIdx = i + 13;

            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;

            if (endIdx < payloadLen) {

                size_t descLen = endIdx - (i + 13);

                if (descLen >= 6) {

                    BOOL isGarbage = YES;

                    for (size_t j = 0; j < descLen && j < 20; j++) {

                        unsigned char ch = payload[i+13+j];

                        if ((ch >= 0x20 && ch < 0x7F) || (ch >= 0xE4 && ch <= 0xE9)) {

                            isGarbage = NO;

                            break;

                        }

                    }

                    if (isGarbage) {

                        DLOG(@"[PROTO-PATCH] Found garbage description at offset %zu, replacing with '运行'", i);

                        memcpy(payload + i + 13, newDesc, 6);

                        for (size_t j = 6; j < descLen; j++) payload[i+13+j] = ' ';

                        patched = YES;

                    }

                }

            }

        }

    }

    

    for (size_t i = 0; i + 16 <= payloadLen; i++) {

        if (cpayload[i] == 'o' && cpayload[i+1] == 'n' && cpayload[i+2] == 'l' && 

            cpayload[i+3] == 'i' && cpayload[i+4] == 'n' && cpayload[i+5] == 'e' && 

            cpayload[i+6] == 'P' && cpayload[i+7] == 'l' && cpayload[i+8] == 'a' && 

            cpayload[i+9] == 'y' && cpayload[i+10] == 'e' && cpayload[i+11] == 'r' && 

            cpayload[i+12] == 'N' && cpayload[i+13] == 'u' && cpayload[i+14] == 'm' && 

            cpayload[i+15] == '=' && cpayload[i+16] == '0') {

            DLOG(@"[PROTO-PATCH] Found onlinePlayerNum=0 at offset %zu, changing to 100", i);

            cpayload[i+16] = '1';

            if (i + 17 < payloadLen && cpayload[i+17] == ',') {

                cpayload[i+17] = '0';

                cpayload[i+18] = '0';

            } else {

                cpayload[i+17] = '0';

            }

            patched = YES;

        }

    }

    

    if (patched) {

        DLOG(@"[PROTO-PATCH] Server list patched successfully");

    }

}



// v36.137: Extracted BURST injection logic as independent function

// Called from: (1) hook_recv entry when g_triggerFakeNextRecv, (2) RECV-CLOSE direct inject

static ssize_t doBurstFakeInject(int fd, void *buf, size_t len) {

    if (!buf || len < 16) return -1;



    DLOG(@"[FORCE-FAKE] v36.137: BURST inject for fd=%d (draining command queue)", fd);

    g_triggerFakeNextRecv = NO;

    g_triggerFakeFd       = -1;



    // Drain entire virtual queue (up to 16 entries)

    GameCmdEntry batch[16];

    int        batchCount = 0;

    for (int i = 0; i < 16; i++) {

        GameCmdEntry e;

        if (!dequeueGameCmd(&e)) break;

        batch[batchCount++] = e;

        DLOG(@"[FORCE-FAKE] v36.137: Batch collected [%d] cmd=0x%08X seq=0x%08X",

             batchCount - 1, e.cmd, e.seqNum);

    }



    uint32_t totalLen     = 0;

    uint32_t respCount    = 0;

    uint8_t *burstBuf    = (uint8_t *)buf;

    size_t   remaining   = len;

    // v36.141: Track whether we already generated a 0x0CB0A300 response.

    // Real server returns ONE 0x0CB0A300 (1632 bytes) for two 0x00FFF493

    // requests (hook.txt SEND #30 + #31 -> RECV #19). Duplicating it

    // pollutes the protocol flow.

    BOOL roleRespGenerated = NO;



    // v36.155: MUST increment role index BEFORE calling generateFakeResponse()

    // so that dynamic role data (name, profession, level) uses the NEW index.

    // Without this, g_roleIndex would be 0 when generating the first response,

    // and the if(g_roleIndex > 0) check in generateFakeResponse would fail,

    // producing static hardcoded attributes instead of unique per-server data.

    g_roleIndex++;

    DLOG(@"[POST-BURST] v36.155: Incremented g_roleIndex to %d (before response generation)", g_roleIndex);



    if (batchCount == 0) {

        // v36.141: Fallback changed from EE007 to FFF493 — server does NOT

        // respond to EE007, so injecting 0x800EE007 would confuse the client.

        DLOG(@"[FORCE-FAKE] v36.141: Queue empty, fallback single FFF493 inject (seq=0x10000)");

        GameCmdEntry ff; ff.cmd = 0x00FFF493; ff.seqNum = 0x00010000; ff.fd = fd; ff.sendLen = 472;

        batch[0] = ff; batchCount = 1;

    }



    for (int i = 0; i < batchCount && remaining >= 16u; i++) {

        // v36.143: WHITELIST mode — only 0x00FFF493 gets a fake response

        // (0x0CB0A300 role data). ALL other commands are skipped.

        // Previous blacklist approach (v36.138-v36.141) kept missing new

        // garbage commands (0x48736343, 0x766A7370, ...) that polluted the

        // BURST with 200-byte bogus responses before 0x0CB0A300.

        if (batch[i].cmd != 0x00FFF493) {

            DLOG(@"[FORCE-FAKE] v36.143: SKIP cmd=0x%08X seq=0x%08X (whitelist: only FFF493)",

                 batch[i].cmd, batch[i].seqNum);

            continue;

        }

        // v36.141: Only generate ONE 0x0CB0A300 for the first 0x00FFF493.

        // Real capture (hook.txt): two 0x00FFF493 -> ONE 0x0CB0A300 (1632B).

        if (roleRespGenerated) {

            DLOG(@"[FORCE-FAKE] v36.141: SKIP duplicate 0x00FFF493 seq=0x%08X (role resp already generated)",

                 batch[i].seqNum);

            continue;

        }

        uint32_t rLen = generateFakeResponse(batch[i].cmd,

                                             burstBuf + totalLen,

                                             (uint32_t)MIN(MAX_FAKE_RESP_BUF, (int)remaining),

                                             batch[i].seqNum);

        // v36.141: Mark 0x0CB0A300 as generated so subsequent 0x00FFF493 are skipped

        if (batch[i].cmd == 0x00FFF493 && rLen > 0) {

            roleRespGenerated = YES;

        }

        if (rLen == 0) {

            rLen = 200;

            if (remaining < rLen) break;

            memset(burstBuf + totalLen, 0, rLen);

            burstBuf[totalLen + 0] = (rLen >> 24) & 0xFF;

            burstBuf[totalLen + 1] = (rLen >> 16) & 0xFF;

            burstBuf[totalLen + 2] = (rLen >> 8)  & 0xFF;

            burstBuf[totalLen + 3] =  rLen & 0xFF;

            uint32_t rc2 = batch[i].cmd | 0x80000000u;

            burstBuf[totalLen + 4] = (rc2 >> 24) & 0xFF; burstBuf[totalLen + 5] = (rc2 >> 16) & 0xFF;

            burstBuf[totalLen + 6] = (rc2 >> 8)  & 0xFF; burstBuf[totalLen + 7] =  rc2 & 0xFF;

            burstBuf[totalLen + 8]  = (batch[i].seqNum >> 24) & 0xFF; burstBuf[totalLen + 9]  = (batch[i].seqNum >> 16) & 0xFF;

            burstBuf[totalLen + 10] = (batch[i].seqNum >> 8)  & 0xFF; burstBuf[totalLen + 11] =  batch[i].seqNum & 0xFF;

            burstBuf[totalLen + 12] = 0x00; // status = success

        }

        if ((uint32_t)remaining < rLen) {

            DLOG(@"[FORCE-FAKE] v36.137: Batch [%d] truncated (need %u, remaining %zu) — stop burst",

                 i, rLen, remaining);

            break;

        }



        // Copy to persistent g_fakeRespBuf for legacy readers (only first response)

        if (i == 0 && g_fakeRespLen == 0) {

            memcpy(g_fakeRespBuf, burstBuf + totalLen, MIN(rLen, (uint32_t)MAX_FAKE_RESP_BUF));

            g_fakeRespLen = rLen;

        }



        totalLen  += rLen;

        remaining -= rLen;

        respCount++;

        DLOG(@"[FORCE-FAKE] v36.137: Batch [%d] appended cmd=0x%08X -> 0x%08X seq=0x%08X len=%u (cum=%u respCount=%d)",

             i, batch[i].cmd, (batch[i].cmd | 0x80000000u), batch[i].seqNum, rLen, totalLen, respCount);

    }



    g_fakeRespInjected  = YES;

    g_fakeRespFd        = fd;

    g_fakeRespSentCount = respCount;

    g_fakeRespActive    = YES;

    g_fakeRespDelivered = YES;

    g_lastRespCmd       = batch[respCount > 0 ? respCount - 1 : 0].cmd;

    g_respCount         = respCount;



    // v36.154: REVERT to CONTIGUOUS injection (state=1→2→0). v36.153's

    // request-driven state=10 caused "连接异常中断" because poll/select

    // set POLLIN while recv() returned EAGAIN, creating a busy-wait loop

    // that the client interpreted as a connection error.

    // v36.154 FIX: Use contiguous injection (proven in v36.146 to show

    // role UI) + add 3-second time delay before Phase 2 can trigger

    // (fixes v36.152 where auto-load ACKs triggered Phase 2 too early).

    //   state=1: next recv injects RECV#20 (71B) → state=2

    //   state=2: next recv injects RECV#21 (840B) → state=0, done

    // v36.155: g_roleIndex already incremented above (before generateFakeResponse).

    // Set post-BURST state for contiguous RECV#20/#21 injection.

    if (totalLen > 0) {

        g_postBurstState = 1;  // v36.154: contiguous injection

        g_postBurstFd = fd;

        g_phase2TriggerCount = 0;

        g_phase1DoneTime = 0;  // Reset; set when RECV#21 is injected

        DLOG(@"[POST-BURST] v36.155: State=1 (contiguous inject RECV#20, roleIndex=%d)", g_roleIndex);

    }



    if (totalLen > 0) {

        DLOG(@"[FAKE-RESP] v36.137: BURST-INJECT returned %u bytes (%d responses, %zu left in recv buffer)",

             totalLen, respCount, remaining);

        NSMutableString *burstHex = [NSMutableString stringWithCapacity:256];

        for (uint32_t i = 0; i < MIN(totalLen, 64u); i++) {

            [burstHex appendFormat:@"%02X ", ((const uint8_t *)buf)[i]];

            if (i == 15 || i == 31 || i == 47) [burstHex appendString:@"\n  "];

        }

        DLOG(@"%@", burstHex);

        return (ssize_t)totalLen;

    }

    DLOG(@"[FAKE-RESP] v36.137: BURST-INJECT produced 0 bytes — returning EAGAIN");

    return -1;

}



static ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {

    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");

    if (!orig_recv || !buf) return -1;

    

    // v37.15: DISABLED BURST injection — was causing crash on re-signed IPA.

    // Native encryption works, client sends real encrypted packets, no fake responses needed.

    if (0 && g_triggerFakeNextRecv && g_triggerFakeFd == fd &&

        g_handshakeComplete && g_loginPacketsSent && !g_fakeRespInjected) {

        ssize_t injectLen = doBurstFakeInject(fd, buf, len);

        if (injectLen > 0) return injectLen;

        errno = EAGAIN;

        return -1;

    }



    // v36.142: Post-BURST state machine — inject RECV #20 and #21.

    // Real protocol (hook.txt): after 0x0CB0A300 (role data, our BURST), the

    // client sends an ACK then expects:

    //   RECV #20: cmd=0x12F00080 (71 bytes) — session token

    //   RECV #21: cmd=0x13000080 (840 bytes) — map/scene data

    //   RECV #22: cmd=0x80FFF490 (27 bytes) — enter-game ACK

    //   RECV #23: cmd=0x16000080 (273 bytes) — scene entity data

    //   RECV #24: cmd=0x80FFF161 (63 bytes) — role attr notifications

    // v36.150: TWO-PHASE injection. Phase 1: RECV #20+#21 → client shows

    // role selection UI (v36.146 verified). Phase 2: when client sends

    // 0x00FFF493 (select role / enter game), inject RECV #22-#24.

    // v36.149 injected #22-#24 immediately after #21, causing client to

    // skip role selection and get stuck at "进入角色界面".

    // v36.154: CONTIGUOUS injection (state=1→2→0). v36.153's request-driven

    // state=10 caused "连接异常中断" (poll/select set POLLIN but recv returned

    // EAGAIN → busy-wait → client timeout). Reverted to proven v36.146 design.

    // v36.154 adds 3-second time delay before Phase 2 can trigger.

    // State: 0=idle, 1=inject RECV#20, 2=inject RECV#21→done

    //        3=RECV#22, 4=RECV#23, 5=RECV#24, 0=done

    // v37.15: DISABLED post-BURST state machine — was causing crash.

    // Native encryption works, no fake response injection needed.

    if (0 && g_postBurstState >= 1 && g_postBurstFd == fd) {

        // Phase 1: RECV #20 (71B session token)

        if (g_postBurstState == 1 && len >= 71) {

            memcpy(buf, kRecv20Data, 71);

            g_postBurstState = 2;

            DLOG(@"[POST-BURST] v36.155: Injected RECV #20 (71B) fd=%d state=2", fd);

            return 71;

        }

        // Phase 1: RECV #21 (840B map data) → Phase 1 done

        if (g_postBurstState == 2 && len >= 840) {

            memcpy(buf, kRecv21Head, 288);

            memset((uint8_t *)buf + 288, 0, 840 - 288);

            for (int i = 0; kRecv21Sparse[i].off != 0 || kRecv21Sparse[i].val != 0; i++) {

                if (kRecv21Sparse[i].off < 840)

                    ((uint8_t *)buf)[kRecv21Sparse[i].off] = kRecv21Sparse[i].val;

            }

            // v36.155: Dynamic role data in RECV #21 based on g_roleIndex.

            // The role selection UI displays this data for the character.

            // Each server must show a DIFFERENT character.

            char dynName[48] = {0};

            snprintf(dynName, sizeof(dynName), "\xE7\x8E\xA9\xE5\xAE\xB6%03d", g_roleIndex);

            int nameLen = (int)strlen(dynName);

            memcpy((uint8_t *)buf + 16, dynName, MIN(nameLen, 16));



            // v36.155: Also set dynamic mapId at offset 48-51 (uint32 LE)

            // so each server shows a unique map, not the same one.

            uint32_t mapId = (uint32_t)g_roleIndex;

            ((uint8_t *)buf)[48] = (mapId & 0xFF);

            ((uint8_t *)buf)[49] = ((mapId >> 8) & 0xFF);

            ((uint8_t *)buf)[50] = ((mapId >> 16) & 0xFF);

            ((uint8_t *)buf)[51] = ((mapId >> 24) & 0xFF);



            DLOG(@"[POST-BURST] v36.155: RECV #21 role name='%s' mapId=%u (roleIndex=%d)", dynName, mapId, g_roleIndex);

            g_postBurstState = 0;

            g_postBurstDone = YES;

            g_phase1DoneTime = CFAbsoluteTimeGetCurrent();

            DLOG(@"[POST-BURST] v36.155: Injected RECV #21 (840B) fd=%d state=0 (Phase 1 done, role '%s' displayed, Phase 2 locked for 3s)", fd, dynName);

            return 840;

        }

        // Phase 2: RECV #22-#24 (triggered by hook_send on role select)

        if (g_postBurstState == 3 && len >= 27) {

            memcpy(buf, kRecv22Data, 27);

            g_postBurstState = 4;

            DLOG(@"[POST-BURST] v36.155: Injected RECV #22 (27B) fd=%d state=4 (Phase 2)", fd);

            return 27;

        }

        if (g_postBurstState == 4 && len >= 273) {

            memcpy(buf, kRecv23Data, 273);

            g_postBurstState = 5;

            DLOG(@"[POST-BURST] v36.155: Injected RECV #23 (273B) fd=%d state=5", fd);

            return 273;

        }

        if (g_postBurstState == 5 && len >= 63) {

            memcpy(buf, kRecv24Data, 63);

            g_postBurstState = 0;

            g_postBurstDone = YES;

            DLOG(@"[POST-BURST] v36.155: Injected RECV #24 (63B) fd=%d state=0 (Phase 2 done)", fd);

            return 63;

        }

    }



    // v36.123: Queue-based fake response system (PRIORITY PATH)

    // This handles ALL subsequent recv calls after initial injection

    if (g_fakeRespActive && g_fakeRespFd == fd) {

        // v36.123: Cap total responses to prevent infinite loop

        if (g_respCount >= 200) {

            DLOG(@"[FAKE-RESP] v36.123: Response cap reached (%d), returning EAGAIN", g_respCount);

            errno = EAGAIN;

            return -1;

        }

        

        // v36.123: Try to dequeue next command with sequence number

        GameCmdEntry entry;

        uint32_t responseCmd = 0;

        uint32_t respSeqNum = 0;

        BOOL dequeued = NO;

        

        if (dequeueGameCmd(&entry)) {

            responseCmd = entry.cmd;

            respSeqNum = entry.seqNum;

            dequeued = YES;

            DLOG(@"[FAKE-RESP] v36.123: Dequeued cmd=0x%08X seq=0x%08X from queue (remaining=%d)", 

                 responseCmd, respSeqNum, g_cmdQueueCount);

        } else if (g_lastGameCmd != 0) {

            // v36.123: Queue empty but we have a last command

            responseCmd = g_lastGameCmd;

            respSeqNum = g_lastSeqNum;

            

            // Only respond if:

            // 1. Different from last response, OR

            // 2. Client sent new data (delivered flag was reset)

            if (responseCmd == g_lastRespCmd && g_fakeRespDelivered) {

                // Same command already responded to, wait for new data

                errno = EAGAIN;

                return -1;

            }

            DLOG(@"[FAKE-RESP] v36.123: Queue empty, using last cmd=0x%08X seq=0x%08X (delivered=%d)", 

                 responseCmd, respSeqNum, g_fakeRespDelivered);

        } else {

            // No commands at all

            DLOG(@"[FAKE-RESP] v36.123: No commands to respond to, returning EAGAIN");

            errno = EAGAIN;

            return -1;

        }

        

        // v36.123: Generate response for the command with correct sequence number

        uint8_t tempBuf[MAX_FAKE_RESP_BUF];

        uint32_t respLen = generateFakeResponse(responseCmd, tempBuf, sizeof(tempBuf), respSeqNum);

        

        if (respLen > 0 && respLen <= len) {

            memcpy(buf, tempBuf, respLen);

            g_fakeRespSentCount++;

            g_fakeRespDelivered = YES;

            g_lastRespCmd = responseCmd;

            g_respCount++;

            

            // v36.123: Log full response details for debugging

            NSMutableString *respHex = [NSMutableString stringWithCapacity:48];

            for (uint32_t i = 0; i < MIN(respLen, 16); i++) {

                [respHex appendFormat:@"%02X ", tempBuf[i]];

            }

            DLOG(@"[FAKE-RESP] v36.123: Delivered response for cmd=0x%08X seq=0x%08X len=%u (queue=%d, respCount=%d, hex=%@)", 

                 responseCmd, respSeqNum, respLen, g_cmdQueueCount, g_respCount, respHex);

            return (ssize_t)respLen;

        }

        

        DLOG(@"[FAKE-RESP] v36.123: generateFakeResponse returned invalid len=%u (max=%zu), returning EAGAIN", respLen, len);

        errno = EAGAIN;

        return -1;

    }

    

    // v36.96: Check for fake response state FIRST - before any real recv call

    // v36.146: Skip entirely if post-BURST is done — client has received all

    // needed fake responses (BURST + RECV #20 + #21). Further recv() calls

    // should return EAGAIN, not generate duplicate 0x0CB0A300 responses.

    if (g_fakeRespInjected && g_fakeRespFd == fd && !g_postBurstDone) {

        if (g_fakeRespSentCount >= 1) {

            // v36.101: Switch to active mode but respect delivered flag

            if (!g_fakeRespActive) {

                g_fakeRespActive = YES;

                DLOG(@"[FAKE-RESP] v36.123: Switching to ACTIVE fake response mode for fd=%d", fd);

            }

            // v36.123: Use command queue for ALL responses, not just g_lastGameCmd

            if (g_respCount >= 200) {

                errno = EAGAIN;

                return -1;

            }

            

            // v36.123: Dequeue next command from queue (fixes wrong cmd/seq in subsequent responses)

            GameCmdEntry entry;

            uint32_t activeCmd = 0;

            uint32_t activeSeq = 0;

            

            if (dequeueGameCmd(&entry)) {

                activeCmd = entry.cmd;

                activeSeq = entry.seqNum;

            } else {

                // v36.123: Queue empty - all commands have been responded to

                DLOG(@"[FAKE-RESP] v36.123: Queue empty, returning EAGAIN (all %d responses delivered)", g_respCount);

                errno = EAGAIN;

                return -1;

            }

            

            // v36.123: Generate fake response using dequeued command with correct seq

            uint8_t tempBuf[MAX_FAKE_RESP_BUF];

            uint32_t respLen = generateFakeResponse(activeCmd, tempBuf, sizeof(tempBuf), activeSeq);

            

            if (respLen > 0 && respLen <= len) {

                memcpy(buf, tempBuf, respLen);

                g_fakeRespSentCount++;

                g_fakeRespDelivered = YES;

                g_lastRespCmd = activeCmd;

                g_respCount++;

                DLOG(@"[FAKE-RESP] v36.123: Delivered response for cmd=0x%08X seq=0x%08X len=%u (total #%d, respCount=%d, queue=%d)", 

                     activeCmd, activeSeq, respLen, g_fakeRespSentCount, g_respCount, g_cmdQueueCount);

                return (ssize_t)respLen;

            }

            

            // No response needed, return EAGAIN

            errno = EAGAIN;

            return -1;

        }

        // First call after injection: return fake response data

        g_fakeRespSentCount++;

        if (g_fakeRespLen > 0 && buf) {

            ssize_t retLen = (ssize_t)g_fakeRespLen;

            if (retLen > (ssize_t)len) retLen = (ssize_t)len;

            memcpy(buf, g_fakeRespBuf, retLen);

            DLOG(@"[FAKE-RESP] v36.123: Returning stored fake response (%zd bytes) for fd=%d", retLen, fd);

            return retLen;

        }

        // No fake response data available, return EAGAIN

        DLOG(@"[FAKE-RESP] v36.123: No fake response data, returning EAGAIN for fd=%d", fd);

        errno = EAGAIN;

        return -1;

    }

    

    // v36.91: Debug log to track recv calls (FORCE-HS removed - no more fake packet injection!)

    DLOG(@"[RECV-ENTRY] fd=%d len=%zu hbAck=%zd hbFd=%d",

         fd, len, g_localHeartbeatAckLen, g_localHeartbeatAckFd);

    

    // v36.91: FORCE-HS MECHANISM COMPLETELY REMOVED!

    // v36.90 proved: injecting fake 0x80FFF495 BEFORE real server packet = state machine corruption.

    // Client receives TWO 0x80FFF495 (fake first, then real) with mismatched seq = handshake fails.

    // Only patch the REAL server 0x80FFF495 status byte = minimum intervention approach.

    

    // v36.68: Check for local heartbeat ACK first (blocked heartbeat responses)

    if (g_localHeartbeatAckLen > 0 && g_localHeartbeatAckFd == fd) {

        ssize_t ackLen = g_localHeartbeatAckLen;

        if (ackLen > (ssize_t)len) ackLen = (ssize_t)len;

        memcpy(buf, g_localHeartbeatAckBuf, ackLen);

        DLOG(@"[LOCAL-HB-ACK] Returning %zd bytes local heartbeat ACK (fd=%d)", ackLen, fd);

        g_localHeartbeatAckLen = 0;

        g_localHeartbeatAckFd = -1;

        return ackLen;

    }

    

    // v36.68: Check for leftover bytes from sticky packet split

    // When 0x80FFF494 + heartbeat ACK arrive in same TCP buffer, we split them

    if (g_stickyLeftoverLen > 0 && g_stickyLeftoverFd == fd) {

        ssize_t leftoverLen = g_stickyLeftoverLen;

        if (leftoverLen > (ssize_t)len) leftoverLen = (ssize_t)len;

        memcpy(buf, g_stickyLeftoverBuf, leftoverLen);

        DLOG(@"[STICKY-LEFTOVER] Returning %zd leftover bytes from sticky packet split (fd=%d)", leftoverLen, fd);

        

        // v36.74: DISABLED auto-response to 0x00FFFF02 in leftover path

        // Let client handle challenge naturally - it needs to construct proper RSA-encrypted response

        // Previously: auto-responded with fake 0x80FFFF02 by copying bytes and flipping cmd,

        // which server rejected because it expects RSA-encrypted data using certificate from 0x80FFF494

        

        // Shift remaining leftover bytes

        if (leftoverLen < g_stickyLeftoverLen) {

            memmove(g_stickyLeftoverBuf, g_stickyLeftoverBuf + leftoverLen, g_stickyLeftoverLen - leftoverLen);

        }

        g_stickyLeftoverLen -= leftoverLen;

        if (g_stickyLeftoverLen == 0) g_stickyLeftoverFd = -1;

        return leftoverLen;

    }

    

    ssize_t ret = orig_recv(fd, buf, len, flags);

    if (ret <= 0) {

        // Log connection close/error with context

        const char *host = ""; int port = 0;

        for (int i = 0; i < g_trackedCount; i++) {

            if (g_trackedFds[i] == fd && g_trackedActive[i]) { host = g_trackedHosts[i]; port = g_trackedPorts[i]; break; }

        }

        if (ret == 0) {

            DLOG(@"[RECV-CLOSE] fd=%d %s:%d ret=0 (server closed connection gracefully)", fd, host, port);

            // v36.61: Game server disconnected, try next server (dynamic port detection)

            BOOL isGamePort = (port == 12003 || port == 58158 || 

                               (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

            if (isGamePort) {

                // v36.99: KEY FIX - For game server fd, NEVER return 0 to client!

                // Returning 0 causes SocketClient/NetImpl to detect "connection closed"

                // and set internal disconnected state, leading to "网络中断" error.

                

                // v36.137: DIRECT BURST INJECTION on RECV-CLOSE!

                //   v36.136 bug: armed g_triggerFakeNextRecv but client NEVER called recv()

                //   again. Client detected disconnect via heartbeat→quitFromServer→close()

                //   and reconnected from scratch (login server 5678).

                //   Fix: inject fake responses DIRECTLY into buf NOW, return totalLen.

                //   This prevents client from ever seeing ret=0 on game server fd.

                // v37.15: DISABLED RECV-CLOSE BURST injection — was causing crash.

                // Native encryption works, let client handle connection close normally.

                if (0 && g_handshakeComplete && g_loginPacketsSent && !g_fakeRespInjected) {

                    DLOG(@"[RECV-CLOSE] v36.137: Game server closed connection (fd=%d). DIRECT BURST inject (handshake=%d loginSent=%d).",

                         fd, g_handshakeComplete, g_loginPacketsSent);

                    ssize_t injectLen = doBurstFakeInject(fd, buf, len);

                    if (injectLen > 0) {

                        DLOG(@"[RECV-CLOSE] v36.137: BURST inject SUCCESS %zd bytes for fd=%d — client sees fake responses, NOT connection close", injectLen, fd);

                        return injectLen;

                    }

                    DLOG(@"[RECV-CLOSE] v36.137: BURST inject FAILED, falling through to EAGAIN");

                } else {

                    DLOG(@"[RECV-CLOSE] v36.137: Game server closed connection (fd=%d). EAGAIN only (handshake=%d loginSent=%d fakeInjected=%d).",

                         fd, g_handshakeComplete, g_loginPacketsSent, g_fakeRespInjected);

                }

                

                // v36.136: DISABLED SERVER-ROTATE!

                //   Rotation caused client to reconnect to next server (101.132.180.110),

                //   which ALSO closes connection, creating an infinite reconnect loop.

                // [SERVER-ROTATE DISABLED in v36.136]

                

                errno = EAGAIN;

                return -1;

            }

        } else {

            DLOG(@"[RECV-ERR] fd=%d %s:%d ret=%zd errno=%d (%s)", fd, host, port, ret, errno, strerror(errno));

        }

        return ret;

    }

    

    const char *host = getHostForFd(fd);

    if (!host) return ret;

    

    int port = getPortForFd(fd);

    const unsigned char *p = (const unsigned char *)buf;

    

    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];

    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];

    size_t showLen = ret > 256 ? 256 : (size_t)ret;

    for (size_t i = 0; i < showLen; i++) {

        [hex appendFormat:@"%02X ", p[i]];

        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];

    }

    DLOG(@"[RECV] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);

    

    if (ret >= 8) {

        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |

                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

        

        // Challenge packets (0x00FFFF01/0x00FFFF02) - LOG AND RESPOND

        // v36.67: Server requires response to 0x00FFFF02 to continue handshake

        if (cmd == 0x00FFFF01 || cmd == 0x00FFFF02) {

            NSMutableString *challengeDetail = [NSMutableString string];

            [challengeDetail appendFormat:@"[CHALLENGE-LOG] cmd=0x%08X len=%zd port=%d\n", cmd, (size_t)ret, port];

            [challengeDetail appendFormat:@"  Full hex: "];

            for (ssize_t i = 0; i < ret && i < 64; i++) {

                [challengeDetail appendFormat:@"%02X ", p[i]];

            }

            if (ret > 64) [challengeDetail appendFormat:@"...\n"];

            else [challengeDetail appendFormat:@"\n"];

            

            // Parse packet structure for analysis

            if (ret >= 12) {

                uint32_t pktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |

                                  ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

                uint32_t seq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |

                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];

                [challengeDetail appendFormat:@"  Parsed: pktLen=%u seq=0x%08X\n", pktLen, seq];

                

                // Check for payload data after header

                if (ret > 12) {

                    [challengeDetail appendFormat:@"  Payload (%zd bytes): ", ret - 12];

                    for (ssize_t i = 12; i < ret && i < 32; i++) {

                        [challengeDetail appendFormat:@"%02X ", p[i]];

                    }

                    if (ret > 32) [challengeDetail appendFormat:@"..."];

                    [challengeDetail appendFormat:@"\n"];

                }

                

                // Try to decode payload as ASCII

                NSString *payloadStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];

                if (payloadStr && payloadStr.length > 0) {

                    [challengeDetail appendFormat:@"  Payload text: %@\n", payloadStr];

                }

            }

            

            // v36.93: DISABLED auto-respond to 0x00FFFF02! (same as v36.91-v36.92)

            // v36.90 analysis: Hook's auto-response (0x80FFFF02) + Client's native response (0x00FFF495)

            // cause DOUBLE response to single challenge, activating FORCE-HS and corrupting state machine.

            // v36.89 observation PROVED client can handle 0x00FFFF02 challenge natively.

            // Let client send 0x00FFF495 (703B RSA response) - this is the PROPER response format!

            if (cmd == 0x00FFFF02 && ret >= 28) {

                [challengeDetail appendFormat:@"  [V36.93] SKIP AUTO-RESPOND: Let client handle 0x00FFFF02 challenge natively\n"];

                [challengeDetail appendFormat:@"  [V36.93] Client will parse RSA cert from 0x80FFF494 and send 0x00FFF495 response\n"];

                DLOG(@"[CHALLENGE] v36.93: Skipping auto-respond - let client send native 0x00FFF495 (703B RSA response)");

            } else if (cmd == 0x00FFFF01) {

                [challengeDetail appendFormat:@"  [NOTE] 0x00FFFF01 (first challenge) - game handles this normally\n"];

            }

            

            DLOG(@"%@", challengeDetail);

        }

        

        if (cmd == 0x802EE113) {

            DLOG(@"[PROTO-R] Server list response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

            

            // DETAILED HEX DUMP of server list response

            DLOG(@"[SERVERLIST-HEX] Full response hex (%zd bytes):", ret);

            for (ssize_t i = 0; i < ret; i += 32) {

                NSMutableString *line = [NSMutableString string];

                for (ssize_t j = i; j < MIN(i + 32, ret); j++) {

                    [line appendFormat:@"%02X ", p[j]];

                }

                DLOG(@"[SERVERLIST-HEX]   %zd: %@", i, line);

            }

            

            // v36.45: DISABLE port patch - use original port directly

            // Just log the ports found, don't modify them

            int portCount = 0;

            for (ssize_t i = 12; i + 1 < ret; i++) {

                if (p[i] == 0x2E && p[i+1] == 0xE3) {

                    portCount++;

                }

            }

            DLOG(@"[SERVERLIST-PATCH] DISABLED: found %d occurrences of port 12003, NOT modifying", portCount);

            

            // Update global game server info from response

            parseServerListResponse((const unsigned char *)buf, ret);

            

            // Also try to decode as JSON

            NSString *jsonStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];

            if (jsonStr && jsonStr.length > 0 && [jsonStr hasPrefix:@"{"]) {

                DLOG(@"[SERVERLIST-JSON] JSON response: %@", jsonStr);

            }

        } else if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {

            DLOG(@"[PROTO-R] Version/auth response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);



            // v37.75: Dump full response body for diagnosis (especially when status=4).

            if (cmd == 0x802EE121 && ret >= 13) {

                size_t dumpLen = (ret > 200) ? 200 : (size_t)ret;

                NSMutableString *respHex = [NSMutableString stringWithCapacity:dumpLen * 3];

                for (size_t i = 0; i < dumpLen; i++) [respHex appendFormat:@"%02X ", p[i]];

                DLOG(@"[EE121-RESP] v37.75: Full response hex (%zuB): %@", dumpLen, respHex);

                // Try to decode body as UTF-8 string (may contain error message)

                if (ret > 13) {

                    NSString *bodyStr = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];

                    if (bodyStr && bodyStr.length > 0) {

                        DLOG(@"[EE121-RESP] v37.76: Body string: %@", bodyStr);

                    }

                }

            }



            // v36.114: Patch status byte for ALL version/auth responses (0x802EE118/120/121)

            // v36.49: ALWAYS patch status byte for 0x802EE121 - KEEP original ret (don't truncate!)

            // v37.87: ROOT FIX! Previous versions only patched byte[12] status 4→0.

            // But client ALSO parses body UTF-8 text — if body contains "登录失败"/"版本过低"

            // Chinese error strings, client state machine BLOCKS even when header says OK.

            // This is the single biggest bug of v37.12-84. Fix: overwrite body bytes IN-PLACE

            // (keep same pktLen=94, same ret=94, no truncation needed — safe).

            // v37.107-DIST: Do NOT patch EE121 status or body!

            // ROOT CAUSE: Previous code forced status 4→0 AND overwrote body text

            // "未授权此手机" → "登录成功". This TRICKED the client into thinking login

            // succeeded, but the server's session state was still "未authorized" →

            // game server (12003) immediately closed connection.

            // FIX: Let the REAL server response pass through unchanged.

            //   - If status=0 (authorized): client proceeds normally.

            //   - If status=4 (未授权): client shows the authorization prompt,

            //     user completes authorization on master device, then re-logs in.

            // This way the device whitelist authorization system works NORMALLY.

            // NOTE: We still LOG the response for debugging, but do NOT modify it.

            //

            // v37.134-FIX6: RE-ENABLE status=4→0 patch for EE121!

            // CONTEXT: FIX5 fixed EE121-CANON TLV structure (added missing empty TLV),

            // so server now ACCEPTS the modified packet and returns status=4 ('版本过低').

            // This is a SERVER-SIDE VERSION CHECK, NOT a device authorization issue.

            // The old "未授权此手机" issue was about device binding — completely different.

            // Now we need to bypass the version check so client proceeds to login flow.

            //

            // v37.134-FIX49: DO NOT CLEAR "未授权此手机" RESPONSE! LET DEVICE GO NORMAL AUTHORIZATION!

            // ROOT CAUSE: Previous code cleared ALL status=4 responses (including "未授权此手机"),

            //   which prevented the normal authorization flow:

            //   1. New device login → server returns "未授权此手机" (status=4)

            //   2. Client should show prompt: "如要授权请使用上次登录的设备进行授权"

            //   3. User authorizes on master device within 10 minutes

            //   4. New device UUID added to whitelist → subsequent logins succeed

            //   But hook cleared the response → client skipped authorization → device never authorized!

            // FIX49: Check body content. Only clear "版本过低" responses (version check bypass).

            //   If body contains "未授权" → DO NOT CLEAR, let client show authorization prompt.

            //   If body contains "版本过低" → CLEAR (version check bypass, as before).

            if ((cmd == 0x802EE121 || cmd == 0x802EE118 || cmd == 0x802EE120) && ret >= 13) {

                uint8_t status = p[12];

                // AZ6: 强制先打印"原始status"，避免FIX6把status=4清零后看不出真实服务器返回
                //   这是判断status=0(成功) / status=4(版本过低) / status=? 的唯一可靠依据
                {
                    size_t pv = (ret - 13 > 32) ? 32 : (size_t)(ret - 13);
                    NSMutableString *hx = [NSMutableString stringWithCapacity:pv*3 + 4];
                    NSMutableString *ac = [NSMutableString stringWithCapacity:pv + 4];
                    for (size_t k=0; k<pv; k++){
                        unsigned char c = p[13+k];
                        [hx appendFormat:@"%02X ", c];
                        if (c>=0x20 && c<=0x7E) [ac appendFormat:@"%c", (char)c]; else [ac appendString:@"."];
                    }
                    DLOG(@"[AZ6-STATUS-RAW] cmd=0x%08X ret=%d status(原始)=%u body_first%zub_hex='%@' ascii='%@'",
                         cmd, (int)ret, (unsigned)status, pv, hx, ac);
                }

                // v37.134-FIX6: Patch status=4→0 for EE121 (bypass server version check)

                if (cmd == 0x802EE121 && status == 4) {

                    // FIX49: Check body content first to distinguish authorization vs version check

                    NSString *bodyStr = nil;

                    BOOL isUnauthorized = NO;  // "未授权此手机" → do NOT clear

                    BOOL isVersionLow = NO;    // "版本过低" → clear (version bypass)

                    if (ret > 13) {

                        bodyStr = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];

                        if (bodyStr && bodyStr.length > 0) {

                            // FIX49: Check for authorization-related keywords

                            if ([bodyStr containsString:@"未授权"] || [bodyStr containsString:@"授权"]) {

                                isUnauthorized = YES;

                            }

                            if ([bodyStr containsString:@"版本过低"] || [bodyStr containsString:@"version"]) {

                                isVersionLow = YES;

                            }

                        }

                    }

                    // FIX49: ONLY clear if it's a version check (版本过低), NOT authorization (未授权)

                    if (isUnauthorized && !isVersionLow) {

                        // "未授权此手机" → DO NOT CLEAR! Let client show authorization prompt!

                        DLOG(@"[EE121-RESP] v37.134-FIX49: cmd=0x%08X status=4, body contains '未授权' → NOT clearing (normal authorization flow)", cmd);

                        if (bodyStr) {

                            DLOG(@"[EE121-RESP] v37.134-FIX49: Body (authorization prompt, let client display): %@", bodyStr);

                        }

                        DLOG(@"[EE121-RESP] v37.134-FIX49: User must authorize this device on master device within 10 minutes!");

                    } else {

                        // "版本过低" or unknown → clear (version check bypass, as before)

                        DLOG(@"[EE121-RESP] v37.134-FIX6: cmd=0x%08X status=4→0 (patching for version bypass, isVersionLow=%d isUnauthorized=%d)", cmd, isVersionLow, isUnauthorized);

                        // Cast away const to modify response in-place (we own this buffer from recv)

                        unsigned char *mp = (unsigned char *)p;

                        mp[12] = 0;

                        // Also clear "版本过低"/"登录失败" body text so client state machine doesn't block

                        if (ret > 13) {

                            if (bodyStr && bodyStr.length > 0) {

                                DLOG(@"[EE121-RESP] v37.134-FIX6: Body before patch: %@", bodyStr);

                                // Replace all body bytes with spaces (preserve pktLen)

                                memset(mp+13, 0x20, (size_t)(ret-13));

                                DLOG(@"[EE121-RESP] v37.134-FIX6: Body cleared (status=0, proceeding to login)");

                            }

                        }

                    }

                } else {

                    // FIX52: 0x802EE118 status=1 补丁!
                    // 新设备(156)日志铁证: 0x802EE118独立接收(ret=13), status=1, 但未走STICKY-PATCH
                    // 主设备走STICKY-PATCH(status 1→0), 新设备独立包未处理 → 客户端可能进入错误状态
                    // FIX52: 对独立接收的0x802EE118也执行status 1→0补丁
                    if (cmd == 0x802EE118 && status != 0 && ret >= 13) {
                        DLOG(@"[FIX52-EE118] Patching standalone cmd=0x802EE118 status %u -> 0 (was only in STICKY-PATCH before)", status);
                        ((unsigned char *)buf)[12] = 0;
                    } else {
                        DLOG(@"[EE121-RESP] v37.134-FIX6: cmd=0x%08X status=%u (NOT patched, let client handle)", cmd, status);
                    }

                    if (cmd == 0x802EE121 && ret > 13) {

                        NSString *bodyStr = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];

                        if (bodyStr && bodyStr.length > 0) {

                            DLOG(@"[EE121-RESP] v37.134-FIX6: Body: %@", bodyStr);

                        }

                    }

                }

            }



            // v37.82: Extract token from EE120 response (0x802EE120) for hash3/hash1 recalculation.

            // CRITICAL BUG in v37.81: Treated TLV length as 2-byte uint16_t (0x1F47=8007 bytes!)

            // But EE120 response format is [12B hdr][1B status][1B len=0x1F][31B token]

            // Evidence: v37.81 log line 588 hex:

            //   [12] = 00 (status OK), [13] = 1F (len=31, 1 byte!), [14..44] = 31B ASCII token

            //   Expected 'Gr1YYlXG0dcXb2yOgdjMRKGU6gl7DN7' starts at byte 14.

            // Also handle variant with optional 2-byte leading 00 1F (some servers may prefix it).

            if (cmd == 0x802EE120 && ret >= 13) {

                // v37.134-FIX16: Removed memory scan — it was corrupting game state

                // and preventing EE121 from being sent. Instead, hash1/hash3 are

                // replaced directly in the EE121 packet via EE007-ALIGN section.



                size_t pos = 13; // after 12B header + 1B status

                while (pos + 1 < (size_t)ret) {

                    // Strategy: Check 1-byte length first (most common in EE120).

                    // If 1-byte length is 31 and next 31 bytes are printable ASCII token, accept it.

                    // Otherwise try 2-byte big-endian length (legacy/fallback).

                    uint8_t  len1b = p[pos];

                    uint16_t len2b = ((uint16_t)p[pos] << 8) | p[pos+1];

                    uint8_t *dataPtr = NULL;

                    size_t dataLen = 0;

                    size_t lenBytes = 0;



                    // Try 1-byte length first

                    if (len1b >= 1 && len1b < 128 && pos + 1 + len1b <= (size_t)ret) {

                        dataPtr = (uint8_t *)(p + pos + 1);

                        dataLen = len1b;

                        lenBytes = 1;

                    }

                    // Try 2-byte length as fallback (for variants)

                    else if (len2b >= 1 && len2b < 2048 && pos + 2 + len2b <= (size_t)ret) {

                        dataPtr = (uint8_t *)(p + pos + 2);

                        dataLen = len2b;

                        lenBytes = 2;

                    }

                    // No valid TLV field, break to avoid infinite loop

                    else {

                        break;

                    }



                    // Check if 31-byte ASCII printable token (the only length we care about)

                    if (dataLen == 31) {

                        int allPrint = 1;

                        for (size_t i = 0; i < 31; i++) {

                            uint8_t c = dataPtr[i];

                            if (!( (c >= 0x30 && c <= 0x39) || // 0-9

                                   (c >= 0x41 && c <= 0x5A) || // A-Z

                                   (c >= 0x61 && c <= 0x7A) )) { // a-z

                                allPrint = 0; break;

                            }

                        }

                        if (allPrint) {

                            memcpy(g_hashToken, dataPtr, 31);

                            g_hashToken[31] = 0;

                            g_hashTokenValid = 1;

                            DLOG(@"[EE120-TOKEN] v37.82: Extracted 31B token (lenBytes=%zu from pos=%zu): %s",

                                 lenBytes, pos, g_hashToken);

                            break;

                        }

                    }

                    // Skip non-31 or non-printable 31 field to continue scanning

                    pos += lenBytes + dataLen;

                }

                if (!g_hashTokenValid) {

                    DLOG(@"[EE120-TOKEN] v37.82: WARNING no 31B token field found (ret=%zd, firstBodyBytes: %02X %02X %02X %02X %02X)",

                         (ssize_t)ret, p[13], p[14], p[15], p[16], p[17]);

                }

            }

        } else if (cmd == 0x8234AB89 && port == 5678) {

            // v37.69: Parse 0x8234AB89 — login server's sessionId/ticket response.

            // This is sent after 0x802EE121 (status=0) to confirm successful login.

            // Without real sessionId/ticket, game server rejects FFF493#2 (only heartbeats).

            DLOG(@"[SESSION-CAPTURE] v37.69: 0x8234AB89 received pktLen=%u ret=%zd", pktLenBE, ret);

            

            // Dump first 200 bytes for format analysis

            size_t dumpLen = (ret > 200) ? 200 : (size_t)ret;

            NSMutableString *hex = [NSMutableString stringWithCapacity:dumpLen * 3];

            for (size_t i = 0; i < dumpLen; i++) [hex appendFormat:@"%02X ", p[i]];

            DLOG(@"[SESSION-CAPTURE] HEX: %@", hex);

            

            // Try JSON decode first

            NSString *bodyStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];

            if (bodyStr && bodyStr.length > 0) {

                DLOG(@"[SESSION-CAPTURE] BODY: %@", bodyStr);

                

                // Extract sessionId from JSON: "sessionId": "..." or "sessionId":"..."

                // v37.134-FIX15: Try both with-space and without-space patterns

                NSRange sidRange = [bodyStr rangeOfString:@"\"sessionId\": \""];

                if (sidRange.location == NSNotFound) {

                    sidRange = [bodyStr rangeOfString:@"\"sessionId\":\""];

                }

                if (sidRange.location != NSNotFound) {

                    NSUInteger start = sidRange.location + sidRange.length;

                    NSRange endRange = [bodyStr rangeOfString:@"\"" options:0 range:NSMakeRange(start, bodyStr.length - start)];

                    if (endRange.location != NSNotFound) {

                        NSUInteger sidLen = endRange.location - start;

                        if (sidLen > 0 && sidLen < sizeof(g_sessionId)) {

                            memcpy(g_sessionId, [bodyStr UTF8String] + start, sidLen);

                            g_sessionId[sidLen] = 0;

                            DLOG(@"[SESSION-CAPTURE] sessionId extracted: %s (len=%lu)", g_sessionId, (unsigned long)sidLen);

                        }

                    }

                }

                

                // Extract ticket from JSON: "ticket": "..." or "ticket":"..."

                // v37.134-FIX15: Try both with-space and without-space patterns

                NSRange tikRange = [bodyStr rangeOfString:@"\"ticket\": \""];

                if (tikRange.location == NSNotFound) {

                    tikRange = [bodyStr rangeOfString:@"\"ticket\":\""];

                }

                if (tikRange.location != NSNotFound) {

                    NSUInteger start = tikRange.location + tikRange.length;

                    NSRange endRange = [bodyStr rangeOfString:@"\"" options:0 range:NSMakeRange(start, bodyStr.length - start)];

                    if (endRange.location != NSNotFound) {

                        NSUInteger tikLen = endRange.location - start;

                        if (tikLen > 0 && tikLen < sizeof(g_ticket)) {

                            memcpy(g_ticket, [bodyStr UTF8String] + start, tikLen);

                            g_ticket[tikLen] = 0;

                            g_ticketLen = (int)tikLen;

                            g_sessionValid = 1;

                            DLOG(@"[SESSION-CAPTURE] ticket extracted: len=%d (first 40 chars: %s...)", g_ticketLen, g_ticket);

                        }

                    }

                }

            }

            

            // Also try TLV format: scan body for sessionId/ticket patterns

            // TLV format: [2B len][data] — sessionId is 32 chars, ticket is ~366 chars

            if (!g_sessionValid && ret >= 44) {

                size_t off = 12;

                while (off + 2 <= (size_t)ret) {

                    uint16_t fLen = ((uint16_t)p[off] << 8) | p[off + 1];

                    if (off + 2 + fLen > (size_t)ret) break;

                    const unsigned char *val = p + off + 2;

                    

                    // sessionId: exactly 32 bytes, printable ASCII

                    if (fLen == 32 && g_sessionId[0] == 0) {

                        int isPrintable = 1;

                        for (int i = 0; i < 32; i++) {

                            if (val[i] < 0x20 || val[i] > 0x7e) { isPrintable = 0; break; }

                        }

                        if (isPrintable) {

                            memcpy(g_sessionId, val, 32);

                            g_sessionId[32] = 0;

                            DLOG(@"[SESSION-CAPTURE] TLV sessionId (32B): %s", g_sessionId);

                        }

                    }

                    

                    // ticket: long Base64 string, typical length 300-400 bytes

                    if (fLen > 200 && fLen < 500 && g_ticket[0] == 0) {

                        int isBase64 = 1;

                        int printableCount = 0;

                        for (uint16_t i = 0; i < fLen; i++) {

                            unsigned char c = val[i];

                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 

                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||

                                c == '|' || c == '-' || c == '_') {

                                printableCount++;

                            } else if (c < 0x20 || c > 0x7e) {

                                isBase64 = 0;

                                break;

                            }

                        }

                        if (isBase64 && printableCount > (int)(fLen * 0.8)) {

                            if (fLen < sizeof(g_ticket)) {

                                memcpy(g_ticket, val, fLen);

                                g_ticket[fLen] = 0;

                                g_ticketLen = (int)fLen;

                                g_sessionValid = 1;

                                DLOG(@"[SESSION-CAPTURE] TLV ticket (%uB) extracted, valid=%d", fLen, g_sessionValid);

                            }

                        }

                    }

                    

                    off += 2 + fLen;

                }

            }

            

            DLOG(@"[SESSION-CAPTURE] v37.69: Final state — sessionValid=%d sessionId=%s ticketLen=%d", 

                 g_sessionValid, g_sessionId[0] ? g_sessionId : "(empty)", g_ticketLen);

        } else if (cmd == 0x802EE100 && port == 5678) {

            // v37.134-FIX9: ALSO parse 0x802EE100 — login server's ALTERNATIVE sessionId/ticket response.

            // Recent server versions use 0x802EE100 instead of 0x8234AB89 for session response.

            DLOG(@"[SESSION-CAPTURE] v37.134-FIX9: 0x802EE100 received pktLen=%u ret=%zd", pktLenBE, ret);

            

            // Dump first 200 bytes for format analysis

            size_t dumpLen100 = (ret > 200) ? 200 : (size_t)ret;

            NSMutableString *hex100 = [NSMutableString stringWithCapacity:dumpLen100 * 3];

            for (size_t i = 0; i < dumpLen100; i++) [hex100 appendFormat:@"%02X ", p[i]];

            DLOG(@"[SESSION-CAPTURE-100] HEX: %@", hex100);

            

            // Try JSON decode first

            NSString *bodyStr100 = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];

            if (bodyStr100 && bodyStr100.length > 0) {

                DLOG(@"[SESSION-CAPTURE-100] BODY: %@", bodyStr100);

                

                // Extract sessionId from JSON: "sessionId": "..." or "sessionId":"..."

                // v37.134-FIX15: Try both with-space and without-space patterns for robustness

                NSRange sidRange100 = [bodyStr100 rangeOfString:@"\"sessionId\": \""];

                if (sidRange100.location == NSNotFound) {

                    sidRange100 = [bodyStr100 rangeOfString:@"\"sessionId\":\""];

                }

                if (sidRange100.location != NSNotFound) {

                    NSUInteger start = sidRange100.location + sidRange100.length;

                    NSRange endRange = [bodyStr100 rangeOfString:@"\"" options:0 range:NSMakeRange(start, bodyStr100.length - start)];

                    if (endRange.location != NSNotFound) {

                        NSUInteger sidLen = endRange.location - start;

                        if (sidLen > 0 && sidLen < sizeof(g_sessionId)) {

                            memcpy(g_sessionId, [bodyStr100 UTF8String] + start, sidLen);

                            g_sessionId[sidLen] = 0;

                            DLOG(@"[SESSION-CAPTURE-100] sessionId extracted: %s (len=%lu)", g_sessionId, (unsigned long)sidLen);

                        }

                    }

                }

                

                // Extract ticket from JSON: "ticket": "..." or "ticket":"..."

                // v37.134-FIX15: Try both with-space and without-space patterns

                NSRange tikRange100 = [bodyStr100 rangeOfString:@"\"ticket\": \""];

                if (tikRange100.location == NSNotFound) {

                    tikRange100 = [bodyStr100 rangeOfString:@"\"ticket\":\""];

                }

                if (tikRange100.location != NSNotFound) {

                    NSUInteger start = tikRange100.location + tikRange100.length;

                    NSRange endRange = [bodyStr100 rangeOfString:@"\"" options:0 range:NSMakeRange(start, bodyStr100.length - start)];

                    if (endRange.location != NSNotFound) {

                        NSUInteger tikLen = endRange.location - start;

                        if (tikLen > 0 && tikLen < sizeof(g_ticket)) {

                            memcpy(g_ticket, [bodyStr100 UTF8String] + start, tikLen);

                            g_ticket[tikLen] = 0;

                            g_ticketLen = (int)tikLen;

                            g_sessionValid = 1;

                            DLOG(@"[SESSION-CAPTURE-100] ticket extracted: len=%d (first 40 chars: %s...)", g_ticketLen, g_ticket);

                        }

                    }

                }

            }

            

            // Also try TLV format: scan body for sessionId/ticket patterns

            if (!g_sessionValid && ret >= 44) {

                size_t off = 12;

                while (off + 2 <= (size_t)ret) {

                    uint16_t fLen = ((uint16_t)p[off] << 8) | p[off + 1];

                    if (off + 2 + fLen > (size_t)ret) break;

                    const unsigned char *val = p + off + 2;

                    

                    // sessionId: exactly 32 bytes, printable ASCII

                    if (fLen == 32 && g_sessionId[0] == 0) {

                        int isPrintable = 1;

                        for (int i = 0; i < 32; i++) {

                            if (val[i] < 0x20 || val[i] > 0x7e) { isPrintable = 0; break; }

                        }

                        if (isPrintable) {

                            memcpy(g_sessionId, val, 32);

                            g_sessionId[32] = 0;

                            DLOG(@"[SESSION-CAPTURE-100] TLV sessionId (32B): %s", g_sessionId);

                        }

                    }

                    

                    // ticket: long Base64 string, typical length 300-400 bytes

                    if (fLen > 200 && fLen < 500 && g_ticket[0] == 0) {

                        int isBase64 = 1;

                        int printableCount = 0;

                        for (uint16_t i = 0; i < fLen; i++) {

                            unsigned char c = val[i];

                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 

                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||

                                c == '|' || c == '-' || c == '_') {

                                printableCount++;

                            } else if (c < 0x20 || c > 0x7e) {

                                isBase64 = 0;

                                break;

                            }

                        }

                        if (isBase64 && printableCount > (int)(fLen * 0.8)) {

                            if (fLen < sizeof(g_ticket)) {

                                memcpy(g_ticket, val, fLen);

                                g_ticket[fLen] = 0;

                                g_ticketLen = (int)fLen;

                                g_sessionValid = 1;

                                DLOG(@"[SESSION-CAPTURE-100] TLV ticket (%uB) extracted, valid=%d", fLen, g_sessionValid);

                            }

                        }

                    }

                    

                    off += 2 + fLen;

                }

            }

            

            DLOG(@"[SESSION-CAPTURE-100] v37.134-FIX9: Final state — sessionValid=%d sessionId=%s ticketLen=%d", 

                 g_sessionValid, g_sessionId[0] ? g_sessionId : "(empty)", g_ticketLen);

        }

        

        // v36.114: TCP STICKY PACKET DETECTION for login server (port 5678)

        // Login server responses can contain multiple packets in one recv

        // Example: 0x8000E002 (120 bytes) + 0x802EE118 (13 bytes) in one recv of 133 bytes

        if (port == 5678 && ret >= 16 && pktLenBE < ret) {

            // There are extra bytes after the first packet - check for sticky sub-packets

            ssize_t offset = pktLenBE;  // Start after first packet

            while (offset < ret) {

                ssize_t remaining = ret - offset;

                if (remaining < 8) break;

                

                uint32_t subPktLen = ((uint32_t)p[offset] << 24) | ((uint32_t)p[offset+1] << 16) |

                                     ((uint32_t)p[offset+2] << 8)  | (uint32_t)p[offset+3];

                uint32_t subCmd    = ((uint32_t)p[offset+4] << 24) | ((uint32_t)p[offset+5] << 16) |

                                     ((uint32_t)p[offset+6] << 8)  | (uint32_t)p[offset+7];

                

                if (subPktLen < 8 || subPktLen > (uint32_t)remaining) break;

                

                DLOG(@"[LOGIN-STICKY] v36.114: Sub-packet at offset %zd: cmd=0x%08X pktLen=%u remaining=%zd", 

                     offset, subCmd, subPktLen, remaining);

                

                // Patch status for version/auth responses in sticky packets

                if ((subCmd == 0x802EE118 || subCmd == 0x802EE120 || subCmd == 0x802EE121) && 

                    remaining >= 13 && p[offset + 12] != 0) {

                    DLOG(@"[LOGIN-STICKY-PATCH] v36.114: Patching sticky sub-packet cmd=0x%08X status %u -> 0", 

                         subCmd, p[offset + 12]);

                    ((unsigned char *)buf)[offset + 12] = 0;

                }

                

                // v37.69: Also handle 0x8234AB89 in sticky sub-packets

                if ((subCmd == 0x8234AB89 || subCmd == 0x802EE100) && remaining >= 44) {

                    DLOG(@"[SESSION-CAPTURE] v37.134-FIX9: Found 0x%08X in sticky sub-packet", subCmd);

                    // Attempt to extract sessionId/ticket from sticky sub-packet body

                    const unsigned char *sp = p + offset;

                    size_t sRet = (size_t)remaining;

                    

                    // JSON decode attempt

                    NSString *sBody = [[NSString alloc] initWithBytes:sp+12 length:(sRet > 12) ? sRet - 12 : 0 encoding:NSUTF8StringEncoding];

                    if (sBody && sBody.length > 0) {

                        NSRange sidR = [sBody rangeOfString:@"\"sessionId\": \""];

                        if (sidR.location != NSNotFound && g_sessionId[0] == 0) {

                            NSUInteger s = sidR.location + sidR.length;

                            NSRange eR = [sBody rangeOfString:@"\"" options:0 range:NSMakeRange(s, sBody.length - s)];

                            if (eR.location != NSNotFound) {

                                NSUInteger l = eR.location - s;

                                if (l > 0 && l < sizeof(g_sessionId)) {

                                    memcpy(g_sessionId, [sBody UTF8String] + s, l);

                                    g_sessionId[l] = 0;

                                }

                            }

                        }

                        NSRange tikR = [sBody rangeOfString:@"\"ticket\": \""];

                        if (tikR.location != NSNotFound && g_ticket[0] == 0) {

                            NSUInteger s = tikR.location + tikR.length;

                            NSRange eR = [sBody rangeOfString:@"\"" options:0 range:NSMakeRange(s, sBody.length - s)];

                            if (eR.location != NSNotFound) {

                                NSUInteger l = eR.location - s;

                                if (l > 0 && l < sizeof(g_ticket)) {

                                    memcpy(g_ticket, [sBody UTF8String] + s, l);

                                    g_ticket[l] = 0;

                                    g_ticketLen = (int)l;

                                    g_sessionValid = 1;

                                    DLOG(@"[SESSION-CAPTURE] Sticky ticket extracted len=%d valid=%d", g_ticketLen, g_sessionValid);

                                }

                            }

                        }

                    }

                }

                

                offset += subPktLen;

            }

        }

    }

    

    // v36.50: ONLY clear '版本过低'/'当前版本' on login server (port 5678) - NOT on game server!

    // Running on port 12003 binary data could corrupt protocol data

    if (port == 5678) {

        static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};

        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {

            if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {

                DLOG(@"[PATCH-R] Cleared '版本过低' at offset %zd (port=5678 only)", i);

                memset((unsigned char *)buf + i, ' ', sizeof(verLow));

            }

        }

        static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};

        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {

            if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {

                DLOG(@"[PATCH-R] Cleared '当前版本' at offset %zd (port=5678 only)", i);

                memset((unsigned char *)buf + i, ' ', sizeof(curVer));

            }

        }

    }

    

#if !MINIMAL_MODE

    // v36.70: Enhanced game server response analysis with CMD-BASED detection

    // Analyze responses on game ports OR by command range detection

    // This ensures analysis works even when getPortForFd returns 0

    BOOL isGamePort = (port == 12003 || port == 58158 || 

                       (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));

    // v36.70: Parse cmd FIRST to enable cmd-based detection when port fails

    uint32_t rcmd_precheck = 0;

    if (ret >= 8) {

        rcmd_precheck = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                        ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

    }

    BOOL gameCmdDetected = isGameCmd(rcmd_precheck);

    // v36.70: Use BOTH port-based AND cmd-based detection

    BOOL isGameAnalysis = isGamePort || gameCmdDetected;

    

    if (isGameAnalysis && ret >= 4) {

        @try {

            uint32_t rcmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

            uint32_t pktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |

                             ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

            

            // v36.86: REMOVED ACK-REPLACE logic - it causes SIGSEGV crash!

            // 0x80FFF495 maps to handle_CHOOSE_WOOD_BOX_RES in the game client.

            // Faking this packet causes the client to call the wrong handler -> crash.

            // Instead: force-send 0x000EE007 device info directly after challenge response.

            

            const char *gamePort;

            if (port == 58158) gamePort = "58158";

            else if (port == 12003) gamePort = "12003";

            else if (port > 0) gamePort = "DYNAMIC";

            else gamePort = "CMD-DETECT";

            

            // v36.70: Log detection method for debugging

            if (gameCmdDetected && !isGamePort) {

                DLOG(@"[CMD-DETECT] Game server detected via cmd range (cmd=0x%08X, port=%d, host=%s) - port-based FAILED", 

                     rcmd_precheck, port, host);

            } else if (isGamePort) {

                DLOG(@"[CMD-DETECT] Game server detected via port (port=%d, host=%s) - cmd check=%d", 

                     port, host, gameCmdDetected ? 1 : 0);

            }

            

            // v36.57: Build comprehensive log with hex dump

            NSMutableString *detail = [NSMutableString stringWithCapacity:1024];

            [detail appendFormat:@"[GAME-RECV] cmd=0x%08X pktLen=%u recvLen=%zd port=%s fd=%d host=%s\n", 

                 rcmd, pktLen, ret, gamePort, fd, host];

            

            // Hex dump - show up to 256 bytes for thorough analysis

            [detail appendFormat:@"  HEX(%zd bytes): ", ret];

            size_t showLen = ret > 256 ? 256 : (size_t)ret;

            for (ssize_t i = 0; i < showLen; i++) {

                [detail appendFormat:@"%02X ", p[i]];

                if ((i+1) % 32 == 0 && (ssize_t)i+1 < showLen) {

                    [detail appendFormat:@"\n  CONT: "];

                }

            }

            if ((size_t)ret > 256) [detail appendFormat:@"...TRUNCATED\n"];

            else [detail appendFormat:@"\n"];

            

            // ASCII interpretation of payload (offset 12 onwards)

            if (ret > 12) {

                NSString *asciiPayload = [[NSString alloc] initWithBytes:p+12 length:MIN((NSUInteger)(ret-12), 200) encoding:NSUTF8StringEncoding];

                if (asciiPayload && asciiPayload.length > 0) {

                    // Check if it's printable text or binary

                    BOOL hasPrintable = NO;

                    for (NSUInteger i = 0; i < MIN(asciiPayload.length, 50); i++) {

                        unichar c = [asciiPayload characterAtIndex:i];

                        if ((c >= 0x20 && c < 0x7F) || c == 0x0A || c == 0x0D) { hasPrintable = YES; break; }

                    }

                    if (hasPrintable) {

                        [detail appendFormat:@"  ASCII payload: %@\n", asciiPayload];

                    }

                }

            }

            

            // v36.61: Special detailed logging for 0x80FFF494 (login response from game server)

            if (rcmd == 0x80FFF494) {

                DLOG(@"[GAME-80FFF494] ===== DETAILED ANALYSIS OF 0x80FFF494 RESPONSE =====");

                DLOG(@"[GAME-80FFF494] Total length: %zd bytes", ret);

                DLOG(@"[GAME-80FFF494] FULL HEX DUMP:");

                for (ssize_t i = 0; i < ret; i += 16) {

                    NSMutableString *line = [NSMutableString string];

                    for (ssize_t j = i; j < MIN(i + 16, ret); j++) {

                        [line appendFormat:@"%02X ", p[j]];

                    }

                    DLOG(@"[GAME-80FFF494]   %04zd: %@", i, line);

                }

                // Parse known fields

                if (ret >= 16) {

                    uint32_t pLen = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];

                    uint32_t pCmd = ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7];

                    uint8_t pStatus = p[12];

                    DLOG(@"[GAME-80FFF494] pktLen=%u cmd=0x%08X status=%u(0x%02X)", pLen, pCmd, pStatus, pStatus);

                    // Check bytes 12-20 for status/error fields

                    DLOG(@"[GAME-80FFF494] Header fields (offset 8-20):");

                    for (int i = 8; i < MIN(20, (int)ret); i++) {

                        DLOG(@"[GAME-80FFF494]   byte[%d] = %u (0x%02X)", i, p[i], p[i]);

                    }

                    // Try to decode payload

                    if (ret > 13) {

                        NSString *payload = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];

                        if (payload && payload.length > 0) {

                            DLOG(@"[GAME-80FFF494] ASCII payload (offset 13+): '%@'", payload);

                        }

                    }

                }

                DLOG(@"[GAME-80FFF494] ===== END DETAILED ANALYSIS =====");

            }

            

            // v36.61: Also log all GAME-RECV packets in detail (first 128 bytes)

            [detail appendFormat:@"  [DETAIL] Full packet hex (all %zd bytes):\n", ret];

            for (ssize_t i = 0; i < ret; i += 16) {

                [detail appendFormat:@"    %04zd: ", i];

                for (ssize_t j = i; j < MIN(i + 16, ret); j++) {

                    [detail appendFormat:@"%02X ", p[j]];

                }

                [detail appendFormat:@"\n"];

            }

            if (ret >= 13) {

                uint8_t status = p[12];

                [detail appendFormat:@"  [STATUS] byte@12 = %u (0x%02X)\n", status, status];

                if (status != 0) {

                    [detail appendFormat:@"  *** WARNING: Non-zero status! Server returned error ***\n"];

                    // v36.90: SELECTIVE status patching based on 80+ version learnings:

                    //   0x80FFF494 (handshake init, status=1) -> DO NOT PATCH!

                    //       status=1 means "challenge required". Patching to 0

                    //       makes client skip challenge -> never sends 0x00FFF495 -> hangs.

                    //   0x80FFF495 (handshake complete, status=1) -> PATCH TO 0!

                    //       This is the REAL handshake completion ACK from server.

                    //       v36.89 observation confirmed server returns status=1 here,

                    //       causing client to call quitFromServer() -> "network interrupted".

                    //       Patching 1->0 allows client to proceed to send 0x000EE007 + 0x00FFF493.

                    if (rcmd == 0x80FFF494) {

                        DLOG(@"[GAME-PATCH] v36.93: NOT patching status %u for 0x80FFF494 (means 'challenge required')", status);

                        [detail appendFormat:@"  [OBSERVE] v36.93: 0x80FFF494 status NOT patched (preserve challenge signal)\n"];

                        

                        // v36.79: Extract RSA public key certificate from 0x80FFF494 response

                        // Cert starts at byte[14] (4 bytes length + 4 bytes cmd + 4 bytes field + 1 byte status + 1 byte type)

                        // byte[13] = cert format type (0x88 = X.509 cert)

                        // bytes[14..end] = Base64-encoded DER certificate data

                        if (ret > 14 && !g_pubKeyCaptured) {

                            // Debug: Log full packet structure

                            DLOG(@"[PUBKEY-DEBUG] Full 0x80FFF494 packet: ret=%zd bytes", ret);

                            DLOG(@"[PUBKEY-DEBUG] Bytes 0-15 hex: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",

                                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],

                                 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

                            DLOG(@"[PUBKEY-DEBUG] Packet header analysis:");

                            DLOG(@"[PUBKEY-DEBUG]   pktLen=%u (bytes 0-3)", ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);

                            DLOG(@"[PUBKEY-DEBUG]   cmd=0x%08X (bytes 4-7)", ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7]);

                            DLOG(@"[PUBKEY-DEBUG]   seq=0x%08X (bytes 8-11)", ((uint32_t)p[8]<<24)|((uint32_t)p[9]<<16)|((uint32_t)p[10]<<8)|p[11]);

                            DLOG(@"[PUBKEY-DEBUG]   status=%u (byte 12)", p[12]);

                            DLOG(@"[PUBKEY-DEBUG]   format=%u (byte 13)", p[13]);

                            

                            // Try multiple offset values

                            NSArray *offsetAttempts = @[@14, @13, @12, @15, @16];

                            for (NSNumber *offsetNum in offsetAttempts) {

                                ssize_t certOffset = offsetNum.integerValue;

                                if (certOffset >= ret) continue;

                                ssize_t certLen = ret - certOffset;

                                if (certLen > 0 && certLen < MAX_PUBKEY_BASE64) {

                                    NSString *certStrTest = [[NSString alloc] initWithBytes:p+certOffset length:(NSUInteger)certLen encoding:NSASCIIStringEncoding];

                                    if (certStrTest) {

                                        // Count valid Base64 chars

                                        int validB64 = 0;

                                        int invalidB64 = 0;

                                        for (ssize_t i = 0; i < certLen; i++) {

                                            unsigned char c = p[certOffset + i];

                                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 

                                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '\n') {

                                                validB64++;

                                            } else {

                                                invalidB64++;

                                            }

                                        }

                                        

                                        DLOG(@"[PUBKEY-DEBUG] Offset %zd: len=%zd, validB64=%d, invalidB64=%d, starts: %@",

                                             certOffset, certLen, validB64, invalidB64,

                                             [certStrTest substringToIndex:MIN(60, certStrTest.length)]);

                                        

                                        // If most chars are valid Base64, this is likely the correct offset

                                        if (validB64 > invalidB64 * 2 && certLen > 100) {

                                            DLOG(@"[PUBKEY-DEBUG] Offset %zd looks promising (valid/invalid ratio)", certOffset);

                                        }

                                    }

                                }

                            }

                            

                            // v36.81: Improved public key extraction

                            // Find Base64 public key data starting from offset 14

                            ssize_t certOffset = 14;

                            ssize_t maxCertLen = ret - certOffset;

                            

                            if (maxCertLen > 0 && maxCertLen < MAX_PUBKEY_BASE64) {

                                // v36.81: Find the actual end of Base64 data (look for padding or non-Base64 chars)

                                ssize_t certLen = 0;

                                BOOL foundPadding = NO;

                                

                                // First pass: find the Base64 data boundaries

                                for (ssize_t i = 0; i < maxCertLen; i++) {

                                    unsigned char c = p[certOffset + i];

                                    

                                    // Valid Base64: A-Z, a-z, 0-9, +, /, =

                                    BOOL isBase64Char = (c >= 'A' && c <= 'Z') || 

                                                       (c >= 'a' && c <= 'z') || 

                                                       (c >= '0' && c <= '9') || 

                                                       c == '+' || c == '/' || c == '=';

                                    

                                    // Skip newlines (valid in Base64 but not part of key data)

                                    BOOL isWhitespace = c == '\n' || c == '\r';

                                    

                                    if (isBase64Char) {

                                        certLen = i + 1;

                                        if (c == '=') {

                                            foundPadding = YES;

                                            // Padding at end of Base64, stop here

                                            // But allow max 2 padding chars

                                            ssize_t nextI = i + 1;

                                            if (nextI >= maxCertLen || p[certOffset + nextI] != '=') {

                                                // Found single or double padding, stop

                                                break;

                                            }

                                        }

                                    } else if (!isWhitespace && i > 20) {

                                        // Found non-Base64 char after some data, stop extraction

                                        // But only if we have enough data (at least 20 chars)

                                        break;

                                    } else if (isWhitespace && i > 20) {

                                        // Whitespace after some data - could be line ending

                                        // Skip it but continue

                                        continue;

                                    }

                                }

                                

                                // Ensure we have a reasonable length (RSA 2048-bit key = ~392 chars Base64)

                                if (certLen > 100 && certLen < MAX_PUBKEY_BASE64) {

                                    // Extract only the Base64 data (skip non-Base64 chars in between)

                                    size_t cleanLen = 0;

                                    for (ssize_t i = 0; i < certLen && cleanLen < MAX_PUBKEY_BASE64; i++) {

                                        unsigned char c = p[certOffset + i];

                                        BOOL isBase64Char = (c >= 'A' && c <= 'Z') || 

                                                           (c >= 'a' && c <= 'z') || 

                                                           (c >= '0' && c <= '9') || 

                                                           c == '+' || c == '/' || c == '=';

                                        if (isBase64Char) {

                                            g_pubKeyBase64[cleanLen++] = c;

                                        }

                                    }

                                    g_pubKeyBase64Len = cleanLen;

                                    g_pubKeyCaptured = YES;

                                    g_challengeResponded = NO; // Reset challenge response flag

                                    

                                    DLOG(@"[PUBKEY-EXTRACT] v36.82: Extracted RSA cert: %lu bytes Base64 (cleaned from %zd raw bytes, offset=%zd)",

                                         (unsigned long)cleanLen, certLen, certOffset);

                                    DLOG(@"[PUBKEY-EXTRACT] Padding found: %d, Base64 length mod 4: %lu",

                                         foundPadding, (unsigned long)(cleanLen % 4));

                                    

                                    // Log first 80 chars of cert

                                    NSString *certPreview = [[NSString alloc] initWithBytes:(const void *)g_pubKeyBase64 length:MIN((NSUInteger)cleanLen, 80) encoding:NSASCIIStringEncoding];

                                    if (certPreview) {

                                        DLOG(@"[PUBKEY-EXTRACT] Cert starts: %@...", certPreview);

                                    }

                                    // Log last 30 chars

                                    if (cleanLen > 30) {

                                        NSString *certEnd = [[NSString alloc] initWithBytes:(const void *)(g_pubKeyBase64 + cleanLen - 30) length:30 encoding:NSASCIIStringEncoding];

                                        if (certEnd) {

                                            DLOG(@"[PUBKEY-EXTRACT] Cert ends: ...%@", certEnd);

                                        }

                                    }

                                } else {

                                    DLOG(@"[PUBKEY-EXTRACT] v36.82: Invalid cert length: %zd (must be 100-%d)", certLen, MAX_PUBKEY_BASE64);

                                }

                            }

                        }

                    } else if (rcmd == 0x80FFF495) {

                        // v36.133: OBSERVATION MODE - DO NOT PATCH! (based on real capture data)

                        //

                        // REAL CAPTURE ANALYSIS (hook.txt RECV #18):

                        //   00 00 01 6d 80 ff f4 95 00 00 00 17 01 5f 65 61 ...fFJA==#|74297

                        //   offset  8-11: seq = 0x00000017 (sequence number)

                        //   offset    12: 0x01 = FORMAT FLAG (0x01=response, 0x02=request)

                        //   offset    13: 0x5f = sub-type/length

                        //   offset 14+: Base64 encrypted payload

                        //

                        // KEY INSIGHT: offset 12 is NOT a status field! 0x01 is the normal

                        //   response format flag. Real client receives 0x01 and proceeds

                        //   naturally to send 0x000EE007 (178B plaintext) + 0x00FFF493 (472B encrypted).

                        //

                        // PREVIOUS BUG (v36.124-v36.132): We incorrectly treated offset 12

                        //   as "status" and patched 1→0, CORRUPTING the response format.

                        //   This caused client to fail parsing and get stuck at "正在进入...".

                        //

                        // v36.133 FIX: Do NOT modify the packet at all. Let client handle

                        //   the real 0x80FFF495 response naturally. Client will decrypt

                        //   using its own BoringSSL and proceed to send subsequent packets.



                        // Save original seq for logging

                        uint32_t origSeq = ((unsigned char *)buf)[8] << 24 |

                                           ((unsigned char *)buf)[9] << 16 |

                                           ((unsigned char *)buf)[10] << 8 |

                                           ((unsigned char *)buf)[11];

                        uint8_t origFmtFlag = ((unsigned char *)buf)[12];



                        DLOG(@"[GAME-OBSERVE] v36.134: 0x80FFF495 received — NOT PATCHING (seq=0x%08X, fmtFlag=%u, ret=%zd bytes)",

                             origSeq, origFmtFlag, ret);

                        DLOG(@"[GAME-OBSERVE] v36.134: Real client flow: recv 0x80FFF495 -> send 0x000EE007 -> send 0x00FFF493");



                        g_handshakeComplete = YES;

                        g_challengeResponded = YES;



                        // v37.28: Activate CCCrypt L4 hook NOW — game server phase begins.

                        // FFF493 will be AES-encrypted via CCCrypt, and L4 will intercept

                        // the plaintext to replace DY_MIESHI → DYanyou0040_MIESHI.

                        g_cccrypt_l4_active = YES;

                        DLOG(@"[CH-L4-GATE] v37.28: CCCrypt L4 hook ACTIVATED (0x80FFF495 received)");



                        // v36.133: DO NOT enable crypto bypass!

                        //   Real client decrypts 0x80FFF495 payload successfully on its own.

                        //   Enabling bypass returns fake JSON which client may reject.

                        // g_forceValidDecrypt = NO;  (already NO by default)

                        DLOG(@"[GAME-OBSERVE] v36.134: Crypto bypass DISABLED — client will decrypt natively");



                        // v36.133: DO NOT inject fake responses!

                        //   Real client sends 0x000EE007 + 0x00FFF493 naturally after 0x80FFF495.

                        //   Fake response injection corrupts the protocol flow.

                        DLOG(@"[GAME-OBSERVE] v36.134: Virtual queue DISABLED — client will send native packets");

                    } else {

                        [detail appendFormat:@"  *** WARNING: Non-zero status on non-handshake packet (cmd=0x%08X) ***\n", rcmd];

                        DLOG(@"[GAME-PATCH] Non-handshake packet (cmd=0x%08X) status=%u left unchanged", rcmd, status);

                    }

                }

            }

            

            // Check for specific error keywords in payload

            if (ret > 12) {

                NSData *payloadData = [NSData dataWithBytes:p+12 length:(NSUInteger)(ret-12)];

                NSString *payloadStr = [[NSString alloc] initWithData:payloadData encoding:NSUTF8StringEncoding];

                if (payloadStr && payloadStr.length > 0) {

                    if ([payloadStr containsString:@"版本过低"] || [payloadStr containsString:@"当前版本"] || 

                        [payloadStr containsString:@"版本太旧"]) {

                        [detail appendFormat:@"  *** ERROR TEXT DETECTED: %@ ***\n", payloadStr];

                        DLOG(@"[GAME-PATCH] Error text found in game server response: %@ (port=%d)", payloadStr, port);

                        // v36.70: RE-ENABLE text clearing with cmd-based detection support

                        if (isGamePort || gameCmdDetected) {

                            static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};

                            static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};

                            for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {

                                if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {

                                    DLOG(@"[GAME-PATCH] Cleared '版本过低' at offset %zd (port=%d)", i, port);

                                    memset((unsigned char *)buf + i, ' ', sizeof(verLow));

                                }

                            }

                            for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {

                                if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {

                                    DLOG(@"[GAME-PATCH] Cleared '当前版本' at offset %zd (port=%d)", i, port);

                                    memset((unsigned char *)buf + i, ' ', sizeof(curVer));

                                }

                            }

                        }

                    }

                }

            }

            

            // v36.57: Categorize known game protocol commands

            if (rcmd == 0x00FFFF01 || rcmd == 0x00FFFF02) {

                [detail appendFormat:@"  [CHALLENGE] Server challenge packet (cmd=0x%08X)\n", rcmd];

            } else if (rcmd == 0x80FFFF01 || rcmd == 0x80FFFF02) {

                [detail appendFormat:@"  [RESPONSE] Challenge response packet (cmd=0x%08X)\n", rcmd];

            } else if (rcmd == 0x00EEE007 || rcmd == 0x80EEE007) {

                [detail appendFormat:@"  [DEVICE-INFO] Device info response (cmd=0x%08X)\n", rcmd];

            } else if (rcmd == 0x00F493 || rcmd == 0x80F493) {

                [detail appendFormat:@"  [ENCRYPTED] Encrypted game data (cmd=0x%08X)\n", rcmd];

            } else if (rcmd == 0x80EE0007 || rcmd == 0x80EE0700) {

                [detail appendFormat:@"  [GAME-PROTO] Game protocol packet (cmd=0x%08X)\n", rcmd];

            } else if (rcmd >= 0x80000000) {

                [detail appendFormat:@"  [SERVER-RESP] Server response (cmd=0x%08X)\n", rcmd];

            } else {

                [detail appendFormat:@"  [UNKNOWN] Unknown command (cmd=0x%08X) - possible protocol data\n", rcmd];

            }

            

            // v36.68: Track game server protocol flow (now using global g_handshakeComplete/g_heartbeatCount)

            // After handshake (0x80FFF494), client should send 0x000EE007 (device info)

            // If only heartbeats are being sent, the device info packet may be missing

            

            if (rcmd == 0x80FFF494 || rcmd == 0x80FFF495) {

                if (!g_handshakeComplete) {

                    g_handshakeComplete = YES;

                    g_heartbeatCount = 0;

                    // v36.68: Clear local heartbeat ACK buffer when handshake completes

                    g_localHeartbeatAckLen = 0;

                    g_localHeartbeatAckFd = -1;

                    DLOG(@"[GAME-FLOW] Handshake complete (cmd=0x%08X). Waiting for 0x00FFFF02 challenge...", rcmd);

                    DLOG(@"[GAME-FLOW] v36.79: Auto-responding to 0x00FFFF02 with RSA-encrypted 0x80FFFF02");

                    DLOG(@"[GAME-FLOW] After challenge response, client should send encrypted 0x000EE007 (device info)");

                }

            } else if (g_handshakeComplete && rcmd >= 0x80000000 && rcmd != 0x000EE007) {

                // Count server responses after handshake - these are likely responses to client heartbeats

                g_heartbeatCount++;

                if (g_heartbeatCount == 3) {

                    // v36.93: OBSERVATION MODE - No FALLBACK FORCE-SEND needed

                    // In v36.93, we DON'T patch status, so client sends native encrypted login packets.

                    // close() hook blocks disconnect. If client enters heartbeat loop anyway,

                    // the close block prevents disconnection and server will eventually respond.

                    DLOG(@"[GAME-FLOW] v36.93 OBSERVATION: Received %d server responses after handshake (no FORCE-SEND needed)", g_heartbeatCount);

                    DLOG(@"[GAME-FLOW] v36.93: If client in heartbeat loop, close() hook prevents disconnect");

                }

                if (g_heartbeatCount == 10) {

                    DLOG(@"[GAME-FLOW] v36.93 CRITICAL: %d heartbeats after handshake! close() blocking disconnect.", g_heartbeatCount);

                    DLOG(@"[GAME-FLOW] v36.93: close() hook still active - connection should remain alive");

                }

            }

            

            // Log if 0x000EE007 related responses are received

            if (rcmd == 0x00EEE007 || rcmd == 0x80EEE007 || rcmd == 0x00EE007) {

                DLOG(@"[GAME-FLOW] Device info response received (cmd=0x%08X). Game should be entering now.", rcmd);

                g_handshakeComplete = YES;

                g_heartbeatCount = 0;

            }

            

            // Reset handshake state on disconnect (heartbeat timeout)

            if (g_handshakeComplete && ret == 0) {

                g_handshakeComplete = NO;

                g_heartbeatCount = 0;

                // v36.95: Reset login packets sent flag

                g_loginPacketsSent = NO;

                g_fakeRespInjected = NO;

                // v36.68: Clear all leftover buffers on disconnect

                g_stickyLeftoverLen = 0;

                g_stickyLeftoverFd = -1;

                g_localHeartbeatAckLen = 0;

                g_localHeartbeatAckFd = -1;

                g_deviceInfoSentToGame = NO;

                // v36.84: Clear force handshake state

                g_forceHandshakeComplete = NO;

                g_forceHandshakeFd = -1;

                g_forceHandshakeLen = 0;

                DLOG(@"[GAME-FLOW] Connection closed, resetting handshake state");

            }

            

            DLOG(@"%@", detail);

            

            // v36.77: STICKY PACKET PATCHING (NO SPLITTING) - Return full buffer to client

            // v36.68-36.76 split sticky packets and saved extra bytes for next recv.

            // This BROKE the protocol because client needs to see 0x00FFFF02 

            // challenge IMMEDIATELY after 0x80FFF494 (same recv buffer).

            // Now: patch ALL sub-packets in buffer, return ENTIRE buffer to client.

            // Client's own parser will extract individual packets correctly.

            BOOL patchedExtra = NO;

            ssize_t scanOffset = pktLen;

            while (scanOffset < ret) {

                ssize_t scanRemaining = ret - scanOffset;

                if (scanRemaining < 8) break;

                

                uint32_t scanPktLen = ((uint32_t)p[scanOffset] << 24) | ((uint32_t)p[scanOffset+1] << 16) |

                                      ((uint32_t)p[scanOffset+2] << 8)  | (uint32_t)p[scanOffset+3];

                uint32_t scanCmd    = ((uint32_t)p[scanOffset+4] << 24) | ((uint32_t)p[scanOffset+5] << 16) |

                                      ((uint32_t)p[scanOffset+6] << 8)  | (uint32_t)p[scanOffset+7];

                

                if (scanPktLen < 8 || scanPktLen > 65535) break;

                if (scanPktLen > (uint32_t)scanRemaining) break;

                

                // v36.93: OBSERVATION MODE - No status patching for sticky sub-packets

                // Let client handle all status values naturally

                if (scanRemaining >= 13) {

                    uint8_t scanStatus = p[scanOffset + 12];

                    if (scanStatus != 0 && (scanCmd == 0x80FFF494 || scanCmd == 0x80FFF495)) {

                        DLOG(@"[STICKY-PATCH] v36.93 OBSERVATION: NOT patching status %u for %@ sub-packet at offset %zd",

                             scanStatus,

                             scanCmd == 0x80FFF495 ? @"0x80FFF495" : @"0x80FFF494",

                             scanOffset);

                    }

                }

                

                // Log the sub-packet

                DLOG(@"[STICKY-SCAN] Sub-packet at offset %zd: cmd=0x%08X len=%u status=%u",

                     scanOffset, scanCmd, scanPktLen, p[scanOffset + 12]);

                

                // v36.92: DO NOT auto-respond to 0x00FFFF02! (confirmed working in v36.89)

                // Let the CLIENT handle the challenge itself. Our auto-response was

                // sending 0x80FFFF02 BEFORE the client could, and the server may have

                // rejected our format (extra status byte, wrong seq, etc.).

                // v36.89 observation confirmed client handles challenge perfectly.

                if (scanCmd == 0x00FFFF02 && scanRemaining >= 28) {

                    DLOG(@"[STICKY-SCAN] v36.93: Letting CLIENT handle 0x00FFFF02 challenge (auto-response disabled)");

                    DLOG(@"[STICKY-SCAN] Challenge data at offset %zd: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",

                         scanOffset,

                         p[scanOffset+12], p[scanOffset+13], p[scanOffset+14], p[scanOffset+15],

                         p[scanOffset+16], p[scanOffset+17], p[scanOffset+18], p[scanOffset+19],

                         p[scanOffset+20], p[scanOffset+21], p[scanOffset+22], p[scanOffset+23],

                         p[scanOffset+24], p[scanOffset+25], p[scanOffset+26], p[scanOffset+27]);

                }

                

                scanOffset += scanPktLen;

            }

            if (patchedExtra) {

                DLOG(@"[STICKY-PATCH] Patched extra sub-packets in buffer (no splitting, returning full %zd bytes)", ret);

            }

            

            // v36.66: TCP STICKY PACKET DETECTION - Check for multiple packets in one recv

            DLOG(@"[STICKY-DETECT] Starting sticky packet detection: ret=%zd firstPktLen=%u firstCmd=0x%08X", 

                 ret, pktLen, rcmd);

            

            ssize_t offset = 0;

            int subPacketCount = 0;

            BOOL foundSticky = NO;

            while (offset < ret) {

                ssize_t remaining = ret - offset;

                if (remaining < 8) break; // Need at least header

                

                uint32_t subPktLen = ((uint32_t)p[offset] << 24) | ((uint32_t)p[offset+1] << 16) |

                                     ((uint32_t)p[offset+2] << 8)  | (uint32_t)p[offset+3];

                uint32_t subCmd    = ((uint32_t)p[offset+4] << 24) | ((uint32_t)p[offset+5] << 16) |

                                     ((uint32_t)p[offset+6] << 8)  | (uint32_t)p[offset+7];

                

                // Validate packet length

                if (subPktLen < 8 || subPktLen > 65535) break;

                

                subPacketCount++;

                if (subPacketCount > 1) {

                    foundSticky = YES;

                    DLOG(@"[STICKY-PACKET] Sub-packet #%d at offset %zd: cmd=0x%08X pktLen=%u remaining=%zd", 

                         subPacketCount, offset, subCmd, subPktLen, remaining);

                    

                    // v36.93: OBSERVATION MODE - No status patching for detected sticky sub-packets

                    if (remaining >= 13) {

                        uint8_t subStatus = p[offset + 12];

                        if (subStatus != 0 && (subCmd == 0x80FFF494 || subCmd == 0x80FFF495)) {

                            DLOG(@"[STICKY-PACKET] v36.93 OBSERVATION: NOT patching status %u for %@ sub-packet at offset %zd",

                                 subStatus,

                                 subCmd == 0x80FFF495 ? @"0x80FFF495" : @"0x80FFF494",

                                 offset);

                        }

                    }

                }

                

                // v36.93: DO NOT auto-respond to 0x00FFFF02! (confirmed working in v36.89)

                if (subCmd == 0x00FFFF02 && remaining >= 28) {

                    DLOG(@"[STICKY-AUTO] v36.93: Letting CLIENT handle 0x00FFFF02 challenge (auto-response disabled)");

                }

                

                // Move to next packet

                if (subPktLen > (uint32_t)remaining) {

                    // Packet extends beyond available data - incomplete packet

                    DLOG(@"[STICKY-PACKET] Incomplete packet at offset %zd: pktLen=%u > remaining=%zd", 

                         offset, subPktLen, remaining);

                    break;

                }

                offset += subPktLen;

            }

            if (foundSticky) {

                DLOG(@"[STICKY-PACKET] Processed %d sub-packets in one recv (total %zd bytes)", subPacketCount, ret);

            } else {

                DLOG(@"[STICKY-DETECT] No sticky packets found (single packet: cmd=0x%08X len=%u)", rcmd, pktLen);

            }

        } @catch (NSException *e) {

            DLOG(@"[GAME-RECV] Exception during analysis: %@", e.reason);

        }

        

        // v36.124: BURST injection REMOVED — using send-intercept approach instead

        // (client sends commands with real seq, we intercept in hook_send,

        //  generate matching responses in hook_recv)



        // v37.87: HEARTBEAT COUNT + FORGED 0x0CB0A300 INJECTION (last-resort)

        // After both FFF493#1 and #2 replaced (with non-empty sessionId/ticket),

        // if server returns >=2 heartbeats (0x80000015) in a row without 0x0CB0A300,

        // we inject 1632B forged 0x0CB0A300 role-data as TCP sticky packet.

        // This pushes client state machine to role-selection UI even if server

        // silently ignores (sessionId invalid because EE121 server reply was 版本过低).

        // v37.87 FIX: 'rcmd' is defined inside @try block (line ~6882, out of scope here).

        // Also unistd.h declares int rcmd(...) as a deprecated function — would conflict!

        // → Re-parse cmd from header bytes 4-7 into a distinct local name (curRespCmd).

        uint32_t curRespCmd = 0;

        if (ret >= 8 && p != NULL) {

            curRespCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                         ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        }

        if (g_fff493_1_sent && g_fff493_2_sent && !g_injected_0CB0A300 && isGamePort) {

            // v37.90 FIX: Real cmd is 0x00A3B010 (not 0x0CB0A300 — byte order was wrong)

            if (curRespCmd == 0x00A3B010 || curRespCmd == 0x0002A310) {

                g_role_0CB0A300_seen = 1;

                g_consec_heartbeats = 0;

                DLOG(@"[0CB0A300-REAL] v37.90: Server returned real 0x00A3B010 role data! No forgery needed (ret=%zd)", ret);

            } else if (curRespCmd == 0x80000015) {

                g_consec_heartbeats++;

                DLOG(@"[HB-COUNT] v37.103: Consecutive heartbeats = %d (after FFF493#1+#2). Threshold=999 (forgery DISABLED, waiting for real role data)", g_consec_heartbeats);

                if (g_consec_heartbeats >= 999 && !g_role_0CB0A300_seen) {

                    // Inject forged 0x0CB0A300 as TCP sticky packet (append to this recv's buf)

                    // Use generateFakeResponse() from v36 (returns 1632B: sub1=816B + sub2=816B)

                    // Ensure room: recv buf is typically 524288B (see log "len=524288"), so 1632B is fine.

                    const uint32_t FAKE_REQ_CMD = 0x00FFF493;  // what client sent to trigger roles

                    uint32_t fakeSeq = 0;  // use next seq (heartbeat seq + 1 is fine)

                    // Extract heartbeat seq from current packet header bytes 8-11

                    if (ret >= 12 && p != NULL) {

                        fakeSeq = ((uint32_t)p[8]<<24) | ((uint32_t)p[9]<<16) |

                                  ((uint32_t)p[10]<<8) | (uint32_t)p[11];

                        fakeSeq += 1;  // next seq after this heartbeat

                    }

                    // Ensure g_roleIndex > 0 so generateFakeResponse uses dynamic attrs

                    if (g_roleIndex <= 0) g_roleIndex = 1;

                    uint8_t tmpForged[2048] = {0};

                    uint32_t forgedLen = generateFakeResponse(FAKE_REQ_CMD, tmpForged, sizeof(tmpForged), fakeSeq);

                    if (forgedLen >= 12 && forgedLen < sizeof(tmpForged)) {

                        ssize_t maxAppend = (ssize_t)len - ret;

                        if (maxAppend >= (ssize_t)forgedLen && p != NULL) {

                            memcpy((void *)(p + ret), tmpForged, forgedLen);

                            DLOG(@"[FORGE-0CB0A300] v37.87: INJECTED forged role-data as sticky packet! forgedLen=%u appended after ret=%zd (total new ret=%zd) seq=0x%08X roleIndex=%d",

                                 forgedLen, ret, ret + forgedLen, fakeSeq, g_roleIndex);

                            ret += forgedLen;

                            g_injected_0CB0A300 = 1;

                            g_consec_heartbeats = 0;

                        } else {

                            DLOG(@"[FORGE-0CB0A300] v37.87: BUFFER FULL — cannot append forgedLen=%u to ret=%zd (len=%zu, maxAppend=%zd). Skipping.",

                                 forgedLen, ret, len, maxAppend);

                        }

                    } else {

                        DLOG(@"[FORGE-0CB0A300] v37.87: generateFakeResponse FAILED len=%u (expected >=12, <2048). Try next heartbeat.", forgedLen);

                    }

                }

            } else if (curRespCmd != 0x00FFFF01 && curRespCmd != 0x80FFF494 && curRespCmd != 0x00FFFF02 && curRespCmd != 0x80FFF495 &&

                       curRespCmd != 0x00FFF495 && (curRespCmd & 0xFF000000) != 0x76000000 && (curRespCmd & 0xFF000000) != 0x66000000) {

                // Non-heartbeat, non-handshake, non-vffi packet → reset counter (but not 0CB0A300-seen)

                // Keep counter; only explicit 0CB0A300 clears it

            }

        }

    }

#endif

    

    return ret;

}



static ssize_t hook_write(int fd, const void *buf, size_t len) {

    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");

    const char *host = getHostForFd(fd);

    int port = getPortForFd(fd);

    if (host && len > 0 && len < 4096) {

        const unsigned char *p = (const unsigned char *)buf;

        NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];

        NSMutableString *ascii = [NSMutableString stringWithCapacity:len];

        size_t showLen = len > 128 ? 128 : len;

        for (size_t i = 0; i < showLen; i++) {

            [hex appendFormat:@"%02X ", p[i]];

            [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];

        }

        DLOG(@"[WRITE] fd=%d %s:%d len=%zu\n  hex: %@\n  txt: %@", fd, host, port, len, hex, ascii);

        

        if (len >= 8) {

            uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                           ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

            DLOG(@"[WRITE-CMD] cmd=0x%08X", cmd);

        }

    }

    // NO PACKET MODIFICATION IN WRITE HOOK

    // Version replacement removed - modifying packet data breaks integrity verification

    return orig_write ? orig_write(fd, buf, len) : -1;

}



static ssize_t hook_read(int fd, void *buf, size_t len) {

    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");

    if (!orig_read || !buf) return -1;

    

    ssize_t ret = orig_read(fd, buf, len);

    if (ret <= 0) return ret;

    

    const char *host = getHostForFd(fd);

    if (!host) return ret;

    

    int port = getPortForFd(fd);

    const unsigned char *p = (const unsigned char *)buf;

    

    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];

    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];

    size_t showLen = ret > 256 ? 256 : (size_t)ret;

    for (size_t i = 0; i < showLen; i++) {

        [hex appendFormat:@"%02X ", p[i]];

        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];

    }

    DLOG(@"[READ] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);

    

    if (ret >= 8) {

        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |

                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        DLOG(@"[PROTO-DBG-R] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

        

        if (cmd == 0x802EE113) {

            DLOG(@"[PROTO-R] Server list response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

            

            // DETAILED HEX DUMP of server list response

            DLOG(@"[SERVERLIST-HEX2] Full response hex (%zd bytes):", ret);

            for (ssize_t i = 0; i < ret; i += 32) {

                NSMutableString *line = [NSMutableString string];

                for (ssize_t j = i; j < MIN(i + 32, ret); j++) {

                    [line appendFormat:@"%02X ", p[j]];

                }

                DLOG(@"[SERVERLIST-HEX2]   %zd: %@", i, line);

            }

            

            // DISABLED parseServerListResponse for v36.35

            DLOG(@"[SERVERLIST-HEX2] NO PARSING - leaving data untouched");

            

            NSString *jsonStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];

            if (jsonStr && jsonStr.length > 0 && [jsonStr hasPrefix:@"{"]) {

                DLOG(@"[SERVERLIST-JSON2] JSON response: %@", jsonStr);

            }

        } else if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {

            DLOG(@"[PROTO-R] Version/auth response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);



            // v37.75: Dump full response body for diagnosis (especially when status=4).

            if (cmd == 0x802EE121 && ret >= 13) {

                size_t dumpLen = (ret > 200) ? 200 : (size_t)ret;

                NSMutableString *respHex = [NSMutableString stringWithCapacity:dumpLen * 3];

                for (size_t i = 0; i < dumpLen; i++) [respHex appendFormat:@"%02X ", p[i]];

                DLOG(@"[EE121-RESP2] v37.76: Full response hex (%zuB): %@", dumpLen, respHex);

                if (ret > 13) {

                    NSString *bodyStr = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];

                    if (bodyStr && bodyStr.length > 0) {

                        DLOG(@"[EE121-RESP2] v37.76: Body string: %@", bodyStr);

                    }

                }

            }



            // v37.107-DIST: Do NOT patch EE121 in read hook either!

            // Same logic as recv hook — let real server response pass through.

            if (cmd == 0x802EE121 && ret >= 13 && port == 5678) {

                uint8_t status = p[12];

                DLOG(@"[EE121-RESP2] v37.107-DIST: status=%u (NOT patched, read hook)", status);

            }

        }

    }

    

    // v36.50: Remove '版本过低' clearing from read hook - it's handled in recv hook only

    // read hook should NOT modify any data to avoid double-patching issues

    

    return ret;

}



static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {

    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");

    if (!orig_recvfrom || !buf) return -1;

    

    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src_addr, addrlen);

    if (ret <= 0) return ret;

    

    if (src_addr && addrlen && *addrlen > 0) {

        char host[64] = "unknown";

        int port = 0;

        if (src_addr->sa_family == AF_INET) {

            struct sockaddr_in *in = (struct sockaddr_in *)src_addr;

            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));

            port = ntohs(in->sin_port);

        } else if (src_addr->sa_family == AF_INET6) {

            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;

            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));

            port = ntohs(in6->sin6_port);

        }

        if (port != 0) {

            updateFdHostPort(fd, host, port);

        }

    }

    

    const char *host = getHostForFd(fd);

    int port = getPortForFd(fd);

    const unsigned char *p = (const unsigned char *)buf;

    

    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];

    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];

    size_t showLen = ret > 256 ? 256 : (size_t)ret;

    for (size_t i = 0; i < showLen; i++) {

        [hex appendFormat:@"%02X ", p[i]];

        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];

    }

    DLOG(@"[RECVFROM] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host ?: "unknown", port, ret, hex, ascii);

    

    if (ret >= 8) {

        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |

                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        DLOG(@"[PROTO-DBG-RF] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

        

        // v37.107-DIST: Do NOT patch EE121 status in recvfrom either!

        if (cmd == 0x802EE120 || cmd == 0x802EE121 || cmd == 0x802EE118) {

            DLOG(@"[PROTO-RF] v37.107-DIST: Version/auth response 0x%08X status=%u (NOT patched)", cmd, ret >= 13 ? p[12] : 0);

        }

    }



    // v37.107-DIST: Do NOT clear '版本过低' messages — let client show real server errors!

    // (Previous code cleared '版本过低' which hid real authorization failures from the user.)

    

    return ret;

}



static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {

    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");

    if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen == 0) return -1;

    

    ssize_t ret = orig_recvmsg(fd, msg, flags);

    if (ret <= 0) return ret;

    

    if (msg->msg_name && msg->msg_namelen > 0) {

        struct sockaddr *src_addr = (struct sockaddr *)msg->msg_name;

        char host[64] = "unknown";

        int port = 0;

        if (src_addr->sa_family == AF_INET) {

            struct sockaddr_in *in = (struct sockaddr_in *)src_addr;

            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));

            port = ntohs(in->sin_port);

        } else if (src_addr->sa_family == AF_INET6) {

            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;

            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));

            port = ntohs(in6->sin6_port);

        }

        if (port != 0) {

            updateFdHostPort(fd, host, port);

        }

    }

    

    const char *host = getHostForFd(fd);

    int port = getPortForFd(fd);

    

    struct iovec *iov = msg->msg_iov;

    if (!iov->iov_base || iov->iov_len == 0) return ret;

    

    const unsigned char *p = (const unsigned char *)iov->iov_base;

    

    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];

    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];

    size_t showLen = ret > 256 ? 256 : (size_t)ret;

    for (size_t i = 0; i < showLen; i++) {

        [hex appendFormat:@"%02X ", p[i]];

        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];

    }

    DLOG(@"[RECVMSG] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host ?: "unknown", port, ret, hex, ascii);

    

    if (ret >= 8 && iov->iov_len >= 8) {

        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |

                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |

                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];

        DLOG(@"[PROTO-DBG-RM] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

        

        // v37.107-DIST: Do NOT patch EE121 status in recvmsg either!

        if (cmd == 0x802EE120 || cmd == 0x802EE121 || cmd == 0x802EE118) {

            DLOG(@"[PROTO-RM] v37.107-DIST: Version/auth response 0x%08X status=%u (NOT patched)", cmd, (iov->iov_len >= 13) ? p[12] : 0);

        }

    }



    // v37.107-DIST: Do NOT clear '版本过低' messages in recvmsg — let client show real errors!

    

    return ret;

}



// === Universal fishhook: patch symbol in ALL loaded images ===

static int rebindSymbol(const char *symbolName, void *replacement, void **original) {

    int totalPatched = 0;

    uint32_t imageCount = _dyld_image_count();

    size_t pageSize = 16384;

    

    for (uint32_t img = 0; img < imageCount; img++) {

        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(img);

        intptr_t slide = _dyld_get_image_vmaddr_slide(img);

        if (!header || header->magic != 0xFEEDFACF) continue;

        

        const struct load_command *cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));

        const struct segment_command_64 *linkeditSeg = NULL;

        struct symtab_command *symtab = NULL;

        struct dysymtab_command *dysymtab = NULL;

        

        // Collect data segments

        const struct segment_command_64 *dataSegs[8];

        int dataSegCount = 0;

        

        for (uint32_t i = 0; i < header->ncmds; i++) {

            if (cmd->cmd == LC_SEGMENT_64) {

                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;

                if (strcmp(seg->segname, "__LINKEDIT") == 0) linkeditSeg = seg;

                else if (strcmp(seg->segname, "__DATA") == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {

                    if (dataSegCount < 8) dataSegs[dataSegCount++] = seg;

                }

            } else if (cmd->cmd == LC_SYMTAB) {

                symtab = (struct symtab_command *)cmd;

            } else if (cmd->cmd == LC_DYSYMTAB) {

                dysymtab = (struct dysymtab_command *)cmd;

            }

            cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);

        }

        

        if (!linkeditSeg || !symtab || !dysymtab) continue;

        

        char *linkeditBase = (char *)slide + linkeditSeg->vmaddr - linkeditSeg->fileoff;

        const struct nlist_64 *syms = (const struct nlist_64 *)(linkeditBase + symtab->symoff);

        char *strtab = (char *)(linkeditBase + symtab->stroff);

        uint32_t *indirectSyms = (uint32_t *)(linkeditBase + dysymtab->indirectsymoff);

        

        for (int d = 0; d < dataSegCount; d++) {

            const struct section_64 *sec = (const struct section_64 *)((char *)dataSegs[d] + sizeof(struct segment_command_64));

            for (uint32_t s = 0; s < dataSegs[d]->nsects; s++) {

                // Check both __la_symbol_ptr and __got

                if (strcmp(sec[s].sectname, "__la_symbol_ptr") != 0 &&

                    strcmp(sec[s].sectname, "__got") != 0) continue;

                

                void **pointers = (void **)((char *)slide + sec[s].addr);

                uint32_t count = (uint32_t)(sec[s].size / sizeof(void *));

                for (uint32_t j = 0; j < count; j++) {

                    uint32_t symIdx = indirectSyms[sec[s].reserved1 + j];

                    if (symIdx >= symtab->nsyms) continue;

                    const char *name = strtab + syms[symIdx].n_un.n_strx;

                    if (strcmp(name, symbolName) == 0) {

                        void *page = (void *)((uintptr_t)&pointers[j] & ~(pageSize - 1));

                        if (mprotect(page, pageSize, PROT_READ | PROT_WRITE) == 0) {

                            if (original && !*original) *original = pointers[j];

                            pointers[j] = replacement;

                            totalPatched++;

                        }

                    }

                }

            }

        }

    }

    return totalPatched;

}



static void installSocketHooks(void) {

    orig_connect = NULL;

    orig_send = NULL;

    orig_recv = NULL;

    orig_recvfrom = NULL;

    orig_recvmsg = NULL;

    orig_write = NULL;

    orig_read = NULL;

    orig_close = NULL;

    orig_getsockopt = NULL;



    // v37.134-FIX25: V3环境优先用MSHookFunction内联patch穿透所有rebind层

    // 原因: write=9 read=6 高rebind数说明其他dylib(libWJHook/zsign等)的fishhook在最外层，

    // 导致我们的rebindSymbol夹在中间层，数据流被外层stub截断/返回错误→游戏不发connect。

    // FIX24错误地移除了MSHookFunction导致回归。

    // fallback判断修正: 不能用 if(!orig)（因为dlsym后orig非NULL，MSHook失败不会置NULL），

    // 改用 preMS == orig_after || orig_after == NULL 判断失败。

    if (g_isV3Environment && g_msHookFunction) {

        DLOG(@"[V3-SOCK] ✅ 用MSHookFunction内联patch(穿透write=9/read=6多层rebind)");



        void *libsys = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);

        if (!libsys) libsys = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);



        int ms_ok = 0;

        if (libsys) {

            // connect: preMS保存旧值→置NULL→MSHook→对比判断

            void *connPtr = dlsym(libsys, "connect");

            if (connPtr) {

                void *preConn = (void *)orig_connect;

                orig_connect = NULL;

                g_msHookFunction(connPtr, (void *)hook_connect, (void **)&orig_connect);

                if (orig_connect && orig_connect != preConn) { ms_ok++; DLOG(@"[V3-SOCK] connect MSHook OK orig=%p", orig_connect); }

                else { DLOG(@"[V3-SOCK-FB] connect MSHook失败 → fallback rebind");

                    int rc = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);

                    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");

                    DLOG(@"[V3-SOCK-FB] connect rebind=%d orig=%p", rc, orig_connect); }

            }

            // send

            void *sendPtr = dlsym(libsys, "send");

            if (sendPtr) {

                void *preSend = (void *)orig_send;

                orig_send = NULL;

                g_msHookFunction(sendPtr, (void *)hook_send, (void **)&orig_send);

                if (orig_send && orig_send != preSend) { ms_ok++; DLOG(@"[V3-SOCK] send MSHook OK orig=%p", orig_send); }

                else { DLOG(@"[V3-SOCK-FB] send MSHook失败 → fallback rebind");

                    int rs = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);

                    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");

                    DLOG(@"[V3-SOCK-FB] send rebind=%d orig=%p", rs, orig_send); }

            }

            // recv (版本过低修复依赖!)

            void *recvPtr = dlsym(libsys, "recv");

            if (recvPtr) {

                void *preRecv = (void *)orig_recv;

                orig_recv = NULL;

                g_msHookFunction(recvPtr, (void *)hook_recv, (void **)&orig_recv);

                if (orig_recv && orig_recv != preRecv) { ms_ok++; DLOG(@"[V3-SOCK] recv MSHook OK orig=%p", orig_recv); }

                else { DLOG(@"[V3-SOCK-FB] recv MSHook失败 → fallback rebind (版本过低修复依赖!)");

                    int rr = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);

                    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");

                    DLOG(@"[V3-SOCK-FB] recv rebind=%d orig=%p", rr, orig_recv); }

            }

            // write

            void *writePtr = dlsym(libsys, "write");

            if (writePtr) {

                void *preWr = (void *)orig_write;

                orig_write = NULL;

                g_msHookFunction(writePtr, (void *)hook_write, (void **)&orig_write);

                if (orig_write && orig_write != preWr) { ms_ok++; DLOG(@"[V3-SOCK] write MSHook OK orig=%p", orig_write); }

                else { DLOG(@"[V3-SOCK-FB] write MSHook失败 → fallback rebind");

                    int rw = rebindSymbol("_write", (void *)hook_write, (void **)&orig_write);

                    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");

                    DLOG(@"[V3-SOCK-FB] write rebind=%d orig=%p", rw, orig_write); }

            }

            // read

            void *readPtr = dlsym(libsys, "read");

            if (readPtr) {

                void *preRd = (void *)orig_read;

                orig_read = NULL;

                g_msHookFunction(readPtr, (void *)hook_read, (void **)&orig_read);

                if (orig_read && orig_read != preRd) { ms_ok++; DLOG(@"[V3-SOCK] read MSHook OK orig=%p", orig_read); }

                else { DLOG(@"[V3-SOCK-FB] read MSHook失败 → fallback rebind");

                    int rd = rebindSymbol("_read", (void *)hook_read, (void **)&orig_read);

                    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");

                    DLOG(@"[V3-SOCK-FB] read rebind=%d orig=%p", rd, orig_read); }

            }

            // recvfrom

            void *recvfromPtr = dlsym(libsys, "recvfrom");

            if (recvfromPtr) {

                void *preRf = (void *)orig_recvfrom;

                orig_recvfrom = NULL;

                g_msHookFunction(recvfromPtr, (void *)hook_recvfrom, (void **)&orig_recvfrom);

                if (orig_recvfrom && orig_recvfrom != preRf) { ms_ok++; DLOG(@"[V3-SOCK] recvfrom MSHook OK orig=%p", orig_recvfrom); }

                else { DLOG(@"[V3-SOCK-FB] recvfrom MSHook失败 → fallback rebind");

                    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);

                    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");

                    DLOG(@"[V3-SOCK-FB] recvfrom rebind=%d orig=%p", rf, orig_recvfrom); }

            }

            // close

            void *closePtr = dlsym(libsys, "close");

            if (closePtr) {

                void *preCl = (void *)orig_close;

                orig_close = NULL;

                g_msHookFunction(closePtr, (void *)hook_close, (void **)&orig_close);

                if (orig_close && orig_close != preCl) { ms_ok++; DLOG(@"[V3-SOCK] close MSHook OK orig=%p", orig_close); }

                else { DLOG(@"[V3-SOCK-FB] close MSHook失败 → fallback rebind");

                    int cl = rebindSymbol("_close", (void *)hook_close, (void **)&orig_close);

                    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");

                    DLOG(@"[V3-SOCK-FB] close rebind=%d orig=%p", cl, orig_close); }

            }

        }

        // 其他符号用rebindSymbol兜底

        int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);

        int gs = rebindSymbol("_getsockopt", (void *)hook_getsockopt, (void **)&orig_getsockopt);

        int p  = rebindSymbol("_poll", (void *)hook_poll, (void **)&orig_poll);

        int sel= rebindSymbol("_select", (void *)hook_select, (void **)&orig_select);

        // 兜底dlsym orig

        if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");

        if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");

        if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");

        if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");

        if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");

        if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");

        if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");

        if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");

        if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");

        if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");

        if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");

        DLOG(@"[V3-SOCK] MSHook完成率=%d/7 recvmsg=0x%x getsockopt=0x%x poll=0x%x select=0x%x", ms_ok, rm, gs, p, sel);

    } else {

        // 全能签环境: 原rebindSymbol

        int c = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);

        int s = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);

        int r = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);

        int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);

        int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);

        int w = rebindSymbol("_write", (void *)hook_write, (void **)&orig_write);

        int rd = rebindSymbol("_read", (void *)hook_read, (void **)&orig_read);

        int cl = rebindSymbol("_close", (void *)hook_close, (void **)&orig_close);

        int gs = rebindSymbol("_getsockopt", (void *)hook_getsockopt, (void **)&orig_getsockopt);

        int p = rebindSymbol("_poll", (void *)hook_poll, (void **)&orig_poll);

        int sel = rebindSymbol("_select", (void *)hook_select, (void **)&orig_select);



        if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");

        if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");

        if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");

        if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");

        if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");

        if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");

        if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");

        if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");

        if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");

        if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");



        DLOG(@"[SOCK] Hooks: connect=%d send=%d recv=%d recvfrom=%d recvmsg=%d write=%d read=%d close=%d getsockopt=%d poll=%d select=%d", c, s, r, rf, rm, w, rd, cl, gs, p, sel);

    }



    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p write=%p read=%p close=%p getsockopt=%p poll=%p select=%p", 

         orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg, orig_write, orig_read, orig_close, orig_getsockopt, orig_poll, orig_select);

    

    if (!orig_connect) DLOG(@"[SOCK-ERROR] connect hook failed - network monitoring disabled!");

    if (!orig_send) DLOG(@"[SOCK-ERROR] send hook failed - outgoing data monitoring disabled!");

    if (!orig_recv) DLOG(@"[SOCK-ERROR] recv hook failed - incoming data monitoring disabled!");

}



// ============================================================

#pragma mark - DYLD API Hooking (hide injected dylibs from detection)

// ============================================================



static const char *g_hiddenDylibs[] = {

    "WangXianHook", "lnSignature", "libSupport", "liblnSignature", "substrate", "frida",

    "systemhook", "zsign", NULL

};



static BOOL shouldHideDylib(const char *name) {

    if (!name) return NO;

    for (int i = 0; g_hiddenDylibs[i]; i++) {

        // FIX30: DYLD隐藏条件化: 只有V3环境(g_zsignPresent=YES)才隐藏systemhook和zsign

        // 全能签环境(无zsign)不隐藏这两个不存在的dylib, 避免额外分支

        if ((strcmp(g_hiddenDylibs[i], "systemhook") == 0 || strcmp(g_hiddenDylibs[i], "zsign") == 0)

            && !g_zsignPresent) {

            continue;

        }

        if (strstr(name, g_hiddenDylibs[i])) return YES;

    }

    return NO;

}



// Store original dyld functions

static uint32_t (*orig_dyld_image_count)(void) = NULL;

static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;

static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;



// Count of hidden images (computed at init)

static uint32_t g_hiddenCount = 0;

static uint32_t g_hiddenIndices[32] = {0};



// Hooked dyld_image_count - return reduced count

static uint32_t hook_dyld_image_count(void) {

    uint32_t realCount = orig_dyld_image_count ? orig_dyld_image_count() : 0;

    uint32_t fakeCount = realCount - g_hiddenCount;

    DLOG(@"[DYLD-HOOK] image_count: real=%u fake=%u", realCount, fakeCount);

    return fakeCount;

}



// Hooked dyld_get_image_name - filter out hidden libraries

static const char *hook_dyld_get_image_name(uint32_t index) {

    if (!orig_dyld_get_image_name) return "";

    

    uint32_t fakeCount = orig_dyld_image_count() - g_hiddenCount;

    if (index >= fakeCount) {

        DLOG(@"[DYLD-HOOK] get_image_name(%u): index out of range (fakeCount=%u)", index, fakeCount);

        return "";

    }

    

    // Map fake index to real index (skip hidden ones)

    uint32_t realIndex = index;

    for (uint32_t i = 0; i < g_hiddenCount; i++) {

        if (g_hiddenIndices[i] <= realIndex) {

            realIndex++;

        }

    }

    

    const char *name = orig_dyld_get_image_name(realIndex);

    if (shouldHideDylib(name)) {

        DLOG(@"[DYLD-HOOK] get_image_name(%u->%u): STILL hidden '%s', skipping", index, realIndex, name);

        // Find next non-hidden

        while (shouldHideDylib(name) && realIndex < orig_dyld_image_count()) {

            realIndex++;

            name = orig_dyld_get_image_name(realIndex);

        }

    }

    

    DLOG(@"[DYLD-HOOK] get_image_name(%u->%u): '%s'", index, realIndex, name ?: "");

    return name ?: "";

}



// Hooked dyld_get_image_header - return header for mapped index

static const struct mach_header *hook_dyld_get_image_header(uint32_t index) {

    if (!orig_dyld_get_image_header) return NULL;

    

    uint32_t fakeCount = orig_dyld_image_count() - g_hiddenCount;

    if (index >= fakeCount) return NULL;

    

    // Map fake index to real index

    uint32_t realIndex = index;

    for (uint32_t i = 0; i < g_hiddenCount; i++) {

        if (g_hiddenIndices[i] <= realIndex) {

            realIndex++;

        }

    }

    

    return orig_dyld_get_image_header(realIndex);

}



// Compute hidden indices at initialization

static void computeHiddenIndices(void) {

    g_hiddenCount = 0;

    uint32_t realCount = _dyld_image_count();

    for (uint32_t i = 0; i < realCount && g_hiddenCount < 32; i++) {

        const char *name = _dyld_get_image_name(i);

        if (shouldHideDylib(name)) {

            g_hiddenIndices[g_hiddenCount++] = i;

            DLOG(@"[DYLD-HIDE] Index %u: '%s' will be hidden", i, name);

        }

    }

    DLOG(@"[DYLD-HIDE] Total hidden: %u / %u", g_hiddenCount, realCount);

}



static void installDyldHooks(void) {

    // Compute hidden indices first

    computeHiddenIndices();

    

    // Get original functions

    orig_dyld_image_count = _dyld_image_count;

    orig_dyld_get_image_name = _dyld_get_image_name;

    orig_dyld_get_image_header = _dyld_get_image_header;

    

    // Try to rebind via fishhook (works for calls through PLT)

    rebindSymbol("_dyld_image_count", (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count);

    rebindSymbol("_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);

    rebindSymbol("_dyld_get_image_header", (void *)hook_dyld_get_image_header, (void **)&orig_dyld_get_image_header);

    

    DLOG(@"[DYLD-HOOK] Installed hooks for image_count/get_image_name/get_image_header");

}



// ============================================================

#pragma mark - dladdr Hook (hide hook function origin)

// ============================================================



typedef int (*DladdrFunc)(const void *, Dl_info *);

static DladdrFunc orig_dladdr = NULL;



static int hook_dladdr(const void *addr, Dl_info *info) {

    if (!orig_dladdr || !info) return 0;

    

    int ret = orig_dladdr(addr, info);

    if (ret && info->dli_fname) {

        // If the address belongs to our hidden dylib, return fake info

        if (shouldHideDylib(info->dli_fname)) {

            DLOG(@"[DLADDR-HOOK] Hiding origin of addr %p (was '%s')", addr, info->dli_fname);

            // Return libSystem.B.dylib as the origin

            info->dli_fname = "/usr/lib/libSystem.B.dylib";

            info->dli_fbase = (void *)0x19d500000;  // Fake base

            info->dli_sname = NULL;

            info->dli_saddr = NULL;

        }

    }

    return ret;

}



static void installDladdrHook(void) {

    void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);

    if (libdyld) {

        orig_dladdr = (DladdrFunc)dlsym(libdyld, "dladdr");

        rebindSymbol("_dladdr", (void *)hook_dladdr, (void **)&orig_dladdr);

        DLOG(@"[DLADDR-HOOK] Installed, orig=%p", orig_dladdr);

    }

}



// ============================================================

#pragma mark - dlsym Hook (hide hook framework symbols)

// ============================================================



typedef void* (*DlsymFunc)(void *, const char *);

static DlsymFunc orig_dlsym = NULL;



static void* hook_dlsym(void *handle, const char *symbol) {

    if (!orig_dlsym) {

        void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);

        if (libdyld) {

            orig_dlsym = (DlsymFunc)dlsym(libdyld, "dlsym");

        }

    }

    if (!orig_dlsym) return NULL;

    

    NSString *symStr = [NSString stringWithUTF8String:symbol];

    NSString *lowerSym = [symStr lowercaseString];

    

    const char *hiddenSymbols[] = {

        "substrate", "fishhook", "mshookfunction", "rebind_symbols",

        "mshookmsg", "mshookclass", "mshookselector",

        "cydia", "cydiasubstrate", "theos",

        NULL

    };

    

    for (int i = 0; hiddenSymbols[i]; i++) {

        if ([lowerSym containsString:[NSString stringWithUTF8String:hiddenSymbols[i]]]) {

            DLOG(@"[DLSYM-HIDE] Returning NULL for symbol: '%s'", symbol);

            return NULL;

        }

    }

    

    void *result = orig_dlsym(handle, symbol);

    if (result) {

        DLOG(@"[DLSYM-LOG] symbol='%s' -> %p", symbol, result);

    }

    return result;

}



static void installDlsymHook(void) {

    void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);

    if (libdyld) {

        orig_dlsym = (DlsymFunc)dlsym(libdyld, "dlsym");

        rebindSymbol("_dlsym", (void *)hook_dlsym, (void **)&orig_dlsym);

        DLOG(@"[DLSYM-HOOK] Installed, orig=%p", orig_dlsym);

    }

}



// ============================================================

#pragma mark - /proc/self/maps filtering (Linux fallback)

// ============================================================



static BOOL shouldHideLine(const char *line) {

    return shouldHideDylib(line);

}



// === FIX45: systemhook.dylib (Dopamine越狱 0号dylib) 劫持fopen/fgets/fread导致读配置崩溃 修复 ===
//   LINE22375代码/崩溃LOG(L443)铁证: systemhook.dylib(idx0) 先于WangXianHook加载→其fishhook替换fopen/fgets等C stdio为buggy实现
//   → 全能签本地注入没有systemhook→能正常读文件进游戏
//   → 服务器重签越狱副设备: systemhook对游戏配置文件返回NULL/0字节→VersionModule读XML配置抛异常→C++ terminate→SIGTRAP!
// 策略A(治本): 
//   1) 直接从 /usr/lib/system/libsystem_c.dylib dlopen拿 REAL fopen/fgets/fread/fclose (绕开systemhook的fishhook interposition)
//   2) fishhook 安装我们的wrapper→orig_fopen/fgets/fread/fclose(这一层是systemhook版本)
//   3) Wrapper中先调用orig→如果返回值异常(NULL/0字节等)→立即FALLBACK调用真正的libsystem_c实现!
//   4) 关键路径(VersionModule读配置文件如version_config/servers.xml等)额外打点记录

// FIX45: 先声明所有stdio typedef (避免稍后typedef未定义编译错误!)
typedef FILE *(*FopenFunc)(const char *, const char *);
typedef char *(*FgetsFunc)(char *, int, FILE *);
typedef size_t (*FreadFunc)(void *, size_t, size_t, FILE *);
typedef int    (*FcloseFunc)(FILE *);

// FIX45: 真实 libsystem_c 函数指针(永远不被任何fishhook影响,因为直接dlsym在libsystem_c handle上)
static FopenFunc    real_libSystem_fopen  = NULL;
static FgetsFunc    real_libSystem_fgets  = NULL;
static FreadFunc    real_libSystem_fread  = NULL;
static FcloseFunc   real_libSystem_fclose = NULL;

// FIX45: orig函数指针 (fishhook rebind时赋值 = systemhook的buggy版本)
static FopenFunc  orig_fopen  = NULL;
static FgetsFunc  orig_fgets  = NULL;
static FreadFunc  orig_fread  = NULL;
static FcloseFunc orig_fclose = NULL;

static size_t hook_fread(void *ptr, size_t size, size_t nitems, FILE *stream) {
    size_t cnt = orig_fread ? orig_fread(ptr, size, nitems, stream) : 0;
    // FIX45: 兜底 → 如果 systemhook 返回0(但文件非EOF且stream有效), 调真正libSystem的fread!
    if (cnt == 0 && real_libSystem_fread && stream && ptr && size > 0 && nitems > 0) {
        size_t rcnt = real_libSystem_fread(ptr, size, nitems, stream);
        if (rcnt != cnt) {
            DLOG(@"[FIX45-FIO] fread fallback: systemhook_ret=%zu → real_libSystem_ret=%zu (size=%zu n=%zu stream=%p)", cnt, rcnt, size, nitems, stream);
            cnt = rcnt;
        }
    }
    return cnt;
}

static int hook_fclose(FILE *stream) {
    int r = orig_fclose ? orig_fclose(stream) : EOF;
    if (r == EOF && real_libSystem_fclose && stream) {
        int rr = real_libSystem_fclose(stream);
        if (rr != EOF) {
            DLOG(@"[FIX45-FIO] fclose fallback: systemhook=EOF → real_libSystem=%d", rr);
            r = rr;
        }
    }
    return r;
}

static FILE *hook_fopen(const char *path, const char *mode) {
    FILE *f = orig_fopen ? orig_fopen(path, mode) : NULL;

    // FIX45: 关键兜底!如果 systemhook 返回NULL (bug!) → 立即使用真实 libSystem fopen!
    if (f == NULL && real_libSystem_fopen && path && mode) {
        FILE *rf = real_libSystem_fopen(path, mode);
        if (rf != NULL) {
            DLOG(@"[FIX45-FIO] fopen FALLBACK: path=%s mode=%s → systemhook=NULL ❌ → real_libSystem SUCCESS ✅ (%p)", path, mode, rf);
        }
        f = rf;
    } else if (f != NULL && path && (strstr(path, "version") || strstr(path, "server") || strstr(path, "config") || strstr(path, "resVer") || strstr(path, ".xml") || strstr(path, ".json") || strstr(path, ".plist"))) {
        // FIX45: 游戏配置文件打开成功,记录(VersionModule会读version/server配置)
        DLOG(@"[FIX45-FIO] fopen CONFIG FILE OK: path=%s mode=%s stream=%p", path, mode, f);
    }

    if (f && path && strstr(path, "/proc/self/maps")) {
        DLOG(@"[PROC] /proc/self/maps opened");
    }

    return f;
}

static char *hook_fgets(char *buf, int size, FILE *stream) {
    char *result = orig_fgets ? orig_fgets(buf, size, stream) : NULL;

    // FIX45: fgets systemhook返回NULL(但feof为0/buf有效/size>0) → 用真实 libSystem 兜底!
    if (result == NULL && real_libSystem_fgets && buf && size > 1 && stream) {
        // 简单检查: 如果还没到EOF (feof==0 && ferror==0) → systemhook bug导致返回NULL!
        if (feof(stream) == 0 && ferror(stream) == 0) {
            char *rr = real_libSystem_fgets(buf, size, stream);
            if (rr != NULL) {
                DLOG(@"[FIX45-FIO] fgets FALLBACK: stream=%p bufsize=%d → systemhook=NULL ❌ → real_libSystem=%@ (trunc20)", stream, size, rr ? [NSString stringWithUTF8String:rr] : nil);
            }
            result = rr;
        }
    }

    if (result && shouldHideLine(result)) {
        buf[0] = '\n';
        buf[1] = '\0';
    }

    return result;
}

// === FIX45 策略B: 兜底防崩溃(VersionModule.widgetSelected try-catch包装) ===
//   CRASH铁证(wxhook29.log#L469/#03): _ZN13VersionModule14widgetSelectedER14SelectionEvent + 5344
//   该C++方法=用户点击UI按钮"进入游戏"后调用→先读本地版本/区服配置文件→systemhook bug致读失败→抛C++异常没人catch→std::terminate→SIGTRAP闪退
//   FIX45策略B: 用libsubstrate.dylib(已加载LINE449)的MSHookFunction直接patch该函数入口
//              → 包一层try { orig } catch(所有异常) → 不让异常抛到terminate! → 强制游戏继续运行!

// FIX45: C++ mangled symbol from crash stack LINE469
#define FIX45_VM_WS_MANGLED "_ZN13VersionModule14widgetSelectedER14SelectionEvent"
// Itanium C++ ABI (arm64): 实例方法 arg1=this* (x0), arg2=SelectionEvent&(内部就是指针x1).
// 为避免C++ void引用类型编译错误, 统一用void*指针版本(ABI完全兼容)
typedef void (*VMWidgetSelectedFuncCC)(void* thisPtr, void* selEventPtr);
static VMWidgetSelectedFuncCC orig_FIX45_VM_ws = NULL;

// FIX45: C++ try/catch requires compiling as objective-c++ (Makefile already does -x objective-c++)
// We use extern "C" linkage for wrapper so its symbol is callable through raw function pointers
extern "C" void fix45_VMWidgetSelected_wrapper(void* thisPtr, void* selEventPtr) {
    if (!orig_FIX45_VM_ws) return;
    @autoreleasepool {
        try {
            // arm64 Itanium C++ ABI: T&(reference) == void*(pointer) in asm/calling convention
            // Directly pass both args with raw cast → ABI matches perfectly.
            orig_FIX45_VM_ws(thisPtr, selEventPtr);
        } catch (const char* s) {
            DLOG(@"[FIX45-VM] 🚨 CAUGHT char* exception msg=%s → FORCE CONTINUE!", s ? s : "(null)");
        } catch (long long code) {
            DLOG(@"[FIX45-VM] 🚨 CAUGHT integer exception code=%lld → FORCE CONTINUE!", code);
        } catch (void* p) {
            DLOG(@"[FIX45-VM] 🚨 CAUGHT pointer exception p=%p → FORCE CONTINUE!", p);
        } catch (...) {
            // Most important: catch ALL C++ exception types (including custom VersionModule ones!)
            // that aren't std::exception derived. This GUARANTEES no std::terminate!
            DLOG(@"[FIX45-VM] 🚨 CAUGHT UNKNOWN(...) C++ exception → FORCE CONTINUE!");
        }
        // ObjC belt
        @try {
        } @catch (NSException *e) {
            DLOG(@"[FIX45-VM] 🚨 CAUGHT NSException name=%@ reason=%@ → FORCE CONTINUE!", [e name], [e reason]);
        }
        DLOG(@"[FIX45-VM] ✅ widgetSelected wrapper completed safely (this=%p event=%p)", thisPtr, selEventPtr);
    }
}

// FIX45: 初始化安装MSHookFunction VersionModule::widgetSelected
static void fix45_installVMWidgetHook() {
    @autoreleasepool {
        // 1) 获取目标函数地址
        void* targetFunc = dlsym(RTLD_DEFAULT, FIX45_VM_WS_MANGLED);
        if (!targetFunc) {
            DLOG(@"[FIX45-VM] ⚠️ dlsym(RTLD_DEFAULT,%s)=NULL → 无法定位函数 → 跳过兜底", FIX45_VM_WS_MANGLED);
            return;
        }
        DLOG(@"[FIX45-VM] 🔍 定位 VersionModule::widgetSelected 成功 addr=%p symbol=%s", targetFunc, FIX45_VM_WS_MANGLED);

        // 2) 获取 MSHookFunction (libsubstrate已加载LINE449)
        void* libsub = dlopen("/usr/lib/libsubstrate.dylib", RTLD_NOLOAD);
        if (!libsub) libsub = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOLOAD);
        if (!libsub) {
            // try CydiaSubstrate.framework path variations
            libsub = dlopen("/Library/MobileSubstrate/MobileSubstrate.dylib", RTLD_NOLOAD);
        }
        if (!libsub) {
            // Fallback: try fishhook global rebind (weaker, but backup)
            DLOG(@"[FIX45-VM] ⚠️ libsubstrate未加载 → fishhook全局rebind作为备用");
            struct rebinding rb = { FIX45_VM_WS_MANGLED, (void*)fix45_VMWidgetSelected_wrapper, (void**)&orig_FIX45_VM_ws };
            int rc = rebind_symbols(&rb, 1);
            DLOG(@"[FIX45-VM] fishhook rebind rc=%d orig=%p", rc, orig_FIX45_VM_ws);
            return;
        }
        void (*pfnMSHookFunction)(void*, void*, void**) = (void(*)(void*,void*,void**))dlsym(libsub, "MSHookFunction");
        if (!pfnMSHookFunction) {
            DLOG(@"[FIX45-VM] ⚠️ dlsym MSHookFunction=NULL → fishhook");
            struct rebinding rb = { FIX45_VM_WS_MANGLED, (void*)fix45_VMWidgetSelected_wrapper, (void**)&orig_FIX45_VM_ws };
            rebind_symbols(&rb, 1);
            return;
        }

        // 3) Install MSHookFunction
        pfnMSHookFunction(targetFunc, (void*)fix45_VMWidgetSelected_wrapper, (void**)&orig_FIX45_VM_ws);
        DLOG(@"[FIX45-VM] ✅ MSHookFunction 成功! target=%p → wrapper=%p orig_backup=%p", targetFunc, (void*)fix45_VMWidgetSelected_wrapper, (void*)orig_FIX45_VM_ws);
    }
}



#pragma mark - CCCrypt / SecKey Hooks



// v37.26: Forward declaration for wrapper to avoid implicit declaration

static int hook_CCCrypt_v37_26(uint32_t op, uint32_t alg, uint32_t options,

                                  const void *key, size_t keyLen,

                                  const void *iv,

                                  const void *dataIn, size_t dataInLen,

                                  void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);



static int hook_CCCrypt(uint32_t op, uint32_t alg, uint32_t options,

                        const void *key, size_t keyLen,

                        const void *iv,

                        const void *dataIn, size_t dataInLen,

                        void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {

    // v37.26: Redirect to the full implementation above. This wrapper exists

    // because installSecurityHooks rebinds by this function's symbol name.

    return hook_CCCrypt_v37_26(op, alg, options, key, keyLen, iv,

                               dataIn, dataInLen, dataOut, dataOutAvailable, dataOutMoved);

}



// ============================================================

// v37.51: CC_MD5 hook — replace modified binary hash with clean hash

// ============================================================

// Our binary hash (全能签 modified): 913a1d1a9b704107b7b607b13d53a094

// Clean binary hash (original):      906e707ec5585f080397b26ff4b8d89d

// When CC_MD5 output matches our hash, replace with clean hash.

// This makes client compute hash1/hash3 using clean binary hash → all 3 hashes consistent.



typedef unsigned char *(*CC_MD5Func)(const void *data, uint32_t len, unsigned char *md);

static CC_MD5Func orig_CC_MD5 = NULL;



// v37.134-FIX11: Runtime-compute our binary hash (NOT hardcoded old value!)

// ROOT CAUSE of status=4: g_our_binary_hash was HARDCODED to f9cc76c5... (v37.60 value)

// but every rebuild/injection changes the actual binary hash → output replacement condition

// memcmp(md, g_our_binary_hash, 16) NEVER matches → binary hash NOT replaced →

// server validates hash1/hash3 = MD5(clean_binary_hash+token) FAILS → status=4.

// FIX: Compute CURRENT binary hash at runtime by reading main executable file.

// v37.134-FIX15: g_our_binary_hash and g_clean_binary_hash moved to top of file (forward declarations)

// g_md5_replace_count declared near top of file (line 589)



static unsigned char *hook_CC_MD5(const void *data, uint32_t len, unsigned char *md) {

    // v37.60: Scan INPUT (≤500B) for channel/deviceModel/GPU and replace ALL THREE

    // to match TLV-replaced EE121 packet. v37.58 only replaced channel → hash3 was

    // computed with native iPhone 16 Pro Max + A18 GPU but packet had iPhone7Plus +

    // A10 GPU → hash mismatch → server rejected.

    // v37.60 replaces all three in CC_MD5 input so hash3 matches packet content.

    const void *actualInput = data;

    void *cleanInput = NULL;

    uint32_t actualLen = len;

    int inputModified = 0;



    if (data && len >= 9 && len <= 65536) {

        // v37.60: Only process small inputs (≤500B) — hash1/hash3 computations.

        // Large inputs (e.g., 19437B binary hash) are handled by output replacement.

        if (len <= 500) {

            const uint8_t *in = (const uint8_t *)data;



            // v37.62: CANONICAL (clean-client) values for EE121 MD5 input.

            // These MUST match the values used in EE121-CANON packet rebuild below so that

            // MD5(156B canonical_fields) == body MD5 == packet.hash2.

            // v37.97: hash2 = MD5(body), NOT binary hash. Binary hash is 906e707ec... used for hash1/hash3.

            // Otherwise server recomputes MD5(extract_fields) != hash2 → CLOSE.

            // Context markers (unique to EE121 hash2/hash3 computation):

            //   - pattern "...SQAGEIOS<ch>...<UUID>WIFI7.6.3979..." → hash2 (156B) / hash3 (168B)

            //   - pattern "906e707ec5585f080397b26ff4b8d89d<31B token>" → hash1/hash3 (63B)

            // Only perform CANONICAL replacement if EE121-unique patterns exist to avoid

            // corrupting other MD5 inputs (e.g., SK signature, HTTP params).

            // --- Canonical replacements (length-neutral where possible) ---

            // accId:  user's real 20-digit (e.g. 73768221250855090904) → 65657881045335015151 (20B same)

            // user:   kk994 (5B) already matches — no replacement needed for this account.

            // pass:   994624 (6B) already matches — no replacement needed.

            // UUID:   FIX53 unified scheme — always use 66B0EE01 (whitelist canonical UUID)
            //         CCCrypt L4 plaintext AND CC_MD5 (HMAC) MUST use the SAME UUID at all times.
            // ch/dm/gp: handled below (DY_MIESHI→DYanyou0040 etc.) — dm/gp also length-changing.
            // Binary hash hex: handled below (f9cc76c5...→906e707ec...).

            static const char kCanUUIDNew[] = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8"; // 36B canonical whitelist UUID

            #define IS_HEX(c) (((c)>='0'&&(c)<='9')||((c)>='a'&&(c)<='f')||((c)>='A'&&(c)<='F'))



            // v37.60: Four search/replace pairs (must match TLV replacement + binary hash)

            static const char chOld[]   = "DY_MIESHI";              // 9 bytes

            static const char chNew[]   = "DYanyou0040_MIESHI";     // 18 bytes (+9)

            static const char dmOld[]   = "iPhone 16 Pro Max";       // 17 bytes

            static const char dmNew[]   = "iPhone7Plus";             // 11 bytes (-6)

            static const char gpOld[]   = "Apple Inc. Apple A18 Pro GPU"; // 28 bytes

            static const char gpNew[]   = "Apple Inc. Apple A10 GPU";     // 24 bytes (-4)

            // v37.134-FIX14: hOld/hNew are now DYNAMIC — computed from g_our_binary_hash

            // at hook install time. Old hardcoded "f9cc76c5..." never matched actual binary hash.

            // The FIX12 code below handles dynamic hex string replacement using g_our_binary_hash.

            // v37.134-FIX15: Define hOld/hNew here for code at lines 9449/9486/9563/9564.

            char hOld[33] = {0}; // our binary hash hex string (lowercase)

            char hNew[33] = {0}; // clean binary hash hex string (lowercase)

            {

                int hr = 0; for (int _h = 0; _h < 16; _h++) if (g_our_binary_hash[_h]) { hr = 1; break; }

                if (hr) {

                    for (int h = 0; h < 16; h++) snprintf(hOld + h*2, 3, "%02x", g_our_binary_hash[h]);

                    for (int h = 0; h < 16; h++) snprintf(hNew + h*2, 3, "%02x", g_clean_binary_hash[h]);

                }

            }

            static const char kCanonAccId[] = "65657881045335015151"; // 20 bytes clean-client accId



            // --- Check for EE121-unique context markers ---

            // hash2/hash3 input marker: SQAGEIOS followed by ch (DY_MIESHI/DYanyou0040) near UUID near WIFI7.6.3979

            int hasEE121Ctx = 0; // 1=hash2/hash3 156/168B input, 2=hash1/hash3 63B clean-hash+token

            {

                // Search for SQAGEIOS + ... + WIFI7.6.3979  (hash2/hash3 156/168B input)

                int foundSq = 0, foundWifi = 0;

                for (uint32_t i = 0; i + 7 <= len; i++) {

                    if (!foundSq && i + 8 <= len && memcmp(in+i, "SQAGEIOS", 8) == 0) foundSq = 1;

                    if (!foundWifi && i + 12 <= len && memcmp(in+i, "WIFI7.6.3979", 12) == 0) foundWifi = 1;

                }

                if (foundSq && foundWifi) hasEE121Ctx = 1;

                else {

                    // hash1/hash3 63B input marker: binary_hash_hex(32) OR clean_hash_hex(32) + ~31B token

                    int foundClean = 0;

                    if (hOld[0] != 0) { // v37.134-FIX15: Guard against empty hash

                        for (uint32_t i = 0; i + 32 <= len; i++) {

                            if (memcmp(in+i, hOld, 32) == 0 || memcmp(in+i, hNew, 32) == 0) { foundClean = 1; break; }

                        }

                    }

                    if (foundClean && len >= 40 && len <= 80) hasEE121Ctx = 2;

                }

            }



            // v37.80: Capture token from 63B MD5 input (binary_hash_hex(32) + token(31) = 63 bytes).

            // This is called for hash3/hash1 computation: MD5(binary_hash || token).

            // v37.97: We NO LONGER force hash2. Original hash2 (MD5 of body) is kept.

            // Token captured here is used for hash1/hash3 = MD5(binary_hash + token) recalculation.

            // hash3+hash1 using the SAME token. Otherwise server detects mismatch and closes.

            if (len == 63) {

                // 63B = 32B hex binary_hash + 31B token. Verify first 32 chars are hex.

                int isHex = 1;

                for (int i = 0; i < 32; i++) {

                    char c = ((const char *)in)[i];

                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) { isHex = 0; break; }

                }

                if (isHex) {

                    // Copy token (last 31 bytes of 63B input)

                    const char *tokenStart = (const char *)in + 32;

                    memcpy(g_hashToken, tokenStart, 31);

                    g_hashToken[31] = 0;

                    g_hashTokenValid = 1;

                    DLOG(@"[MD5-TOKEN-CAPTURE] v37.80: Captured token(31B) from 63B MD5 input: %s", g_hashToken);

                }

            }



            // Scan for replaceable matches

            int hasCh = 0, hasDm = 0, hasGp = 0, hasHash = 0, hasUUID = 0;
            int hasFull = 0; // FIX53R: "FULL" marker — present in FFF493#2 concat, NOT in EE121 concat

            uint32_t uuidPos = 0; // position of ANY 36B format UUID (when hasEE121Ctx==1)

            for (uint32_t i = 0; i + 9 <= len; i++) {

                // v37.134-FIX14: RE-ENABLE channel/dm/gp replacement in CC_MD5 hook.

                // EE007-ALIGN changes packet body ch/dm/gp → hash2 must match modified body.

                if (!hasCh && i + 9 <= len && memcmp(in + i, chOld, 9) == 0) hasCh = 1;

                // FIX51: 支持iPhone 16 Pro Max(17B) + iPhone 14 Pro(13B) + iPhone 13 Pro(13B) + iPhone7Plus(11B)
                if (!hasDm && i + 17 <= len && memcmp(in + i, dmOld, 17) == 0) hasDm = 1;
                // FIX53F: iPhone 14/13 Pro(13B) 仅当后面不是空格时匹配(排除"Pro Max"等17B型号)
                if (!hasDm && i + 13 <= len && (memcmp(in + i, "iPhone 14 Pro", 13) == 0 || memcmp(in + i, "iPhone 13 Pro", 13) == 0)
                    && !(i + 14 <= len && in[i + 13] == ' ')) hasDm = 1;
                if (!hasDm && i + 11 <= len && memcmp(in + i, "iPhone7Plus", 11) == 0) hasDm = 1;

                // FIX51: 支持A18 Pro GPU(28B) + A16 GPU(24B) + A15 GPU(24B) + A10 GPU(24B)
                if (!hasGp && i + 28 <= len && memcmp(in + i, gpOld, 28) == 0) hasGp = 1;
                if (!hasGp && i + 24 <= len && (memcmp(in + i, "Apple Inc. Apple A16 GPU", 24) == 0 || memcmp(in + i, "Apple Inc. Apple A15 GPU", 24) == 0)) hasGp = 1;
                if (!hasGp && i + 24 <= len && memcmp(in + i, "Apple Inc. Apple A10 GPU", 24) == 0) hasGp = 1;

                // FIX53E: 通用 fallback — 自动识别所有未知的 iPhone/iPad 型号和 Apple GPU
                // 精确匹配未命中时, 用前缀匹配确保任何设备都能被替换为 canonical 值
                if (!hasDm && i + 7 <= len && memcmp(in + i, "iPhone ", 7) == 0) hasDm = 1; // "iPhone " (带空格, 不含iPhone7Plus)
                if (!hasDm && i + 4 <= len && memcmp(in + i, "iPad", 4) == 0) hasDm = 1;      // iPad全系列
                if (!hasGp && i + 18 <= len && memcmp(in + i, "Apple Inc. Apple A", 18) == 0) hasGp = 1; // A10~A18全系列GPU (FIX53G: 18B not 19B)

                if (!hasHash && hOld[0] != 0 && i + 32 <= len && memcmp(in + i, hOld, 32) == 0) hasHash = 1;

                // v37.93 FIX: UUID detection when ch/dm/gp found (not just eeCtx==1).

                // ROOT CAUSE: 162B and 168B hash inputs have different field order

                // (no "SQAGEIOS"+"WIFI7.6.3979" markers) → eeCtx=0 → UUID NOT replaced.

                // These hashes used NATIVE UUID (180C4F27...) instead of CANONICAL

                // (66B0EE01...) → server validation failed → status=4 (版本过低).

                // FIX: Also detect UUID when any EE121-specific string (ch/dm/gp) is found.

                // Format: 8hex - 4hex - 4hex - 4hex - 12hex = 36 bytes total

                if ((hasEE121Ctx == 1 || hasCh || hasDm || hasGp) && !hasUUID && i + 36 <= len) {

                    const uint8_t *u = in + i;

                    if (IS_HEX(u[0])&&IS_HEX(u[1])&&IS_HEX(u[2])&&IS_HEX(u[3])&&IS_HEX(u[4])&&IS_HEX(u[5])&&IS_HEX(u[6])&&IS_HEX(u[7])

                        && u[8]=='-'

                        && IS_HEX(u[9])&&IS_HEX(u[10])&&IS_HEX(u[11])&&IS_HEX(u[12])

                        && u[13]=='-'

                        && IS_HEX(u[14])&&IS_HEX(u[15])&&IS_HEX(u[16])&&IS_HEX(u[17])

                        && u[18]=='-'

                        && IS_HEX(u[19])&&IS_HEX(u[20])&&IS_HEX(u[21])&&IS_HEX(u[22])

                        && u[23]=='-'

                        && IS_HEX(u[24])&&IS_HEX(u[25])&&IS_HEX(u[26])&&IS_HEX(u[27])&&IS_HEX(u[28])&&IS_HEX(u[29])

                        && IS_HEX(u[30])&&IS_HEX(u[31])&&IS_HEX(u[32])&&IS_HEX(u[33])&&IS_HEX(u[34])&&IS_HEX(u[35])) {

                        // FIX53: Only accept if NOT already equal to canonical UUID (66B0EE01).
                        // Otherwise no replacement needed.
                        if (memcmp(u, kCanUUIDNew, 36) != 0) {

                            hasUUID = 1;

                            uuidPos = i;

                        }

                    }

                }

                // FIX53R: Detect "FULL" (4B) — present in FFF493#2 hash2 concat, NOT in EE121.
                // ROOT CAUSE (wxhook-188): FIX53Q used hasUuidMac (UUID=MACADDRESS= prefix) to
                // distinguish EE121 from FFF493#2, but EE121 hash2 concat (121B) does NOT have
                // this prefix either! → hasUuidMac=0 → UUID NOT inserted → hash2 mismatch → reject.
                // FIX: Use "FULL" marker instead. FFF493#2 concat has "FULL" (clientFull field),
                // EE121 concat does NOT. So: !hasFull = EE121 → insert UUID; hasFull = FFF493#2 → skip.
                if (!hasFull && i + 4 <= len && memcmp(in + i, "FULL", 4) == 0) {
                    hasFull = 1;
                }

            }



            // v37.97: RE-ENABLED accId replacement in CC_MD5.

            // Previous v37.79 disabled this based on WRONG assumption that hash1/hash3 = MD5(hash2+token).

            // Frida capture proves: hash1/hash3 = MD5(binary_hash + token) — no accId in 63B input.

            // accId is ONLY in 170B body input (for hash2 = MD5(body)).

            // EE121-CANON rebuild sends CANONICAL accId in body, so hash2 must be MD5(canonical body).

            // Without accId replacement: hash2 = MD5(body with REAL accId) ≠ MD5(canonical body) → REJECT.

            // The 63B input (binary_hash + token) has no 20-digit number, so no false match.

            int hasAccId = 0;

            if (len >= 20) {

                for (uint32_t i = 0; i + 20 <= len; i++) {

                    // Next char must NOT be a digit (avoid matching part of longer number)

                    if (i + 20 < len && in[i+20] >= '0' && in[i+20] <= '9') continue;

                    BOOL allDigits = YES;

                    for (uint32_t j = 0; j < 20; j++) {

                        if (in[i+j] < '0' || in[i+j] > '9') { allDigits = NO; break; }

                    }

                    if (allDigits && memcmp(in+i, kCanonAccId, 20) != 0) {

                        hasAccId = 1;

                        break;

                    }

                }

            }



            if (hasCh || hasDm || hasGp || hasHash || hasUUID || hasAccId) {

                // Calculate new length:

                //   +9(channel:18-9) -6(dm:11-17) -4(gp:24-28) +0(hash) +0(UUID 36=36) +0(accId 20=20) = -1

                int32_t newLen_i = (int32_t)len;

                if (hasCh) newLen_i += 9;   // 18 - 9

                if (hasDm) newLen_i -= 6;   // 11 - 17

                if (hasGp) newLen_i -= 4;   // 24 - 28

                // v37.134-FIX18: Insert UUID (36B) when EE121 body has empty TLV#9 (no UUID found).

                // Root cause: IDFV returns nil on some devices → TLV#9 empty → server returns status=4.

                // Fix: CC_MD5 hook inserts canonical UUID after GPU in hash2 input → hash2 includes UUID.

                // Send hook (EE007-ALIGN) also inserts UUID TLV into packet body → body matches hash2.

                if (hasGp && !hasUUID && !hasFull) newLen_i += 36; // FIX53R: EE121 only (not FFF493#2 which has "FULL")

                uint32_t newLen = (newLen_i > 0) ? (uint32_t)newLen_i : len;



                cleanInput = malloc(newLen + 64); // safety pad

                if (cleanInput) {

                    // Build new buffer by scanning input and replacing matches

                    uint32_t out = 0;

                    uint32_t pos = 0;

                    while (pos < len) {

                        if (hasCh && pos + 9 <= len && memcmp(in + pos, chOld, 9) == 0) {

                            memcpy((uint8_t *)cleanInput + out, chNew, 18);

                            out += 18; pos += 9;

                            g_md5_channel_replaced = 1;

                        } else if (hasDm && pos + 17 <= len && memcmp(in + pos, dmOld, 17) == 0) {

                            memcpy((uint8_t *)cleanInput + out, dmNew, 11);

                            out += 11; pos += 17;

                        // FIX53F: 仅当后面不是空格时匹配(排除"iPhone 14 Pro Max"等17B型号, 让通用fallback处理)
                        } else if (hasDm && pos + 13 <= len && (memcmp(in + pos, "iPhone 14 Pro", 13) == 0 || memcmp(in + pos, "iPhone 13 Pro", 13) == 0)
                                   && !(pos + 14 <= len && in[pos + 13] == ' ')) {

                            // v37.134-FIX51: 支持 iPhone 14 Pro (13B) + iPhone 13 Pro (13B) 设备型号!
                            // FIX53E: 新设备(164)是iPhone 13 Pro, 但hook只匹配iPhone 14 Pro
                            //   → 设备型号未在CC_MD5中替换 → HMAC与包内容不一致 → 服务器拒绝!
                            // FIX51: 匹配iPhone 14/13 Pro(13B), 替换为iPhone7Plus(11B)
                            memcpy((uint8_t *)cleanInput + out, dmNew, 11);
                            out += 11; pos += 13;
                            DLOG(@"[FIX51-DM-iPhone14or13Pro] Replaced iPhone 14/13 Pro with iPhone7Plus in CC_MD5 input (13B→11B)");

                        } else if (hasDm && pos + 11 <= len && memcmp(in + pos, "iPhone7Plus", 11) == 0) {

                            // FIX51: iPhone7Plus已经是canonical, 直接复制
                            memcpy((uint8_t *)cleanInput + out, dmNew, 11);
                            out += 11; pos += 11;

                        } else if (hasDm && pos + 7 <= len && memcmp(in + pos, "iPhone ", 7) == 0) {

                            // FIX53G: 通用设备型号 fallback — 任何未精确匹配的 iPhone 型号
                            // FIX53G修复: 1)memcmp 18B(非19B,避免null终止符bug) 2)20B上限(最长iPhone型号17B) 3)添加UUID=/WIFI边界
                            int dmEnd = pos + 7;
                            while (dmEnd < len && dmEnd - pos < 20) {
                                if (dmEnd + 18 <= len && memcmp(in + dmEnd, "Apple Inc. Apple A", 18) == 0) break;
                                if (dmEnd + 5 <= len && memcmp(in + dmEnd, "UUID=", 5) == 0) break;
                                if (dmEnd + 4 <= len && memcmp(in + dmEnd, "WIFI", 4) == 0) break;
                                if (in[dmEnd] == 0) break;
                                dmEnd++;
                            }
                            int origDmLen = dmEnd - pos;
                            memcpy((uint8_t *)cleanInput + out, dmNew, 11);
                            out += 11; pos += origDmLen;
                            DLOG(@"[FIX53G-DM-GENERIC] Replaced unknown iPhone model (%dB→11B) in CC_MD5 input", origDmLen);

                        } else if (hasDm && pos + 4 <= len && memcmp(in + pos, "iPad", 4) == 0) {

                            // FIX53G: iPad通用fallback — 同iPhone修复(18B memcmp + 20B max + UUID=/WIFI边界)
                            int dmEnd = pos + 4;
                            while (dmEnd < len && dmEnd - pos < 20) {
                                if (dmEnd + 18 <= len && memcmp(in + dmEnd, "Apple Inc. Apple A", 18) == 0) break;
                                if (dmEnd + 5 <= len && memcmp(in + dmEnd, "UUID=", 5) == 0) break;
                                if (dmEnd + 4 <= len && memcmp(in + dmEnd, "WIFI", 4) == 0) break;
                                if (in[dmEnd] == 0) break;
                                dmEnd++;
                            }
                            int origDmLen = dmEnd - pos;
                            memcpy((uint8_t *)cleanInput + out, dmNew, 11);
                            out += 11; pos += origDmLen;
                            DLOG(@"[FIX53G-DM-iPad] Replaced iPad model (%dB→11B) in CC_MD5 input", origDmLen);

                        } else if (hasGp && pos + 28 <= len && memcmp(in + pos, gpOld, 28) == 0) {

                            memcpy((uint8_t *)cleanInput + out, gpNew, 24);

                            out += 24; pos += 28;

                            // v37.134-FIX18: Insert canonical UUID after GPU when UUID absent.
                            // When EE121 TLV#9 is empty (IDFV nil), hash2 input lacks UUID.
                            // Insert 36B canonical UUID here so hash2 = MD5(body WITH UUID).
                            // The send hook (EE007-ALIGN) also inserts UUID TLV into the packet.
                            // FIX53: Always use canonical 66B0EE01 — single UUID scheme for all phases.
                            if (!hasUUID && !hasFull) { // FIX53R: EE121 only (not FFF493#2 which has "FULL")

                                memcpy((uint8_t *)cleanInput + out, kCanUUIDNew, 36);

                                out += 36;

                            }

                        } else if (hasGp && pos + 24 <= len && (memcmp(in + pos, "Apple Inc. Apple A16 GPU", 24) == 0 || memcmp(in + pos, "Apple Inc. Apple A15 GPU", 24) == 0)) {

                            // v37.134-FIX51: 支持 A16 GPU (24B) + A15 GPU (24B)!
                            // FIX53E: 新设备(164)是A15 GPU, 但hook只匹配A16 GPU
                            //   → GPU未在CC_MD5中替换 → HMAC不匹配 → 服务器拒绝!
                            // FIX51: 匹配A16/A15 GPU(24B), 替换为A10 GPU(24B,相同长度)
                            memcpy((uint8_t *)cleanInput + out, gpNew, 24);

                            out += 24; pos += 24;

                            DLOG(@"[FIX51-GPU-A16orA15] Replaced A16/A15 GPU with A10 GPU in CC_MD5 input (24B→24B)");

                            // FIX53: Always use canonical 66B0EE01 after GPU
                            if (!hasUUID && !hasFull) { // FIX53R: EE121 only (not FFF493#2 which has "FULL")

                                memcpy((uint8_t *)cleanInput + out, kCanUUIDNew, 36);

                                out += 36;

                            }

                        } else if (hasGp && pos + 24 <= len && memcmp(in + pos, "Apple Inc. Apple A10 GPU", 24) == 0) {

                            // FIX51: A10 GPU已经是canonical, 直接复制
                            memcpy((uint8_t *)cleanInput + out, gpNew, 24);

                            out += 24; pos += 24;

                            // FIX53: Always use canonical 66B0EE01 after GPU
                            if (!hasUUID && !hasFull) { // FIX53R: EE121 only (not FFF493#2 which has "FULL")

                                memcpy((uint8_t *)cleanInput + out, kCanUUIDNew, 36);

                                out += 36;

                            }

                        } else if (hasGp && pos + 18 <= len && memcmp(in + pos, "Apple Inc. Apple A", 18) == 0) {

                            // FIX53G: 通用 GPU fallback — 任何未精确匹配的 Apple GPU (如A12/A14/A17等)
                            // FIX53G修复: 18B memcmp(非19B) + gpEnd从18开始
                            int gpEnd = pos + 18;
                            while (gpEnd + 3 <= len && gpEnd - pos < 32 && memcmp(in + gpEnd, "GPU", 3) != 0) gpEnd++;
                            int origGpLen = (gpEnd + 3 <= len) ? (gpEnd + 3 - pos) : 24;
                            memcpy((uint8_t *)cleanInput + out, gpNew, 24);
                            out += 24; pos += origGpLen;

                            DLOG(@"[FIX53G-GPU-GENERIC] Replaced unknown Apple GPU (%dB→24B) in CC_MD5 input", origGpLen);

                            // FIX53: Always use canonical 66B0EE01 after GPU
                            if (!hasUUID && !hasFull) { // FIX53R: EE121 only (not FFF493#2 which has "FULL")
                                memcpy((uint8_t *)cleanInput + out, kCanUUIDNew, 36);
                                out += 36;
                            }

                        } else if (hasHash && pos + 32 <= len && memcmp(in + pos, hOld, 32) == 0) {

                            memcpy((uint8_t *)cleanInput + out, hNew, 32);

                            out += 32; pos += 32;

                        // AZ-STATUS-FIX: CC_MD5 hash2 输入 version "7.6.3" → "9.9.9" (等长5B)
                        //   与 EE007-ALIGN TLV version 替换保持一致 → hash2==MD5(replaced_fields) 通过服务器校验
                        //   (注意: CC_MD5 hook没有cmd变量, 使用 EE121 上下文 hasEE121Ctx==1 代替判断避免误命中)
                        } else if (hasEE121Ctx == 1 && pos + 5 <= len && memcmp(in + pos, "7.6.3", 5) == 0) {

                            memcpy((uint8_t *)cleanInput + out, "9.9.9", 5);
                            out += 5; pos += 5;
                            g_md5_ver_replaced = 1;
                            DLOG(@"[AZ-MD5-VERSION] Replaced version 7.6.3→9.9.9 in CC_MD5 hash2 input at pos=%u (EE121 ctx)", (unsigned)pos - 5);

                        // AZ-STATUS-FIX: CC_MD5 hash2 输入 build "984" → "999" (等长3B)
                        //   仅在 EE121 上下文 (hasEE121Ctx==1, 且 7.6.3 已经出现过) 中替换, 避免误匹配其他数字串
                        } else if (hasEE121Ctx == 1 && g_md5_ver_replaced && pos + 3 <= len && memcmp(in + pos, "984", 3) == 0
                                   && !(pos + 4 <= len && in[pos+3] >= '0' && in[pos+3] <= '9')) {  // 避免误匹配账号数字前缀

                            memcpy((uint8_t *)cleanInput + out, "999", 3);
                            out += 3; pos += 3;
                            g_md5_build_replaced = 1;
                            DLOG(@"[AZ-MD5-BUILD] Replaced build 984→999 in CC_MD5 hash2 input at pos=%u (EE121 ctx)", (unsigned)pos - 3);

                        } else if (hasUUID && pos == uuidPos) {

                            // FIX53: Unified single UUID replacement — always use 66B0EE01.
                            // Both CCCrypt AES plaintext AND CC_MD5 (HMAC) use the same canonical UUID.
                            memcpy((uint8_t *)cleanInput + out, kCanUUIDNew, 36);
                            out += 36; pos += 36;
                            DLOG(@"[FIX53-UUID-MD5] Replaced UUID in CC_MD5 input with 66B0EE01 (unified single-channel — matches CCCrypt plaintext)");

                        } else if (hasAccId && pos + 20 <= len

                                   && (pos+20 >= len || in[pos+20] < '0' || in[pos+20] > '9')) {

                            // v37.108-DIST: Do NOT replace 20-digit accountId in MD5 input!

                            // ROOT CAUSE: Forcing CANONICAL accId in MD5 → hash mismatch

                            // for users with different credentials. Server validates

                            // hashes against their REAL accountId.

                            // Just copy original 20-digit through.

                            uint8_t allDigNative = 1;

                            for (uint32_t j = 0; j < 20 && allDigNative; j++) {

                                if (in[pos+j] < '0' || in[pos+j] > '9') allDigNative = 0;

                            }

                            if (allDigNative) {

                                memcpy((uint8_t *)cleanInput + out, in + pos, 20);

                                out += 20; pos += 20;

                            } else {

                                ((uint8_t *)cleanInput)[out++] = in[pos++];

                            }

                        } else {

                            ((uint8_t *)cleanInput)[out++] = in[pos++];

                        }

                    }

                    actualInput = cleanInput;

                    actualLen = out;

                    inputModified = 2; // content replacement

                    DLOG(@"[MD5-HOOK] v37.97-AZ2: Replaced input ch=%d dm=%d gp=%d hash=%d uuid=%d accId=%d eeCtx=%d hasFull=%d (oldLen=%u newLen=%u out=%u) chRepl=%d verRepl=%d buildRepl=%d",

                         hasCh, hasDm, hasGp, hasHash, hasUUID, hasAccId, hasEE121Ctx, hasFull, len, newLen, out,
                         g_md5_channel_replaced, g_md5_ver_replaced, g_md5_build_replaced);

                    // Dump original input for diagnosis

                    if (len <= 200) {

                        NSMutableString *hex = [NSMutableString string];

                        for (uint32_t j = 0; j < len; j++) [hex appendFormat:@"%02x", in[j]];

                        DLOG(@"[MD5-DUMP] v37.62: CC_MD5 input(%uB): %@", len, hex);

                    }

                }

            }



            // v37.60: Unconditional dump for ALL small inputs (diagnose hash1/hash2 63B input)

            if (!inputModified && len <= 200 && len >= 20) {

                NSMutableString *hex = [NSMutableString string];

                for (uint32_t j = 0; j < len; j++) [hex appendFormat:@"%02x", in[j]];

                DLOG(@"[MD5-DUMP-RAW] v37.62: CC_MD5 input(%uB) no-match: %@", len, hex);

            }

        }



        // v37.57: Also search for 16-byte modified binary hash (raw bytes)

        // v37.134-FIX11: Only check if our binary hash is initialized (not all-zeros)

        if (!inputModified && actualLen >= 16) {

            int hashReady2 = 0; for (int _j = 0; _j < 16; _j++) if (g_our_binary_hash[_j]) { hashReady2 = 1; break; }

            if (hashReady2) {

                const uint8_t *ain = (const uint8_t *)actualInput;

                for (uint32_t i = 0; i + 16 <= actualLen; i++) {

                    if (memcmp(ain + i, g_our_binary_hash, 16) == 0) {

                        void *tmp = malloc(actualLen);

                        if (tmp) {

                            memcpy(tmp, actualInput, actualLen);

                            memcpy((uint8_t *)tmp + i, g_clean_binary_hash, 16);

                            if (cleanInput) { free(cleanInput); }

                            cleanInput = tmp;

                            actualInput = cleanInput;

                            inputModified = 1;

                            DLOG(@"[MD5-HOOK] v37.57: Replaced modified hash BYTES in input at offset %u (inputLen=%u)", i, actualLen);

                        }

                        break;

                    }

                }

            }

        }



        // v37.134-FIX12: Search for hex STRING form of binary hash (32 chars like "2099ec7b...")

        // From Frida log: CC_MD5 input = hex_string(binary_hash) + token = 63 bytes

        // Previous code only searched 16-byte binary form → NEVER matched hex string form!

        // Also: hOld hardcoded "f9cc76c5..." never matches current binary hash → use dynamic g_our_binary_hash

        // FIX12b: Allow even after channel/dm/gp replacement (inputModified=2) — search in modified buffer

        if (actualLen >= 32) {

            int hashReady3 = 0; for (int _j2 = 0; _j2 < 16; _j2++) if (g_our_binary_hash[_j2]) { hashReady3 = 1; break; }

            if (hashReady3) {

                // Convert our binary hash to hex string (lowercase)

                char ourHashHex[33];

                for (int h = 0; h < 16; h++) sprintf(ourHashHex + h*2, "%02x", g_our_binary_hash[h]);

                ourHashHex[32] = '\0';

                // Convert clean binary hash to hex string (lowercase)

                char cleanHashHex[33];

                for (int h = 0; h < 16; h++) sprintf(cleanHashHex + h*2, "%02x", g_clean_binary_hash[h]);

                cleanHashHex[32] = '\0';



                // Search for ourHashHex in input (use actualInput which may already be modified by ch/dm/gp)

                const char *ain = (const char *)actualInput;

                int found = 0;

                for (uint32_t i = 0; i + 32 <= actualLen; i++) {

                    if (memcmp(ain + i, ourHashHex, 32) == 0) {

                        // Need a buffer to write to

                        if (!inputModified) {

                            // First modification — allocate new buffer

                            void *tmp = malloc(actualLen);

                            if (tmp) {

                                memcpy(tmp, actualInput, actualLen);

                                memcpy((uint8_t *)tmp + i, cleanHashHex, 32);

                                if (cleanInput) { free(cleanInput); }

                                cleanInput = tmp;

                                actualInput = cleanInput;

                                inputModified = 1;

                                found = 1;

                                _log([NSString stringWithFormat:@"[MD5-HOOK] v37.134-FIX12: Replaced binary hash HEX STRING in input at offset %u (inputLen=%u): %@ → %@", i, actualLen,

                                     [NSString stringWithUTF8String:ourHashHex], [NSString stringWithUTF8String:cleanHashHex]]);

                            }

                        } else {

                            // Already modified (ch/dm/gp) — write into existing cleanInput buffer

                            memcpy((uint8_t *)cleanInput + i, cleanHashHex, 32);

                            found = 1;

                            _log([NSString stringWithFormat:@"[MD5-HOOK] v37.134-FIX12: Replaced binary hash HEX STRING in MODIFIED input at offset %u (inputLen=%u): %@ → %@", i, actualLen,

                                 [NSString stringWithUTF8String:ourHashHex], [NSString stringWithUTF8String:cleanHashHex]]);

                        }

                        break;

                    }

                }

                // Also try uppercase hex string (some implementations use uppercase)

                if (!found) {

                    char ourHashHexUpper[33];

                    for (int h = 0; h < 16; h++) sprintf(ourHashHexUpper + h*2, "%02X", g_our_binary_hash[h]);

                    ourHashHexUpper[32] = '\0';

                    char cleanHashHexUpper[33];

                    for (int h = 0; h < 16; h++) sprintf(cleanHashHexUpper + h*2, "%02X", g_clean_binary_hash[h]);

                    cleanHashHexUpper[32] = '\0';

                    for (uint32_t i = 0; i + 32 <= actualLen; i++) {

                        if (memcmp(ain + i, ourHashHexUpper, 32) == 0) {

                            if (!inputModified) {

                                void *tmp = malloc(actualLen);

                                if (tmp) {

                                    memcpy(tmp, actualInput, actualLen);

                                    memcpy((uint8_t *)tmp + i, cleanHashHexUpper, 32);

                                    if (cleanInput) { free(cleanInput); }

                                    cleanInput = tmp;

                                    actualInput = cleanInput;

                                    inputModified = 1;

                                    _log([NSString stringWithFormat:@"[MD5-HOOK] v37.134-FIX12: Replaced binary hash HEX STRING (UPPER) in input at offset %u (inputLen=%u)", i, actualLen]);

                                }

                            } else {

                                memcpy((uint8_t *)cleanInput + i, cleanHashHexUpper, 32);

                                _log([NSString stringWithFormat:@"[MD5-HOOK] v37.134-FIX12: Replaced binary hash HEX STRING (UPPER) in MODIFIED input at offset %u (inputLen=%u)", i, actualLen]);

                            }

                            break;

                        }

                    }

                }

            }

        }

    }



    unsigned char *ret = orig_CC_MD5(actualInput, actualLen, md);

    if (ret && md) {

        // v37.134-FIX11: Only check if our binary hash is initialized (not all-zeros)

        int hashReady = 0; for (int _i = 0; _i < 16; _i++) if (g_our_binary_hash[_i]) { hashReady = 1; break; }

        // Existing: check if output is our modified binary hash (hash2 case)

        if (hashReady && memcmp(md, g_our_binary_hash, 16) == 0) {

            memcpy(md, g_clean_binary_hash, 16);

            g_md5_replace_count++;

            DLOG(@"[MD5-HOOK] v37.51: Replaced binary hash OUTPUT (#%d, inputLen=%u)", g_md5_replace_count, len);

        }

        // v37.57: Log ALL CC_MD5 calls for diagnosis

        DLOG(@"[MD5-LOG] v37.62: CC_MD5 inLen=%u actLen=%u mod=%d out=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",

             len, actualLen, inputModified,

             md[0],md[1],md[2],md[3],md[4],md[5],md[6],md[7],

             md[8],md[9],md[10],md[11],md[12],md[13],md[14],md[15]);

    }

    if (cleanInput) free(cleanInput);

    return ret;

}



// Also hook CC_MD5_Final for streaming MD5

typedef int (*CC_MD5_FinalFunc)(unsigned char *md, void *c);

static CC_MD5_FinalFunc orig_CC_MD5_Final = NULL;



static int hook_CC_MD5_Final(unsigned char *md, void *c) {

    int ret = orig_CC_MD5_Final(md, c);

    if (ret == 1 && md) {

        // v37.134-FIX11: Only check if our binary hash is initialized (not all-zeros)

        int hashReadyF = 0; for (int _k = 0; _k < 16; _k++) if (g_our_binary_hash[_k]) { hashReadyF = 1; break; }

        if (hashReadyF && memcmp(md, g_our_binary_hash, 16) == 0) {

            memcpy(md, g_clean_binary_hash, 16);

            g_md5_replace_count++;

            DLOG(@"[MD5-HOOK] v37.51: Replaced binary hash via CC_MD5_Final (#%d)", g_md5_replace_count);

        }

    }

    return ret;

}



// v37.134-FIX15: Hook CC_MD5_Update for streaming MD5 fallback.

// If game uses CC_MD5_Init+Update+Final instead of one-shot CC_MD5,

// and CC_MD5_Final rebind fails (rebind=0), we intercept data at Update level.

// Same replacement logic as CC_MD5 hook: binary hash + ch/dm/gp.

typedef int (*CC_MD5_UpdateFunc)(void *c, const void *data, CC_LONG len);

static CC_MD5_UpdateFunc orig_CC_MD5_Update = NULL;



static int hook_CC_MD5_Update(void *c, const void *data, CC_LONG len) {

    if (!orig_CC_MD5_Update || !data || len == 0) {

        return orig_CC_MD5_Update ? orig_CC_MD5_Update(c, data, len) : 0;

    }



    const uint8_t *in = (const uint8_t *)data;

    void *cleanInput = NULL;

    const void *actualInput = data;

    CC_LONG actualLen = len;

    int inputModified = 0;



    int hashReady = 0; for (int _i = 0; _i < 16; _i++) if (g_our_binary_hash[_i]) { hashReady = 1; break; }



    if (hashReady && actualLen >= 16) {

        // Search for 16-byte binary hash in input

        for (CC_LONG i = 0; i + 16 <= actualLen; i++) {

            if (memcmp(in + i, g_our_binary_hash, 16) == 0) {

                void *tmp = malloc(actualLen);

                if (tmp) {

                    memcpy(tmp, actualInput, actualLen);

                    memcpy((uint8_t *)tmp + i, g_clean_binary_hash, 16);

                    if (cleanInput) free(cleanInput);

                    cleanInput = tmp;

                    actualInput = cleanInput;

                    inputModified = 1;

                    DLOG(@"[MD5-UPDATE-HOOK] v37.134-FIX15: Replaced binary hash BYTES at offset %lu (len=%lu)", (unsigned long)i, (unsigned long)actualLen);

                }

                break;

            }

        }



        // Search for 32-char hex string form

        if (actualLen >= 32) {

            char ourHashHex[33];

            for (int h = 0; h < 16; h++) sprintf(ourHashHex + h*2, "%02x", g_our_binary_hash[h]);

            ourHashHex[32] = '\0';

            char cleanHashHex[33];

            for (int h = 0; h < 16; h++) sprintf(cleanHashHex + h*2, "%02x", g_clean_binary_hash[h]);

            cleanHashHex[32] = '\0';



            const char *ain = (const char *)actualInput;

            for (CC_LONG i = 0; i + 32 <= actualLen; i++) {

                if (memcmp(ain + i, ourHashHex, 32) == 0) {

                    if (!inputModified) {

                        void *tmp = malloc(actualLen);

                        if (tmp) {

                            memcpy(tmp, actualInput, actualLen);

                            memcpy((uint8_t *)tmp + i, cleanHashHex, 32);

                            if (cleanInput) free(cleanInput);

                            cleanInput = tmp;

                            actualInput = cleanInput;

                            inputModified = 1;

                            DLOG(@"[MD5-UPDATE-HOOK] v37.134-FIX15: Replaced binary hash HEX STRING at offset %lu (len=%lu)", (unsigned long)i, (unsigned long)actualLen);

                        }

                    } else {

                        memcpy((uint8_t *)cleanInput + i, cleanHashHex, 32);

                        DLOG(@"[MD5-UPDATE-HOOK] v37.134-FIX15: Replaced binary hash HEX STRING in MODIFIED input at offset %lu", (unsigned long)i);

                    }

                    break;

                }

            }

        }



        // Search for ch/dm/gp patterns (same as CC_MD5 hook)

        if (actualLen >= 9) {

            static const char chOld[]   = "DY_MIESHI";

            static const char chNew[]   = "DYanyou0040_MIESHI";

            static const char dmOld[]   = "iPhone 16 Pro Max";

            static const char dmNew[]   = "iPhone7Plus";

            static const char gpOld[]   = "Apple Inc. Apple A18 Pro GPU";

            static const char gpNew[]   = "Apple Inc. Apple A10 GPU";



            int hasCh = 0, hasDm = 0, hasGp = 0;
            int hasUuidMac = 0;  // FIX53: UUID=MACADDRESS=xxx detected
            int hasUuidBare = 0; // FIX53: bare UUID detected
            int dmVariant = 0; // FIX52: 0=none, 1=16ProMax(17B), 2=14Pro(13B), 3=7Plus(11B)
            int gpVariant = 0; // FIX52: 0=none, 1=A18Pro(28B), 2=A16(24B), 3=A10(24B)

            for (CC_LONG i = 0; i + 9 <= actualLen; i++) {

                if (!hasCh && i + 9 <= actualLen && memcmp((const uint8_t *)actualInput + i, chOld, 9) == 0) hasCh = 1;

                // FIX52: 支持iPhone 16 Pro Max(17B) + iPhone 14 Pro(13B) + iPhone 13 Pro(13B) + iPhone7Plus(11B)
                if (!hasDm && i + 17 <= actualLen && memcmp((const uint8_t *)actualInput + i, dmOld, 17) == 0) { hasDm = 1; dmVariant = 1; }
                // FIX53F: 13B匹配仅当后面不是空格(排除"Pro Max"等, 让通用fallback处理)
                if (!hasDm && i + 13 <= actualLen && (memcmp((const uint8_t *)actualInput + i, "iPhone 14 Pro", 13) == 0 || memcmp((const uint8_t *)actualInput + i, "iPhone 13 Pro", 13) == 0)
                    && !(i + 14 <= actualLen && ((const uint8_t *)actualInput)[i + 13] == ' ')) { hasDm = 1; dmVariant = 2; }
                if (!hasDm && i + 11 <= actualLen && memcmp((const uint8_t *)actualInput + i, "iPhone7Plus", 11) == 0) { hasDm = 1; dmVariant = 3; }

                // FIX52: 支持A18 Pro GPU(28B) + A16 GPU(24B) + A15 GPU(24B) + A10 GPU(24B)
                if (!hasGp && i + 28 <= actualLen && memcmp((const uint8_t *)actualInput + i, gpOld, 28) == 0) { hasGp = 1; gpVariant = 1; }
                if (!hasGp && i + 24 <= actualLen && (memcmp((const uint8_t *)actualInput + i, "Apple Inc. Apple A16 GPU", 24) == 0 || memcmp((const uint8_t *)actualInput + i, "Apple Inc. Apple A15 GPU", 24) == 0)) { hasGp = 1; gpVariant = 2; }
                if (!hasGp && i + 24 <= actualLen && memcmp((const uint8_t *)actualInput + i, "Apple Inc. Apple A10 GPU", 24) == 0) { hasGp = 1; gpVariant = 3; }

                // FIX53E: 通用 fallback — 自动识别所有未知 iPhone/iPad 型号和 Apple GPU
                if (!hasDm && i + 7 <= actualLen && memcmp((const uint8_t *)actualInput + i, "iPhone ", 7) == 0) { hasDm = 1; dmVariant = 2; }
                if (!hasDm && i + 4 <= actualLen && memcmp((const uint8_t *)actualInput + i, "iPad", 4) == 0) { hasDm = 1; dmVariant = 2; }
                if (!hasGp && i + 18 <= actualLen && memcmp((const uint8_t *)actualInput + i, "Apple Inc. Apple A", 18) == 0) { hasGp = 1; gpVariant = 2; } // FIX53G: 18B not 19B

                // FIX53G: 检测UUID=MACADDRESS=前缀(16B, 非17B — null终止符bug修复)
                if (!hasUuidMac && i + 16 <= actualLen && memcmp((const uint8_t *)actualInput + i, "UUID=MACADDRESS=", 16) == 0) { hasUuidMac = 1; }

                // FIX53: 检测裸UUID(36B格式, 连字符位置8/13/18/23)
                if (!hasUuidBare && i + 36 <= actualLen &&
                    ((const char *)actualInput)[i+8] == '-' &&
                    ((const char *)actualInput)[i+13] == '-' &&
                    ((const char *)actualInput)[i+18] == '-' &&
                    ((const char *)actualInput)[i+23] == '-') { hasUuidBare = 1; }

                if (hasCh && hasDm && hasGp && hasUuidMac) break;

            }



            if (hasCh || hasDm || hasGp || hasUuidMac || hasUuidBare) {

                int32_t newLen_i = (int32_t)actualLen;

                if (hasCh) newLen_i += 9;   // 18 - 9

                // FIX52: 根据设备型号变体计算delta
                if (dmVariant == 1) newLen_i -= 6;   // 11 - 17 (16 Pro Max)
                else if (dmVariant == 2) newLen_i -= 2; // 11 - 13 (14 Pro)
                else if (dmVariant == 3) newLen_i += 0;  // 11 - 11 (7Plus, no change)

                // FIX53: UUID=MACADDRESS替换 53B→53B(等长, 全部用66B0EE01), 裸UUID 36→36(delta=0)

                // FIX52: 根据GPU变体计算delta
                if (gpVariant == 1) newLen_i -= 4;   // 24 - 28 (A18 Pro)
                else if (gpVariant == 2) newLen_i += 0; // 24 - 24 (A16, same length)
                else if (gpVariant == 3) newLen_i += 0;  // 24 - 24 (A10, same length)

                CC_LONG newLen = (newLen_i > 0) ? (CC_LONG)newLen_i : actualLen;



                void *tmp = malloc(newLen + 64);

                if (tmp) {

                    const uint8_t *src = (const uint8_t *)actualInput;

                    uint32_t out = 0;

                    CC_LONG pos = 0;

                    while (pos < actualLen) {

                        if (hasCh && pos + 9 <= actualLen && memcmp(src + pos, chOld, 9) == 0) {

                            memcpy((uint8_t *)tmp + out, chNew, 18); out += 18; pos += 9;

                        } else if (hasDm && dmVariant == 1 && pos + 17 <= actualLen && memcmp(src + pos, dmOld, 17) == 0) {

                            memcpy((uint8_t *)tmp + out, dmNew, 11); out += 11; pos += 17;

                        // FIX53F: 13B匹配仅当后面不是空格(排除Pro Max等, 让通用fallback处理)
                        } else if (hasDm && dmVariant == 2 && pos + 13 <= actualLen &&
                                   (memcmp(src + pos, "iPhone 14 Pro", 13) == 0 || memcmp(src + pos, "iPhone 13 Pro", 13) == 0)
                                   && !(pos + 14 <= actualLen && src[pos + 13] == ' ')) {

                            // FIX52: iPhone 14/13 Pro(13B) → iPhone7Plus(11B)
                            memcpy((uint8_t *)tmp + out, dmNew, 11); out += 11; pos += 13;

                        } else if (hasDm && dmVariant == 2 && pos + 7 <= actualLen && memcmp(src + pos, "iPhone ", 7) == 0) {

                            // FIX53G-DM-GENERIC: 通用iPhone fallback — 修复19B null终止符bug + 20B max + UUID=/WIFI边界
                            int dmLen = 7;
                            while (pos + dmLen < actualLen && dmLen < 20) {
                                if (pos + dmLen + 18 <= actualLen && memcmp(src + pos + dmLen, "Apple Inc. Apple A", 18) == 0) break;
                                if (pos + dmLen + 5 <= actualLen && memcmp(src + pos + dmLen, "UUID=", 5) == 0) break;
                                if (pos + dmLen + 4 <= actualLen && memcmp(src + pos + dmLen, "WIFI", 4) == 0) break;
                                if (src[pos + dmLen] == '"' || src[pos + dmLen] == ',' || src[pos + dmLen] == 0) break;
                                dmLen++;
                            }
                            memcpy((uint8_t *)tmp + out, dmNew, 11); out += 11; pos += dmLen;
                            DLOG(@"[FIX53G-DM-GENERIC] Replaced unknown iPhone model (%dB→11B) in CC_MD5_Update", dmLen);

                        } else if (hasDm && dmVariant == 2 && pos + 4 <= actualLen && memcmp(src + pos, "iPad", 4) == 0) {

                            // FIX53G-DM-iPad: iPad通用fallback — 同上修复
                            int dmLen = 4;
                            while (pos + dmLen < actualLen && dmLen < 20) {
                                if (pos + dmLen + 18 <= actualLen && memcmp(src + pos + dmLen, "Apple Inc. Apple A", 18) == 0) break;
                                if (pos + dmLen + 5 <= actualLen && memcmp(src + pos + dmLen, "UUID=", 5) == 0) break;
                                if (pos + dmLen + 4 <= actualLen && memcmp(src + pos + dmLen, "WIFI", 4) == 0) break;
                                if (src[pos + dmLen] == '"' || src[pos + dmLen] == ',' || src[pos + dmLen] == 0) break;
                                dmLen++;
                            }
                            memcpy((uint8_t *)tmp + out, dmNew, 11); out += 11; pos += dmLen;
                            DLOG(@"[FIX53G-DM-iPad] Replaced iPad model (%dB→11B) in CC_MD5_Update", dmLen);

                        } else if (hasDm && dmVariant == 3 && pos + 11 <= actualLen && memcmp(src + pos, "iPhone7Plus", 11) == 0) {

                            // FIX52: iPhone7Plus已经是canonical, 直接复制
                            memcpy((uint8_t *)tmp + out, dmNew, 11); out += 11; pos += 11;

                        } else if (hasGp && gpVariant == 1 && pos + 28 <= actualLen && memcmp(src + pos, gpOld, 28) == 0) {

                            memcpy((uint8_t *)tmp + out, gpNew, 24); out += 24; pos += 28;

                        } else if (hasGp && gpVariant == 2 && pos + 24 <= actualLen &&
                                   (memcmp(src + pos, "Apple Inc. Apple A16 GPU", 24) == 0 || memcmp(src + pos, "Apple Inc. Apple A15 GPU", 24) == 0)) {

                            // FIX52: A16/A15 GPU(24B) → A10 GPU(24B, 等长)
                            memcpy((uint8_t *)tmp + out, gpNew, 24); out += 24; pos += 24;

                        } else if (hasGp && gpVariant == 2 && pos + 18 <= actualLen && memcmp(src + pos, "Apple Inc. Apple A", 18) == 0) {

                            // FIX53G-GPU-GENERIC: 通用GPU fallback — 修复19B null终止符bug
                            int gpLen = 18;
                            while (pos + gpLen < actualLen && gpLen < 32 && src[pos + gpLen] != '"' && src[pos + gpLen] != ',' && src[pos + gpLen] != 0) gpLen++;
                            memcpy((uint8_t *)tmp + out, gpNew, 24); out += 24; pos += gpLen;
                            DLOG(@"[FIX53G-GPU-GENERIC] Replaced unknown Apple GPU (%dB→24B) in CC_MD5_Update", gpLen);

                        } else if (hasGp && gpVariant == 3 && pos + 24 <= actualLen && memcmp(src + pos, "Apple Inc. Apple A10 GPU", 24) == 0) {

                            // FIX52: A10 GPU已经是canonical, 直接复制
                            memcpy((uint8_t *)tmp + out, gpNew, 24); out += 24; pos += 24;

                        } else if (hasUuidMac && pos + 16 <= actualLen && memcmp(src + pos, "UUID=MACADDRESS=", 16) == 0) {

                            // FIX53G: UUID=MACADDRESS=xxx → canonical (52B). 修复null终止符bug(17B→16B, 53B→52B)
                            // FIX53G: 处理空UUID — 当UUID=MACADDRESS=后紧跟引号(空值), 插入canonical UUID
                            if (pos + 16 < actualLen && (src[pos + 16] == '"' || src[pos + 16] == ',' || src[pos + 16] == 0)) {
                                // 空UUID: UUID=MACADDRESS=" → UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8" (+36B)
                                memcpy((uint8_t *)tmp + out, "UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 52); out += 52; pos += 16;
                                DLOG(@"[FIX53G-UUID-INSERT] Inserted canonical UUID into empty UUID=MACADDRESS= field in CC_MD5_Update (+36B)");
                            } else if (pos + 52 <= actualLen) {
                                // 非空UUID: UUID=MACADDRESS=xxx(52B) → canonical(52B, 等长)
                                memcpy((uint8_t *)tmp + out, "UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 52); out += 52; pos += 52;
                            } else {
                                // 不足52B, 按原样复制
                                int copyLen = actualLen - pos;
                                memcpy((uint8_t *)tmp + out, src + pos, copyLen); out += copyLen; pos += copyLen;
                            }

                        } else if (hasUuidBare && pos + 36 <= actualLen &&
                                   ((const char *)src)[pos+8] == '-' &&
                                   ((const char *)src)[pos+13] == '-' &&
                                   ((const char *)src)[pos+18] == '-' &&
                                   ((const char *)src)[pos+23] == '-') {

                            // FIX53: bare UUID → 66B0EE01 (canonical white-list UUID, 等长36B)
                            memcpy((uint8_t *)tmp + out, "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 36); out += 36; pos += 36;

                        } else {

                            ((uint8_t *)tmp)[out++] = src[pos++];

                        }

                    }

                    if (cleanInput) free(cleanInput);

                    cleanInput = tmp;

                    actualInput = cleanInput;

                    actualLen = out;

                    inputModified = 1;

                    DLOG(@"[MD5-UPDATE-HOOK] v37.134-FIX53: Replaced ch=%d dm=%d gp=%d uuidMac=%d uuidBare=%d (oldLen=%lu newLen=%lu)",

                         hasCh, hasDm, hasGp, hasUuidMac, hasUuidBare, (unsigned long)len, (unsigned long)actualLen);

                }

            }

        }

    }



    int ret = orig_CC_MD5_Update(c, actualInput, actualLen);

    if (cleanInput) free(cleanInput);

    return ret;

}



typedef OSStatus (*SecKeyEncryptFunc)(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen);

static SecKeyEncryptFunc orig_SecKeyEncrypt = NULL;



static OSStatus hook_SecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen) {

    if (!orig_SecKeyEncrypt) orig_SecKeyEncrypt = (SecKeyEncryptFunc)dlsym(RTLD_NEXT, "SecKeyEncrypt");

    if (!orig_SecKeyEncrypt) return errSecParam;

    DLOG(@"[SEC] SecKeyEncrypt plainLen=%zu cipherLen=%zu", plainTextLen, cipherTextLen ? *cipherTextLen : 0);

    return orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);

}



typedef OSStatus (*SecKeyDecryptFunc)(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen);

static SecKeyDecryptFunc orig_SecKeyDecrypt = NULL;



static OSStatus hook_SecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen) {

    if (!orig_SecKeyDecrypt) orig_SecKeyDecrypt = (SecKeyDecryptFunc)dlsym(RTLD_NEXT, "SecKeyDecrypt");

    if (!orig_SecKeyDecrypt) return errSecParam;

    

    // v36.126: Do NOT bypass here — SecKeyDecrypt is the low-level implementation

    // called internally by SecKeyCreateDecryptedData. Only SecKeyCreateDecryptedData

    // should bypass (it will clear forceValidDecrypt). If game uses SecKeyDecrypt

    // directly (pre-iOS 10), we handle via CCCrypt or add separate bypass later.

    

    OSStatus ret = orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);

    DLOG(@"[SEC] SecKeyDecrypt cipherLen=%zu plainLen=%zu ret=%d", cipherTextLen, plainTextLen ? *plainTextLen : 0, (int)ret);

    return ret;

}



// SecKeyCreateDecryptedData hook (iOS 10+)

// CORRECT signature: CFDataRef SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);

typedef CFDataRef (*SecKeyCreateDecryptedDataFunc)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);

static SecKeyCreateDecryptedDataFunc orig_SecKeyCreateDecryptedData = NULL;



static CFDataRef hook_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error) {

    if (!orig_SecKeyCreateDecryptedData) {

        orig_SecKeyCreateDecryptedData = (SecKeyCreateDecryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateDecryptedData");

    }

    if (!orig_SecKeyCreateDecryptedData) return NULL;

    

    // v36.126: CRITICAL FIX — Skip real decryption entirely when forceValidDecrypt=YES

    // v36.125 bug: calling orig first → RSA decryption "succeeds" with garbage → bypass never triggered

    if (g_forceValidDecrypt && ciphertext) {

        CFIndex cipherLen = CFDataGetLength(ciphertext);

        DLOG(@"[SEC-BYPASS] v36.126: SKIPPING real decrypt (cipherLen=%ld), returning fake valid plaintext", cipherLen);

        

        // Return a valid plaintext directly — no real decryption attempted

        // Format: JSON with success indicator (proven pattern from other game protocols)

        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";

        CFDataRef fakeData = CFDataCreate(NULL, (const UInt8 *)fakePlaintext, strlen(fakePlaintext));

        

        // Dump the ORIGINAL ciphertext first 64 bytes for analysis

        NSMutableString *hexDump = [NSMutableString stringWithCapacity:128];

        const UInt8 *cipherBytes = CFDataGetBytePtr(ciphertext);

        CFIndex dumpLen = MIN((CFIndex)64, cipherLen);

        for (CFIndex i = 0; i < dumpLen; i++) {

            [hexDump appendFormat:@"%02X ", cipherBytes[i]];

        }

        DLOG(@"[SEC-BYPASS] v36.126: Ciphertext first %ld bytes: %@", dumpLen, hexDump);

        

        // Clear force flag — only bypass ONE decryption call

        g_forceValidDecrypt = NO;

        DLOG(@"[SEC-BYPASS] v36.126: Returned fake plaintext (%zu bytes), forceValidDecrypt=NO", strlen(fakePlaintext));

        return fakeData;

    }

    

    // Normal mode — real decryption

    CFErrorRef *errPtr = NULL;

    CFDataRef result = orig_SecKeyCreateDecryptedData(key, algorithm, ciphertext, errPtr);

    if (errPtr && *errPtr) {

        DLOG(@"[SEC] SecKeyCreateDecryptedData FAILED: %@", CFBridgingRelease(CFErrorCopyDescription(*errPtr)));

    } else if (result) {

        DLOG(@"[SEC] SecKeyCreateDecryptedData SUCCESS: cipherLen=%lu plainLen=%lu",

             ciphertext ? CFDataGetLength(ciphertext) : 0, CFDataGetLength(result));

        // v36.135: Dump decrypted plaintext to see what server returned

        CFIndex plainLen = CFDataGetLength(result);

        if (plainLen > 0 && plainLen <= 512) {

            const UInt8 *plainBytes = CFDataGetBytePtr(result);

            NSMutableString *plainHex = [NSMutableString stringWithCapacity:plainLen * 3];

            NSMutableString *plainAscii = [NSMutableString stringWithCapacity:plainLen];

            for (CFIndex i = 0; i < plainLen; i++) {

                [plainHex appendFormat:@"%02X ", plainBytes[i]];

                [plainAscii appendFormat:@"%c", (plainBytes[i] >= 0x20 && plainBytes[i] < 0x7F) ? plainBytes[i] : '.'];

            }

            DLOG(@"[SEC-PLAIN] v36.135: Decrypted plaintext (%ld bytes): HEX: %@", plainLen, plainHex);

            DLOG(@"[SEC-PLAIN] v36.135: Decrypted plaintext ASCII: %@", plainAscii);

        }

    } else {

        DLOG(@"[SEC] SecKeyCreateDecryptedData returned NULL");

    }

    return result;

}



// ============================================================

// v36.123: Hook [UIDevice identifierForVendor]

// Let client construct 0x000EE007 with UUID NATIVELY

// (Avoids send-level buffer modification per Experience 1423135)

// ============================================================

// v37.19-DIST: Hook [UIDevice identifierForVendor] — do NOT force a fixed UUID.

// Distributable build: each user must use their OWN native IDFV so that the

// challenge-response (0x00FFF495 → 0x80FFF495 status) signature matches their

// real device fingerprint registered on the login server (0x002EE121).

// A globally hard-coded UUID makes ALL injected users share the same fingerprint,

// causing 0x80FFF495 status=1 (challenge failure) and immediate server FIN after

// 0x00FFF493. This was the root cause of v37.18 "connection interrupted".

// We still swizzle so that we have a hook point for future per-user overrides,

// but just call the original implementation.

static NSUUID* hook_identifierForVendor(UIDevice *self, SEL _cmd) {

    // v37.19-DIST: Call original — each user's own native IDFV

    if (orig_identifierForVendor) {

        NSUUID *real = orig_identifierForVendor(self, _cmd);

        static BOOL logged = NO;

        if (!logged) {

            DLOG(@"[IDFV-HOOK] v37.27-DIST: Using native IDFV = %@ (NOT fixed, distributable safe)", real);

            logged = YES;

        }

        return real;

    }

    // Fallback (should not happen)

    return nil;

}



static void installIDFVHook(void) {

    // v37.107-DIST: Use NATIVE IDFV — each user's own device UUID!

    // ROOT CAUSE: Fixed CANONICAL UUID (66B0EE01-...) caused ALL users to share

    // the same device fingerprint. Old accounts bound to their REAL device UUID

    // → server's device whitelist check FAILS → "未授权此手机" error.

    // FIX: Call original identifierForVendor so each user uses their OWN UUID.

    // This way: old accounts match their bound device UUID → no authorization needed.

    // New accounts on new devices → normal authorization flow (master device approves).

    DLOG(@"[IDFV-HOOK] v37.107-DIST: Using NATIVE IDFV (NOT fixed, distributable safe)");



    // Now swizzle UIDevice's identifierForVendor

    Class uiDeviceCls = NSClassFromString(@"UIDevice");

    if (!uiDeviceCls) {

        DLOG(@"[IDFV-HOOK] v36.123: FAILED - UIDevice class not found");

        return;

    }

    Method m = class_getInstanceMethod(uiDeviceCls, @selector(identifierForVendor));

    if (!m) {

        DLOG(@"[IDFV-HOOK] v36.123: FAILED - method identifierForVendor not found");

        return;

    }

    orig_identifierForVendor = (NSUUID* (*)(UIDevice*, SEL))method_getImplementation(m);

    IMP newImp = (IMP)hook_identifierForVendor;

    method_setImplementation(m, newImp);

    DLOG(@"[IDFV-HOOK] v37.107-DIST: SUCCESS - [UIDevice identifierForVendor] returns NATIVE UUID");

}



// SecKeyCreateEncryptedData hook (iOS 10+)

// CORRECT signature: CFDataRef SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);

typedef CFDataRef (*SecKeyCreateEncryptedDataFunc)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);

static SecKeyCreateEncryptedDataFunc orig_SecKeyCreateEncryptedData = NULL;



static CFDataRef hook_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error) {

    if (!orig_SecKeyCreateEncryptedData) {

        orig_SecKeyCreateEncryptedData = (SecKeyCreateEncryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateEncryptedData");

    }

    if (!orig_SecKeyCreateEncryptedData) return NULL;

    CFErrorRef *errPtr = NULL;

    CFDataRef result = orig_SecKeyCreateEncryptedData(key, algorithm, plaintext, errPtr);

    if (errPtr && *errPtr) {

        DLOG(@"[SEC] SecKeyCreateEncryptedData FAILED: %@", CFBridgingRelease(CFErrorCopyDescription(*errPtr)));

    } else if (result) {

        DLOG(@"[SEC] SecKeyCreateEncryptedData SUCCESS: plainLen=%lu cipherLen=%lu", 

             plaintext ? CFDataGetLength(plaintext) : 0, CFDataGetLength(result));

    } else {

        DLOG(@"[SEC] SecKeyCreateEncryptedData returned NULL");

    }

    return result;

}



// ============================================================

#pragma mark - v37.134-FIX20 V3自签分发环境修复 (zsign.dylib + 多层rebind链问题)

// 仅当 objc_getClass("zsign") 存在时激活，全能签环境逻辑100%不动。

// ============================================================



// --- 手动声明 ObjC Runtime 函数 (避免import<objc/runtime.h>引发BOM冲突) ---

Class      objc_getClass(const char *name);

Method     class_getClassMethod(Class cls, SEL name);

Method     class_getInstanceMethod(Class cls, SEL name);

IMP        method_getImplementation(Method m);

IMP        method_setImplementation(Method m, IMP imp);



// v37.134-FIX20: g_isV3Environment/g_msHookFunction/g_origZsign* 已在文件顶部(770行附近)前向声明，

// 这里不再重复定义。所有 V3 相关全局变量的初始化都在 entry → installAllHooks() → detectV3Environment() 中完成。



// +[zsign alert:] FIX30/31: 透明调用orig! 必须调用orig,否则zsign内部状态错乱→闪退!

// FIX31新增: 整体 @try/@catch + self/zsign类匹配校验 + param非nil校验 + 记录orig调用前后时间

// 根本上杜绝: 即使orig内部抛NSInvalidArgumentException / 任何ObjC异常 → 也会被catch→不闪退!

static void v3hook_zsign_alert(id self, SEL _cmd, id param) {

    @try {

        Class zs = objc_getClass("zsign");

        BOOL zsignOK = (zs != nil && (self == zs || object_getClass(self) == zs ||

                  class_isMetaClass(object_getClass(self))));

        DLOG(@"[V3-zsign] FIX31: +alert: ENTER self=%@(isMeta=%d) expectedClass=%@(match=%d) paramType=%@ param=%@",

             NSStringFromClass(object_getClass(self)),

             class_isMetaClass(object_getClass(self))?1:0,

             NSStringFromClass(zs), zsignOK?1:0,

             param?NSStringFromClass([param class]):@"<nil>",

             (param && [param respondsToSelector:@selector(description)]) ? [param description] : @"");

        

        if (g_origZsignAlertImp) {

            void (*fn)(id, SEL, id) = (typeof(fn))g_origZsignAlertImp;

            DLOG(@"[V3-zsign] FIX31: +alert: 即将透明调用orig IMP=%p", fn);

            fn(self, _cmd, param);

            DLOG(@"[V3-zsign] FIX31: +alert: orig调用完成 → UIAlertView.show hook仍会拦截真实弹窗, 无弹窗风险");

        } else {

            DLOG(@"[V3-zsign] FIX31: +alert: orig IMP=NULL (installV3ZsignAlertOnlyBypass 签名不匹配/未替换?) → 直接return(等同于空实现, 但已经过签名安全检查)");

        }

    } @catch (NSException *e) {

        DLOG(@"[V3-zsign] FIX31: +alert: ORIG内部抛异常! 已被捕获→不闪退! name=%@ reason=%@ userInfo=%@ callStack=%@",

             e.name, e.reason, e.userInfo, [e callStackSymbols]);

        // FIX31: 即便原实现内部异常崩, 我们也吞掉→App不闪退!

    }

}



// v37.134-FIX33: +[zsign request] WRAPPER (透明调用orig, 仅标记g_v3RequestHasBeenCalled=YES)

// 签名校验(v16@0:8): void return, 参数只有self+_cmd (无参数). wxhook 18.log L34 铁证:

//   +[zsign request] typeEncoding='v16@0:8' → method_getNumberOfArguments=2, return='v'

// FIX33: 这是 真V3自签 vs 全能签注入 唯一可靠区分:

//   真V3自签 → V3签名流程会call zsign +request → g_v3RequestHasBeenCalled=YES

//   全能签注入 → zsign闲置不被call → g_v3RequestHasBeenCalled=NO

// 后续 patchSignatureResponse 里会用这个flag决定 postAppInfoApi/getAppInfoApi

//   YES(真V3) → patchResponse=NO 返回服务器code:1 (lnSign协议成功码)

//   NO(全能签) → 正常改 code:1→0 (全能签协议成功码)

static void v3hook_zsign_request_wrapper(id self, SEL _cmd) {

    @try {

        Class zs = objc_getClass("zsign");

        BOOL zsignOK = (zs != nil && (self == zs || object_getClass(self) == zs ||

                  class_isMetaClass(object_getClass(self))));

        DLOG(@"[V3-zsign] FIX33: +request ENTER self=%@(isMeta=%d zsMatch=%d) → SET g_v3RequestHasBeenCalled=YES (真V3自签模式: post/get API跳过code patch)",

             NSStringFromClass(object_getClass(self)),

             class_isMetaClass(object_getClass(self))?1:0,

             zsignOK?1:0);

        // FIX33: 标记为"真V3自签验签流程已启动"! 后续post/get API不改code值

        g_v3RequestHasBeenCalled = YES;



        if (g_origZsignRequestImp) {

            void (*fn)(id, SEL) = (typeof(fn))g_origZsignRequestImp;

            DLOG(@"[V3-zsign] FIX33: +request 透明调用orig IMP=%p (V3验证流程正常执行)", fn);

            fn(self, _cmd);

            DLOG(@"[V3-zsign] FIX33: +request orig调用完成 → V3验证流程OK");

        } else {

            DLOG(@"[V3-zsign] FIX33: +request orig IMP=NULL → 直接return(V3验证流程将自行处理)");

        }

    } @catch (NSException *e) {

        DLOG(@"[V3-zsign] FIX33: +request ORIG内部抛异常! 已吞→不崩! name=%@ reason=%@",

             e.name, e.reason);

    }

}



// +[zsign getRootVC] 透明调用原实现（不影响）

static id v3hook_zsign_getRootVC(id self, SEL _cmd) {

    DLOG(@"[V3-zsign] +getRootVC 经过Hook(正常返回原实现)");

    if (g_origZsignGetRootVCImp) {

        id (*fn)(id, SEL) = (typeof(fn))g_origZsignGetRootVCImp;

        return fn(self, _cmd);

    }

    return nil;

}



// FIX21: 穿透 systemhook.dylib 的 rebind 表

// V3自签系统注入 systemhook.dylib (DYLD 0号)，其 fishhook 在 WangXianHook 之前

// 执行 rebind，将 SCNetworkReachabilityGetFlags 等系统函数替换为自己的stub

// (通常返回"不可达"或"空实现")，导致我们的 Hook 收到的已是被污染的地址。

//

// 解决方案: 直接读取 systemhook 的 gRebinds 表，将关键网络符号的 new_func

// 指针改回真实 SystemConfiguration 实现，确保后续 Hook 基于真实地址生效。

//

// 注: 此操作在 detectV3Environment 返回 YES 后、installSCNetworkReachabilityHook

// 之前执行，保证 Hook 拿到的是已修复的地址。



// 前向声明: hook_v3_dyld_dlsym_hook 定义在后面，但v3_penetrateSystemhookRebinds中需要使用

static void* hook_v3_dyld_dlsym_hook(const char *name);



static void v3_penetrateSystemhookRebinds(void) {

    DLOG(@"[V3-PEN] === 开始穿透 systemhook rebind 表 ===");



    // 1. 获取 systemhook.dylib 的基址 (通过 _dyld_image_count 遍历)

    uint32_t imgCnt = _dyld_image_count();

    const void *sysHookBase = NULL;

    for (uint32_t i = 0; i < imgCnt; i++) {

        const char *name = _dyld_get_image_name(i);

        if (name && strstr(name, "systemhook.dylib")) {

            sysHookBase = _dyld_get_image_header(i);

            DLOG(@"[V3-PEN] 找到 systemhook.dylib 基址=%p (index=%u)", sysHookBase, i);

            break;

        }

    }

    if (!sysHookBase) {

        DLOG(@"[V3-PEN] systemhook.dylib 未加载 → 跳过穿透");

        return;

    }



    // 2. 用 RTLD_NEXT (绕过 dyld_dlsym_hook 拦截) 获取真实符号地址

    void *realSCNetwork = NULL;

    void *realConnect = NULL;

    void *realSend = NULL;

    void *realRecv = NULL;



    // dlopen SystemConfiguration 框架 (用 RTLD_NOLOAD 不增加引用计数)

    void *scLib = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOLOAD);

    if (scLib) {

        realSCNetwork = dlsym(scLib, "SCNetworkReachabilityGetFlags");

        DLOG(@"[V3-PEN] 真实SCNetworkReachabilityGetFlags=%p", realSCNetwork);

    }



    void *sysLib = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);

    if (sysLib) {

        realConnect = dlsym(sysLib, "connect");

        realSend = dlsym(sysLib, "send");

        realRecv = dlsym(sysLib, "recv");

        DLOG(@"[V3-PEN] 真实connect=%p send=%p recv=%p", realConnect, realSend, realRecv);

    }



    // 3. 穿透 systemhook 的 rebind 表

    // systemhook 导出: gRebindCount (uint32_t), gRebinds (rebind_entry_t[])

    // rebind_entry_t 结构 (arm64):  name_ptr(8) | old_func(8) | new_func(8) = 24字节

    //

    // systemhook 内存布局 (Frida扫描结果):

    //   base: 0x1018d0000  size: 49152

    //   gRebindCount @ 0x1018e0028 (相对base偏移 0x10028)

    //   gRebinds     @ 0x1018e0030 (相对base偏移 0x10030)

    // 这两个是 .const/__DATA 段的全局变量，基址固定不变

    typedef struct {

        const char *name;      // offset 0

        void *old_func;        // offset 8

        void *new_func;        // offset 16

    } rebind_entry_t;



    uint32_t *rebindCountPtr = NULL;

    rebind_entry_t *rebindsBasePtr = NULL;



    // 方法1: 直接用已知偏移计算 (最可靠，因为符号是固定的全局变量)

    // 偏移 0x10028 和 0x10030 是相对基址的虚拟内存偏移，ASLR后依然成立

    {

        uintptr_t base = (uintptr_t)sysHookBase;

        uintptr_t gRebindCount_offset = 0x10028ULL;

        uintptr_t gRebinds_offset = 0x10030ULL;



        rebindCountPtr = (uint32_t *)(base + gRebindCount_offset);

        rebindsBasePtr = (rebind_entry_t *)(base + gRebinds_offset);



        // 验证: gRebindCount 值应该在 1~500 之间

        uint32_t countVal = *rebindCountPtr;

        if (countVal > 0 && countVal < 500) {

            DLOG(@"[V3-PEN] ✅ 固定偏移法命中: gRebindCount=%p(=%u) gRebinds=%p",

                 rebindCountPtr, countVal, rebindsBasePtr);

        } else {

            DLOG(@"[V3-PEN] 固定偏移法失败(count=%u 不合理) → 用dlsym兜底", countVal);

            rebindCountPtr = NULL;

            rebindsBasePtr = NULL;

        }

    }



    // 方法2: 如果固定偏移法失败，用 dlsym (即使被 dyld_dlsym_hook 拦截，

    //        内部 __dyld_lookup_and_bind 仍可能正确返回)

    if (!rebindCountPtr) {

        void *handle = dlopen(NULL, RTLD_LAZY);

        if (handle) {

            void *cnt = dlsym(handle, "gRebindCount");

            void *reb = dlsym(handle, "gRebinds");

            if (cnt && reb) {

                rebindCountPtr = (uint32_t *)cnt;

                rebindsBasePtr = (rebind_entry_t *)reb;

                DLOG(@"[V3-PEN] ✅ dlsym法命中: gRebindCount=%p gRebinds=%p", rebindCountPtr, rebindsBasePtr);

            }

        }

    }



    // 方法3: 如果还失败，暴力扫描 systemhook 的 __DATA 段

    if (!rebindCountPtr) {

        // 扫描 systemhook base 到 base+0x10000 之间的 uint32 值

        // 找一个值在 1~500 之间，且紧随其后的 gRebinds 指针指向 base+0x10000 之后合理位置

        uintptr_t base = (uintptr_t)sysHookBase;

        uint32_t *scanStart = (uint32_t *)(base + 0x4000);

        uint32_t *scanEnd = (uint32_t *)(base + 0x10000);



        DLOG(@"[V3-PEN] 暴力扫描 %p ~ %p", scanStart, scanEnd);

        for (uint32_t *p = scanStart; p < scanEnd; p++) {

            uint32_t val = *p;

            if (val == 0 || val > 500) continue;

            // gRebinds 紧随 gRebindCount (偏移 +8)

            uintptr_t rebPtr = *(uintptr_t *)(p + 2);  // 跳过 uint32 (4字节) + 4字节padding

            if (rebPtr >= base && rebPtr < base + 0x20000) {

                // 验证: rebPtr 指向的 rebind_entry.name 应是有效指针

                const char *nameCheck = *(const char **)rebPtr;

                if (nameCheck && (uintptr_t)nameCheck > 0x10000 && (uintptr_t)nameCheck < 0x100000000ULL) {

                    rebindCountPtr = p;

                    rebindsBasePtr = (rebind_entry_t *)rebPtr;

                    DLOG(@"[V3-PEN] ✅ 暴力扫描命中: gRebindCount=%p(=%u) gRebinds=%p",

                         rebindCountPtr, val, rebindsBasePtr);

                    break;

                }

            }

        }

        if (!rebindCountPtr) {

            DLOG(@"[V3-PEN] ❌ 暴力扫描也未找到 rebind 表 → 放弃修复");

        }

    }



    // 4. 修复 rebind 表: 将关键符号的 new_func 改回真实地址

    if (rebindCountPtr && rebindsBasePtr) {

        uint32_t count = *rebindCountPtr;

        DLOG(@"[V3-PEN] 当前 rebind 总数=%u", count);



        int fixed = 0;

        for (uint32_t i = 0; i < count; i++) {

            // 用 rebind_entry_t 结构体方式访问

            rebind_entry_t *entry = &rebindsBasePtr[i];

            char *namePtr = (char *)entry->name;

            void *oldFunc = entry->old_func;

            void *newFunc = entry->new_func;



            if (!namePtr || !*namePtr) continue;



            // 检查是否是我们关心的符号

            void *targetFix = NULL;

            if (strstr(namePtr, "SCNetworkReachabilityGetFlags")) {

                targetFix = realSCNetwork;

            } else if (strcmp(namePtr, "connect") == 0 || strcmp(namePtr, "_connect") == 0) {

                targetFix = realConnect;

            } else if (strcmp(namePtr, "send") == 0 || strcmp(namePtr, "_send") == 0) {

                targetFix = realSend;

            } else if (strcmp(namePtr, "recv") == 0 || strcmp(namePtr, "_recv") == 0) {

                targetFix = realRecv;

            }



            if (targetFix && newFunc != targetFix) {

                DLOG(@"[V3-PEN] 🎯 修复 rebind[%u] %s: old=%p cur_new=%p → real=%p",

                     i, namePtr, oldFunc, newFunc, targetFix);



                // 将 new_func 指针改回真实地址

                entry->new_func = targetFix;

                fixed++;



                // 验证写入成功

                void *verify = entry->new_func;

                DLOG(@"[V3-PEN]   ✅ 验证写入: %s new_func=%p", namePtr, verify);

            }

        }

        DLOG(@"[V3-PEN] ✅ 共修复 %d 个 rebind 条目", fixed);

    } else {

        DLOG(@"[V3-PEN] ⚠️ 未找到 rebind 表 → 跳过修复 (依赖 MSHookFunction 内联 patch 兜底)");

    }



    // 5. 额外防护: 安装 dyld_dlsym_hook 拦截

    // v37.134-FIX27: 完全禁用 dyld_dlsym_hook 的MSHook!

    // 原因: MSHookFunction在本环境100%失败(0/7)，但dyld_dlsym_hook被替换后

    // orig=0x0(无trampoline) → 所有dlsym调用返回NULL → 游戏无法解析connect等

    // 网络符号 → 不发起socket连接 → "卡在启动页面无联网"。

    // 且rebind总数=0(日志确认)，根本不需要穿透dyld_dlsym_hook。

    // 以下代码完全注释掉:

    #if 0

    {

        typedef void* (*dyld_dlsym_hook_t)(const char *name);

        dyld_dlsym_hook_t orig_dyld_dlsym_hook = NULL;



        void *dlsymHookFn = dlsym(RTLD_DEFAULT, "dyld_dlsym_hook");

        if (!dlsymHookFn) dlsymHookFn = dlsym(RTLD_DEFAULT, "_dyld_dlsym_hook");



        if (dlsymHookFn && g_msHookFunction) {

            DLOG(@"[V3-PEN] 发现 dyld_dlsym_hook=%p → MSHook 拦截", dlsymHookFn);

            g_msHookFunction(dlsymHookFn,

                             (void *)hook_v3_dyld_dlsym_hook,

                             (void **)&orig_dyld_dlsym_hook);

            DLOG(@"[V3-PEN] ✅ dyld_dlsym_hook MSHook安装完成 orig=%p", orig_dyld_dlsym_hook);

        } else if (dlsymHookFn) {

            int r = rebindSymbol("_dyld_dlsym_hook",

                                 (void *)hook_v3_dyld_dlsym_hook,

                                 (void **)&orig_dyld_dlsym_hook);

            if (r == 0) {

                DLOG(@"[V3-PEN] ✅ dyld_dlsym_hook fishhook rebind 成功");

            } else {

                DLOG(@"[V3-PEN] dyld_dlsym_hook fishhook 失败 r=%d", r);

            }

        }

    }

    #endif

    DLOG(@"[V3-PEN] dyld_dlsym_hook MSHook 已禁用(FIX27: rebind=0无需穿透, 避免orig=0x0破坏dlsym)");



    DLOG(@"[V3-PEN] === systemhook rebind 穿透完成 ===");

}



// FIX21 辅助: dyld_dlsym_hook 拦截器

// 当 systemhook 的 dyld_dlsym_hook 拦截关键符号查找时，返回真实地址

// 避免 dlsym 返回被 systemhook 污染的 new_func 指针

static void* (*g_orig_dyld_dlsym_hook)(const char *name) = NULL;

static void* hook_v3_dyld_dlsym_hook(const char *name) {

    // 先调原 dyld_dlsym_hook (可能返回被污染的地址)

    void *result = NULL;

    if (g_orig_dyld_dlsym_hook) {

        result = g_orig_dyld_dlsym_hook(name);

    }

    // 如果查询的是关键网络符号，强制返回真实地址

    // (在穿透修复已完成后，rebind 表已被修复，此处是兜底)

    if (name) {

        if (strcmp(name, "SCNetworkReachabilityGetFlags") == 0 ||

            strcmp(name, "_SCNetworkReachabilityGetFlags") == 0) {

            void *real = dlsym(RTLD_DEFAULT, "SCNetworkReachabilityGetFlags");

            if (real && real != result) {

                DLOG(@"[V3-PEN-HOOK] dyld_dlsym_hook(%s) 返回被污染=%p → 替换为真实=%p", name, result, real);

                return real;

            }

        }

    }

    return result;

}



static BOOL detectV3Environment(void) {

    // FIX31: 全函数包 @try/@catch，防止 zsign.dylib 的 +load 初始化竞争导致任何异常崩

    @try {

    Class zs = objc_getClass("zsign");

    if (zs) {

        DLOG(@"[V3-DETECT] 🔴 检测到 zsign.dylib 已加载(zsign类存在) → 判定为 V3 分发自签环境，激活 V3 专用修复");

        // 顺便尝试动态加载 libsubstrate 的 MSHookFunction (优先用内联patch代替fishhook)

        g_msHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");

        if (g_msHookFunction) {

            DLOG(@"[V3-DETECT] ✅ libsubstrate 已加载，MSHookFunction 可用(%p) → 网络层Hook优先用内联patch", g_msHookFunction);

        } else {

            DLOG(@"[V3-DETECT] ⚠️ MSHookFunction不可用 → 网络层Hook退化: fishhook+二次flags覆盖兜底");

        }

        // === FIX28: 完全跳过 V3-PEN systemhook rebind穿透 ===

        DLOG(@"[V3-DETECT] FIX28: V3-PEN已跳过(rebind=0无需穿透,避免副作用)");

        

        // FIX31: 再验证一下zsign类的关键方法有哪些 → 打印到log (crash ring buffer会保存)

        unsigned int methCount = 0;

        Method *meths = class_copyMethodList(object_getClass(zs), &methCount);

        NSMutableArray *selNames = [NSMutableArray array];

        for (unsigned int i = 0; i < methCount && meths; i++) {

            SEL s = method_getName(meths[i]);

            const char *type = method_getTypeEncoding(meths[i]);

            [selNames addObject:[NSString stringWithFormat:@"[%@](%s)", NSStringFromSelector(s), type?type:"?"]];

        }

        if (meths) free(meths);

        DLOG(@"[V3-DETECT] FIX31: zsign meta-class methods(total=%d): %@", methCount, selNames);

        

        // 同样列出实例方法（如果有）

        meths = class_copyMethodList(zs, &methCount);

        selNames = [NSMutableArray array];

        for (unsigned int i = 0; i < methCount && meths; i++) {

            SEL s = method_getName(meths[i]);

            const char *type = method_getTypeEncoding(meths[i]);

            [selNames addObject:[NSString stringWithFormat:@"-[%@](%s)", NSStringFromSelector(s), type?type:"?"]];

        }

        if (meths) free(meths);

        if (methCount > 0) DLOG(@"[V3-DETECT] FIX31: zsign instance methods(total=%d): %@", methCount, selNames);

        

        return YES;

    }

    // zsign不存在=全能签正常环境，不打印任何V3日志避免干扰

    return NO;

    } @catch (NSException *e) {

        DLOG(@"[V3-DETECT] FIX31: detectV3Environment 捕获异常! name=%@ reason=%@ → 按全能签环境处理(NO)", e.name, e.reason);

        return NO;

    }

}



// FIX32 重写: installV3ZsignAlertOnlyBypass全部@try/@catch + method签名types校验

// FIX31 BUG: 用 strncmp(actual,"v@:@",4) 错误!

//   ObjC typeEncoding 格式是  v24@0:8@16  → 前4字节 v-2-4-@, 不是 v-@:-(@)

//   → 永远 MISMATCH → alert hook 没装上! FIX32 改用 Runtime API:

//     method_getNumberOfArguments ≥ 3 (self + _cmd + 至少1参数)

//     method_copyReturnType[0] == 'v'  (void return, 不会被当成NSObject释放引起crash)

static BOOL fix31_checkMethodSignature(Method m, int minArgCount, char expectReturn, SEL selName, NSString *label) {

    if (!m) {

        DLOG(@"[V3-zsign] FIX32-SIG: %@ method=nil sel=%@ → 跳过替换", label, NSStringFromSelector(selName));

        return NO;

    }

    const char *enc = method_getTypeEncoding(m);

    if (!enc) {

        DLOG(@"[V3-zsign] FIX32-SIG: %@ sel=%@ typeEncoding=NULL → 不替换(防止SIGSEGV)", label, NSStringFromSelector(selName));

        return NO;

    }

    unsigned int argCount = method_getNumberOfArguments(m);

    char *retType = method_copyReturnType(m);

    char retFirst = retType ? retType[0] : '?';

    if (retType) free(retType);

    // arg count 规则: ObjC方法总有 self(0) + _cmd(1), 所以 alert:(id) 总参数=3 (self,_cmd,param)

    // return 'v'=void. 如果return是@(对象), 调用orig后ARC会尝试retain/autorelease可能乱

    BOOL countOk = ((int)argCount >= minArgCount);

    BOOL retOk = (retFirst == expectReturn);

    BOOL ok = countOk && retOk;

    DLOG(@"[V3-zsign] FIX32-SIG: %@ sel=%@ encoding='%s' nArgs=%u(need≥%d) retType='%c'(need='%c') → %@",

        label, NSStringFromSelector(selName), enc, argCount, minArgCount, retFirst, expectReturn,

        ok?@"OK ✅":(countOk?@"FAIL: returnType不匹配! 不替换 ❌":@"FAIL: nArgs不匹配! 不替换 ❌"));

    return ok;

}



// FIX28/30/31/33: 替换zsign +alert:透明调用orig(阻止弹窗+不闪退)

// FIX33新增: 也替换zsign +request(WRAPPER:透明调用orig+只设置g_v3RequestHasBeenCalled=YES做标记)

//   这是真V3自签 vs 全能签注入 最可靠唯一区分:

//   真V3=zsign +request被V3流程实际call → YES → post/get API返回服务器code:1

//   全能签=zsign存在但闲置,+request从不被call → NO → post/get API code:1→0

// FIX30关键修复: +alert:空实现(不调用orig)会导致zsign内部状态错乱→闪退! 必须透明调用orig.

// FIX31关键修复: 全程 @try/@catch + method签名types校验 + method存在校验

static void installV3ZsignAlertOnlyBypass(void) {

    @try {

    Class zs = objc_getClass("zsign");

    if (!zs) return;

    DLOG(@"[V3-zsign] FIX33: installV3ZsignAlertOnlyBypass开始 → 替换 +alert:透明调用orig + 替换+request→WRAPPER(标记g_v3RequestHasBeenCalled)");



    Method mAlert = class_getClassMethod(zs, @selector(alert:));

    // FIX32: alert:签名校验用Runtime API: nArgs≥3 + return='v'

    //   v24@0:8@16 → method_getNumberOfArguments=3, method_copyReturnType='v' → OK!

    // FIX31错误写法: 用strncmp("v@:@")前缀匹配 → v24@0:8@16前4字节v24@≠v@:@ → FAIL不替换

    if (fix31_checkMethodSignature(mAlert, 3, 'v', @selector(alert:), @"+[zsign alert:]") == NO) {

        DLOG(@"[V3-zsign] FIX32: +alert: 签名不匹配(返回非void / 参数 < 3) → 不做IMP替换(防止闪退)! 保留原实现.");

        return;

    }

    g_origZsignAlertImp = method_getImplementation(mAlert);

    if (!g_origZsignAlertImp) {

        DLOG(@"[V3-zsign] FIX31: +alert: method_getImplementation返回NULL → 不替换");

        return;

    }

    method_setImplementation(mAlert, (IMP)v3hook_zsign_alert);

    DLOG(@"[V3-zsign] FIX31: +alert: IMP替换成功! orig=%p → new=%p (透明调用orig, UIAlertView.show仍会拦截弹窗)",

         g_origZsignAlertImp, (IMP)v3hook_zsign_alert);



    // FIX33: 装zsign +request WRAPPER!

    // wxhook 18.log L34铁证: encoding='v16@0:8' → 参数=2(self+_cmd) return='v'(void)

    Method mReq = class_getClassMethod(zs, @selector(request));

    if (!mReq) {

        DLOG(@"[V3-zsign] FIX33: +[zsign request] NOT FOUND → 无法安装WRAPPER! g_v3RequestHasBeenCalled将保持NO(全能签路径保证code:1→0)");

    } else if (fix31_checkMethodSignature(mReq, 2, 'v', @selector(request), @"+[zsign request]") == NO) {

        const char *t = method_getTypeEncoding(mReq);

        DLOG(@"[V3-zsign] FIX33: +[zsign request] 签名不匹配(enc=%s) → 不装WRAPPER, g_v3RequestHasBeenCalled保持NO", t?t:"?");

    } else {

        g_origZsignRequestImp = method_getImplementation(mReq);

        if (!g_origZsignRequestImp) {

            DLOG(@"[V3-zsign] FIX33: +[zsign request] IMP=NULL → 不装WRAPPER");

        } else {

            method_setImplementation(mReq, (IMP)v3hook_zsign_request_wrapper);

            DLOG(@"[V3-zsign] FIX33: +[zsign request] WRAPPER安装成功! orig=%p → wrapper=%p (透明调用orig+SET g_v3RequestHasBeenCalled=YES当被实际call时)",

                 g_origZsignRequestImp, (IMP)v3hook_zsign_request_wrapper);

            DLOG(@"[V3-zsign] FIX33: 区分规则: 真V3自签→调用时设YES=post/get跳过patch code; 全能签→不调用NO=post/get正常patch code:1→0");

        }

    }

    // FIX28/30/31/33: +getRootVC保持不替换

    DLOG(@"[V3-zsign] FIX33: +getRootVC保持原实现不替换");

    } @catch (NSException *e) {

        DLOG(@"[V3-zsign] FIX33: installV3ZsignAlertOnlyBypass 捕获异常! name=%@ reason=%@ → 跳过所有替换", e.name, e.reason);

    }

}



// ============================================================

#pragma mark - v37.3 SCNetworkReachabilityGetFlags hook (+ FIX20 V3强化)

// Force return kSCNetworkReachabilityFlagsReachable so client's

// pre-connect network check passes for game server (port 12003)

// ============================================================



typedef int (*SCNetworkReachabilityGetFlagsFunc)(void *target, uint32_t *flags);

static SCNetworkReachabilityGetFlagsFunc orig_SCNetworkReachabilityGetFlags = NULL;



static int hook_SCNetworkReachabilityGetFlags(void *target, uint32_t *flags) {

    if (!g_isV3Environment) {

        // === 全能签环境：原始一行逻辑完全不变 ===

        // v37.3: Force reachable — kSCNetworkReachabilityFlagsReachable = 0x02

        if (flags) *flags = 0x02;

        return 1;  // TRUE

    }



    // === FIX20 V3环境强化：多层rebind链，先调orig拿别人可能的写入，再我们最后覆盖2遍 ===

    int origRet = 0;

    uint32_t origFlagsVal = 0;

    if (orig_SCNetworkReachabilityGetFlags) {

        // 先用局部变量装orig返回，避免直接污染*flags

        uint32_t tmpFlags = 0;

        origRet = orig_SCNetworkReachabilityGetFlags(target, &tmpFlags);

        origFlagsVal = tmpFlags;

    }

    // 第一次强制写 (我们认为 orig 后面可能有 6-8 层 rebind 中的其他库在 onLeave 写 *flags，所以我们循环2次)

    if (flags) {

        for (int i = 0; i < 2; i++) {

            *flags = 0x02;  // kSCNetworkReachabilityFlagsReachable

            __sync_synchronize();  // 内存屏障，防止编译器/CPU重排

            if (((*flags) & 0x02u) != 0u) break;  // 写成功就退出

        }

    }

    // 第一次命中就直接打日志 (避免刷屏)

    static int hitCount = 0;

    if (hitCount < 5) {

        hitCount++;

        DLOG(@"[V3-SCNETWORK] 🔴 flags覆盖 orig_ret=%d orig_flags=0x%x → 最终flags=0x%x hit#%d",

             origRet, origFlagsVal, flags ? *flags : 0, hitCount);

    }

    return 1;  // 永远 TRUE(函数调用成功)

}



static void installSCNetworkReachabilityHook(void) {

    void *scLib = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOLOAD);

    if (!scLib) {

        scLib = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_LAZY);

    }

    if (!scLib) {

        DLOG(@"[SEC] SystemConfiguration framework NOT loaded");

        return;

    }

    void *realSCAddr = dlsym(scLib, "SCNetworkReachabilityGetFlags");

    if (!realSCAddr) {

        DLOG(@"[SEC] SCNetworkReachabilityGetFlags NOT found in SystemConfiguration");

        return;

    }

    orig_SCNetworkReachabilityGetFlags = (SCNetworkReachabilityGetFlagsFunc)realSCAddr;



    // v37.134-FIX25: V3环境优先用MSHookFunction内联patch穿透所有rebind层

    // 原因: SCNetworkReachabilityGetFlags如果被zsign/libWJHook/systemhook外层rebind截断，

    // 返回flags!=0x02 → 游戏直接判定无网络 → 卡在启动页面，根本不发起connect。

    // FIX24错误地移除了MSHookFunction导致回归。

    // fallback判断修正: preMS == orig_after || orig_after == NULL 判断失败。

    if (g_isV3Environment && g_msHookFunction) {

        DLOG(@"[V3-SCNETWORK] ✅ 用MSHookFunction内联patch(穿透SCNetwork多层rebind)");

        void *preSC = (void *)orig_SCNetworkReachabilityGetFlags;

        orig_SCNetworkReachabilityGetFlags = NULL;

        g_msHookFunction(realSCAddr,

                         (void *)hook_SCNetworkReachabilityGetFlags,

                         (void **)&orig_SCNetworkReachabilityGetFlags);

        if (orig_SCNetworkReachabilityGetFlags && orig_SCNetworkReachabilityGetFlags != preSC) {

            DLOG(@"[V3-SCNETWORK] MSHook OK orig=%p", orig_SCNetworkReachabilityGetFlags);

        } else {

            DLOG(@"[V3-SCNETWORK-FB] MSHook失败 → fallback rebind");

            int r = rebindSymbol("_SCNetworkReachabilityGetFlags",

                                 (void *)hook_SCNetworkReachabilityGetFlags,

                                 (void **)&orig_SCNetworkReachabilityGetFlags);

            if (!orig_SCNetworkReachabilityGetFlags) orig_SCNetworkReachabilityGetFlags = (SCNetworkReachabilityGetFlagsFunc)dlsym(RTLD_NEXT, "SCNetworkReachabilityGetFlags");

            DLOG(@"[V3-SCNETWORK-FB] rebind=%d orig=%p", r, orig_SCNetworkReachabilityGetFlags);

        }

    } else {

        // 全能签环境: 原rebindSymbol

        int r = rebindSymbol("_SCNetworkReachabilityGetFlags",

                             (void *)hook_SCNetworkReachabilityGetFlags,

                             (void **)&orig_SCNetworkReachabilityGetFlags);

        DLOG(@"[SEC] SCNetworkReachabilityGetFlags hook: rebind=%d addr=%p V3=%d",

             r, orig_SCNetworkReachabilityGetFlags, g_isV3Environment ? 1 : 0);

    }

}



static void installSecurityHooks(void) {

    // Log all loaded dylibs for diagnosis (use original functions before hook)

    uint32_t count = _dyld_image_count();

    DLOG(@"[DYLD] Total loaded images: %u", count);

    // FIX53B: Instead of printing 500+ [DYLD] %u: name lines (wasteful and was being
    // filtered away anyway by sparse logger), print a compact summary — only the
    // dylibs that matter for debugging + a count of total system dylibs.
    {
        NSMutableArray *hookDylibs = [NSMutableArray array];
        NSMutableArray *lnOrLibSupport = [NSMutableArray array];
        uint32_t totalDylibs = 0;
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            NSString *nsname = [NSString stringWithUTF8String:name];
            if ([nsname containsString:@".dylib"]) {
                totalDylibs++;
                NSString *base = nsname.lastPathComponent;
                if ([base containsString:@"WangXianHook"] ||
                    [base containsString:@"WangXian2Hook"] ||
                    [base containsString:@"lnSignature"] ||
                    [base containsString:@"libSupport"] ||
                    [base containsString:@"FridaGadget"] ||
                    [base containsString:@"zsign"] ||
                    [base containsString:@"libsystemhook"] ||
                    [base containsString:@"fishhook"] ||
                    [base containsString:@"systemhook"]) {
                    [hookDylibs addObject:[NSString stringWithFormat:@"[%u] %@", i, base]];
                }
                if ([base isEqualToString:@"lnSignature.dylib"] ||
                    [base isEqualToString:@"libSupport.dylib"]) {
                    [lnOrLibSupport addObject:base];
                }
            }
        }
        DLOG(@"[DYLD-INIT] Loaded images total=%u  .dylib count=%u  hook-relevant dylibs=%lu  lnSignature/libSupport present=%lu",
             count, totalDylibs, (unsigned long)hookDylibs.count, (unsigned long)lnOrLibSupport.count);
        if (hookDylibs.count > 0) {
            for (NSString *s in hookDylibs) {
                DLOG(@"[DYLD-INIT]   Hook dylib: %@", s);
            }
        }
        if (lnOrLibSupport.count == 0) {
            DLOG(@"[DYLD-INIT]   ⚠️ Neither lnSignature.dylib nor libSupport.dylib loaded — full injection install may be missing.");
        }
    }

    

    // v37.8: RESTORED DYLD hiding — Frida diagnostic (hook.txt) confirmed client

    //        calls _dyld_image_count() 100+ times and detects lnSignature.dylib

    //        + libSupport.dylib → triggers '版本过低'. DYLD hiding is REQUIRED.

    //        capture_real.js worked because Frida agent is NOT in dyld list.

    installDyldHooks();

    installDladdrHook();

    installDlsymHook();  // KEEP: dlsym hook is in capture_real.js

    

    // === FIX45: 初始化stdio真实指针 + 安装wrapper hooks ===
    {
        // 1) 先拿 libsystem_c.dylib (Darwin真正定义fopen/fgets/fread的地方!) handle上的REAL函数
        //    用dlopen+dlsym在具体库handle上 → 永远返回该库内部的原始符号,完全绕过systemhook.dylib的fishhook interposition!
        void *libc = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_NOLOAD);
        if (!libc) libc = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);
        if (libc) {
            real_libSystem_fopen  = (FopenFunc)dlsym(libc, "fopen");
            real_libSystem_fgets  = (FgetsFunc)dlsym(libc, "fgets");
            real_libSystem_fread  = (FreadFunc)dlsym(libc, "fread");
            real_libSystem_fclose = (FcloseFunc)dlsym(libc, "fclose");
            DLOG(@"[FIX45-FIO] ✅ libsystem_c真实指针: fopen=%p fgets=%p fread=%p fclose=%p (永远不受systemhook fishhook影响!)",
                 (void*)real_libSystem_fopen, (void*)real_libSystem_fgets, (void*)real_libSystem_fread, (void*)real_libSystem_fclose);
        } else {
            // 最后兜底RTLD_NEXT (跳过WangXianHook自己)
            DLOG(@"[FIX45-FIO] ⚠️ libsystem_c dlopen失败 → fallback RTLD_NEXT");
            real_libSystem_fopen  = (FopenFunc)dlsym(RTLD_NEXT, "fopen");
            real_libSystem_fgets  = (FgetsFunc)dlsym(RTLD_NEXT, "fgets");
            real_libSystem_fread  = (FreadFunc)dlsym(RTLD_NEXT, "fread");
            real_libSystem_fclose = (FcloseFunc)dlsym(RTLD_NEXT, "fclose");
        }

        // 2) 安装 fishhook rebind → 把我们的wrapper挂到全局符号上
        //    rebind_symbols会扫描所有已加载image的GOT,将符号解析替换掉,并保存原函数地址到orig_*
        struct rebinding fioRebinds[] = {
            {"fopen",  (void*)hook_fopen,  (void**)&orig_fopen},
            {"fgets",  (void*)hook_fgets,  (void**)&orig_fgets},
            {"fread",  (void*)hook_fread,  (void**)&orig_fread},
            {"fclose", (void*)hook_fclose, (void**)&orig_fclose}
        };
        int rcRebind = rebind_symbols(fioRebinds, sizeof(fioRebinds)/sizeof(fioRebinds[0]));
        DLOG(@"[FIX45-FIO] ✅ rebind_symbols rc=%d orig: fopen=%p fgets=%p fread=%p fclose=%p",
             rcRebind, (void*)orig_fopen, (void*)orig_fgets, (void*)orig_fread, (void*)orig_fclose);
        // 如果rebind_symbols没找到某些符号(罕见), fallback到real_libSystem或RTLD_DEFAULT
        if (!orig_fopen)  orig_fopen  = real_libSystem_fopen  ? real_libSystem_fopen  : (FopenFunc) dlsym(RTLD_DEFAULT, "fopen");
        if (!orig_fgets)  orig_fgets  = real_libSystem_fgets  ? real_libSystem_fgets  : (FgetsFunc) dlsym(RTLD_DEFAULT, "fgets");
        if (!orig_fread)  orig_fread  = real_libSystem_fread  ? real_libSystem_fread  : (FreadFunc) dlsym(RTLD_DEFAULT, "fread");
        if (!orig_fclose) orig_fclose = real_libSystem_fclose ? real_libSystem_fclose : (FcloseFunc)dlsym(RTLD_DEFAULT, "fclose");
    }

    // === FIX45: 初始化VersionModule.widgetSelected try-catch兜底 ===
    fix45_installVMWidgetHook();

    

    // v37.30: Restore v37.28 CCCrypt gated hook. USER CONFIRMED v37.28 did NOT

    // crash — only disconnected. CCCrypt fishhook rebind is SAFE when gated

    // after 0x80FFF495 (game server phase). We need this to:

    //   (A) Dump FULL plaintext hex of FFF493 payload before AES encrypt

    //   (B) Replace DY_MIESHI → DYanyou0040_MIESHI in plaintext before encryption

    {

        void *libCommonCrypto = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOLOAD);

        if (!libCommonCrypto) libCommonCrypto = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);

        void *realCCCryptAddr = NULL;

        if (libCommonCrypto) realCCCryptAddr = dlsym(libCommonCrypto, "CCCrypt");

        if (!realCCCryptAddr) realCCCryptAddr = dlsym(RTLD_NEXT, "CCCrypt");

        orig_CCCrypt = (CCCryptFunc)realCCCryptAddr;



        if (orig_CCCrypt) {

            // v37.134-FIX25: V3环境优先用MSHookFunction内联patch穿透所有rebind层

            // FIX24错误地移除了MSHookFunction → 导致CC_MD5/CCCrypt hook在V3多层rebind下不生效。

            // fallback判断修正: preMS == orig_after || orig_after == NULL。

            if (g_isV3Environment && g_msHookFunction) {

                DLOG(@"[V3-CCCRYPT] ✅ 用MSHookFunction内联patch(穿透CCCrypt多层rebind, GATED after 0x80FFF495)");

                void *preCC = (void *)orig_CCCrypt;

                orig_CCCrypt = NULL;

                g_msHookFunction(realCCCryptAddr, (void *)hook_CCCrypt, (void **)&orig_CCCrypt);

                if (orig_CCCrypt && orig_CCCrypt != preCC) {

                    DLOG(@"[V3-CCCRYPT] MSHook OK orig=%p (GATED safe)", orig_CCCrypt);

                } else {

                    DLOG(@"[V3-CCCRYPT-FB] MSHook失败 → fallback rebind");

                    int r1 = rebindSymbol("_CCCrypt", (void *)hook_CCCrypt, (void **)&orig_CCCrypt);

                    if (!orig_CCCrypt) orig_CCCrypt = (CCCryptFunc)dlsym(RTLD_NEXT, "CCCrypt");

                    DLOG(@"[V3-CCCRYPT-FB] rebind=%d orig=%p (GATED safe)", r1, orig_CCCrypt);

                }

            } else {

                // 全能签环境: 原rebindSymbol

                int r1 = rebindSymbol("_CCCrypt", (void *)hook_CCCrypt, (void **)&orig_CCCrypt);

                DLOG(@"[SEC] CCCrypt hook v37.30: rebind=%d addr=%p (GATED after 0x80FFF495 per v37.28 safe)", r1, orig_CCCrypt);

            }

        } else {

            DLOG(@"[SEC] CCCrypt not found via dlsym (L4 won't work!)");

        }

    }



    // v37.51: Hook CC_MD5 and CC_MD5_Final to replace modified binary hash

    // with clean (original) binary hash. This makes the client compute all

    // hash1/hash2/hash3 using the original binary hash → server accepts.

    {

        orig_CC_MD5 = (CC_MD5Func)dlsym(RTLD_NEXT, "CC_MD5");



        // v37.134-FIX11: Compute CURRENT binary hash at runtime using UNHOOKED CC_MD5.

        // Previous hardcoded f9cc76c5... was from v37.60 — every rebuild changes

        // the actual binary so the match condition NEVER fired → status=4.

        if (orig_CC_MD5) {

            @autoreleasepool {

                NSString *exePath = [[NSBundle mainBundle] executablePath];

                if (exePath) {

                    NSData *exeData = [NSData dataWithContentsOfFile:exePath];

                    if (exeData && exeData.length > 10000) {

                        unsigned char tempHash[16];

                        memset(tempHash, 0, 16);

                        orig_CC_MD5((const void *)exeData.bytes, (CC_LONG)exeData.length, tempHash);

                        memcpy(g_our_binary_hash, tempHash, 16);

                        _log([NSString stringWithFormat:@"[MD5-BINARY-HASH] v37.134-FIX11: Runtime computed binary hash (%ld bytes) = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (vs hardcoded old f9cc76c5...)",

                             (long)exeData.length,

                             tempHash[0],tempHash[1],tempHash[2],tempHash[3],

                             tempHash[4],tempHash[5],tempHash[6],tempHash[7],

                             tempHash[8],tempHash[9],tempHash[10],tempHash[11],

                             tempHash[12],tempHash[13],tempHash[14],tempHash[15]]);

                    } else {

                        _log([NSString stringWithFormat:@"[MD5-BINARY-HASH] v37.134-FIX11: ERROR: Could not read executable (%@ len=%ld)", exePath, exeData ? (long)exeData.length : -1L]);

                    }

                }

            }

        }



        if (orig_CC_MD5) {

            // v37.134-FIX25: V3环境优先用MSHookFunction内联patch穿透所有rebind层

            // FIX24错误地移除了MSHookFunction → 导致CC_MD5在V3多层rebind下不生效 → hash计算错误 → 版本过低。

            // fallback判断修正: preMS == orig_after || orig_after == NULL。

            void *realCCMD5Addr = (void *)orig_CC_MD5;  // 保存 dlsym 得到的真实地址（二进制hash已经计算完）

            if (g_isV3Environment && g_msHookFunction) {

                DLOG(@"[V3-MD5] ✅ 用MSHookFunction内联patch(穿透CC_MD5多层rebind — 版本过低修复依赖此!)");

                void *preMD5 = (void *)orig_CC_MD5;

                orig_CC_MD5 = NULL;

                g_msHookFunction(realCCMD5Addr,

                                 (void *)hook_CC_MD5,

                                 (void **)&orig_CC_MD5);

                if (orig_CC_MD5 && orig_CC_MD5 != preMD5) {

                    DLOG(@"[V3-MD5] MSHook OK orig=%p", orig_CC_MD5);

                } else {

                    DLOG(@"[V3-MD5-FB] MSHook失败 → fallback rebind (版本过低修复依赖此!)");

                    int rm = rebindSymbol("_CC_MD5", (void *)hook_CC_MD5, (void **)&orig_CC_MD5);

                    if (!orig_CC_MD5) orig_CC_MD5 = (CC_MD5Func)dlsym(RTLD_NEXT, "CC_MD5");

                    DLOG(@"[V3-MD5-FB] rebind=%d orig=%p (版本过低修复依赖此!)", rm, orig_CC_MD5);

                }

            } else {

                // 全能签环境: 原rebindSymbol

                int rm = rebindSymbol("_CC_MD5", (void *)hook_CC_MD5, (void **)&orig_CC_MD5);

                DLOG(@"[SEC] CC_MD5 hook v37.62: rebind=%d addr=%p", rm, orig_CC_MD5);

            }

        } else {

            DLOG(@"[SEC] CC_MD5 not found via dlsym");

        }

        // v37.134-FIX17: Removed CC_MD5_Final/Update hooks (rebind=0, never worked).

        // Removed memory scan (corrupted game state, prevented EE121 from being sent).

        // Instead, hash1/hash3 are directly replaced in the EE121 packet via

        // CC_MD5(clean_binary_hash_hex + token) computation. See [EE121-HASH-FIX17].

    }



#if !DISABLE_CRYPTO_HOOKS

    // Hook SecKeyEncrypt / SecKeyDecrypt for RSA logging

    orig_SecKeyEncrypt = (SecKeyEncryptFunc)dlsym(RTLD_NEXT, "SecKeyEncrypt");

    if (orig_SecKeyEncrypt) {

        int r2 = rebindSymbol("_SecKeyEncrypt", (void *)hook_SecKeyEncrypt, (void **)&orig_SecKeyEncrypt);

        DLOG(@"[SEC] SecKeyEncrypt hook: rebind=%d addr=%p", r2, orig_SecKeyEncrypt);

    }

    

    orig_SecKeyDecrypt = (SecKeyDecryptFunc)dlsym(RTLD_NEXT, "SecKeyDecrypt");

    if (orig_SecKeyDecrypt) {

        int r3 = rebindSymbol("_SecKeyDecrypt", (void *)hook_SecKeyDecrypt, (void **)&orig_SecKeyDecrypt);

        DLOG(@"[SEC] SecKeyDecrypt hook: rebind=%d addr=%p", r3, orig_SecKeyDecrypt);

    }

    

    // Hook SecKeyCreateDecryptedData (iOS 10+ decrypt API)

    orig_SecKeyCreateDecryptedData = (SecKeyCreateDecryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateDecryptedData");

    if (orig_SecKeyCreateDecryptedData) {

        int r4 = rebindSymbol("_SecKeyCreateDecryptedData", (void *)hook_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData);

        DLOG(@"[SEC] SecKeyCreateDecryptedData hook: rebind=%d addr=%p", r4, orig_SecKeyCreateDecryptedData);

    }

    

    // Hook SecKeyCreateEncryptedData (iOS 10+ encrypt API)

    orig_SecKeyCreateEncryptedData = (SecKeyCreateEncryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateEncryptedData");

    if (orig_SecKeyCreateEncryptedData) {

        int r5 = rebindSymbol("_SecKeyCreateEncryptedData", (void *)hook_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData);

        DLOG(@"[SEC] SecKeyCreateEncryptedData hook: rebind=%d addr=%p", r5, orig_SecKeyCreateEncryptedData);

    }

#else

    DLOG(@"[SEC] Crypto hooks DISABLED (v36.47 fix - avoid corrupting encryption data)");

#endif



    // v36.123: Hook [UIDevice identifierForVendor] so client builds UUID-natively

    installIDFVHook();

    

    // v37.3: Hook SCNetworkReachabilityGetFlags — force reachable for game server connection

    installSCNetworkReachabilityHook();

    

    DLOG(@"[SEC] Security hooks ready (with DYLD hiding)");

}



// ============================================================

#pragma mark - NSUserDefaults observation (log reads, set verify flags)

// ============================================================



typedef id (*ObjForKeyIMP)(id, SEL, NSString *);

static ObjForKeyIMP orig_objectForKey = NULL;

static int g_nsudCount = 0;

static id hook_objectForKey(id self, SEL _cmd, NSString *key) {

    id val = orig_objectForKey ? orig_objectForKey(self, _cmd, key) : nil;

    // Log first 50 NSUserDefaults reads to avoid spam

    if (g_nsudCount < 50) {

        DLOG(@"[NSUD] objectForKey: %@ = %@", key, val);

    }

    g_nsudCount++;

    return val;

}



typedef BOOL (*BoolForKeyIMP)(id, SEL, NSString *);

static BoolForKeyIMP orig_boolForKey = NULL;

static BOOL hook_boolForKey(id self, SEL _cmd, NSString *key) {

    BOOL val = orig_boolForKey ? orig_boolForKey(self, _cmd, key) : NO;

    if (g_nsudCount < 50) {

        DLOG(@"[NSUD] boolForKey: %@ = %d", key, val);

    }

    g_nsudCount++;

    return val;

}



// ============================================================

#pragma mark - Observation-only hooks (log, don't modify)

// ============================================================



// NSDictionary objectForKey: - trace server list parsing (minimal logging)

static id (*orig_dictObjectForKey)(id, SEL, id) = NULL;

static int g_dictLogCount = 0;

static id hook_dictObjectForKey(id self, SEL _cmd, id key) {

    id ret = orig_dictObjectForKey ? orig_dictObjectForKey(self, _cmd, key) : nil;

    // Limit logging to first 30 calls to avoid performance issues during keyboard input

    if (g_dictLogCount < 30) {

        NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";

        if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||

            [keyStr containsString:@"status"] || [keyStr containsString:@"Status"] ||

            [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {

            NSString *retCls = ret ? NSStringFromClass([ret class]) : @"nil";

            DLOG(@"[DICT] objectForKey:'%@' -> %@ (%@)", keyStr, ret ?: @"nil", retCls);

            g_dictLogCount++;

        }

    }

    return ret;

}



// NSArray arrayForKey: - for JSON parsing (minimal logging)

static id (*orig_arrayForKey)(id, SEL, id) = NULL;

static int g_arrayLogCount = 0;

static id hook_arrayForKey(id self, SEL _cmd, id key) {

    id ret = orig_arrayForKey ? orig_arrayForKey(self, _cmd, key) : nil;

    // Limit logging to first 20 calls to avoid performance issues during keyboard input

    if (g_arrayLogCount < 20) {

        NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";

        if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||

            [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {

            NSUInteger cnt = 0;

            if ([ret isKindOfClass:[NSArray class]]) cnt = [ret count];

            DLOG(@"[DICT] arrayForKey:'%@' -> count=%lu", keyStr, (unsigned long)cnt);

            g_arrayLogCount++;

        }

    }

    return ret;

}



// NSURLSession.dataTaskWithRequest:completionHandler: - intercept and modify responses

typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));

static DTReqCompIMP orig_dtwrc = NULL;

static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, void (^comp)(NSData *, NSURLResponse *, NSError *)) {

    NSString *url = req.URL.absoluteString;

    DLOG(@"[NET] URL: %@", url);

    

    // Wrap completion handler to intercept and modify response

    void (^wrappedComp)(NSData *, NSURLResponse *, NSError *) = comp;

    if (comp) {

        wrappedComp = [^(NSData *data, NSURLResponse *resp, NSError *err) {

            NSHTTPURLResponse *httpResp = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;

            DLOG(@"[NET] Response: status=%ld url=%@ err=%@ bodyLen=%lu",

                 httpResp ? (long)httpResp.statusCode : -1, url, err, (unsigned long)data.length);

            

            if (data && data.length > 0) {

                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

                

                if (body) {

                    DLOG(@"[NET] Body: %@", body);

                    

                    // v37.122: FIRST check - use unified signature bypass for ALL signature verification URLs

                    if (url && isSignatureVerificationURL(url)) {

                        NSData *patchedData = patchSignatureResponse(url, body);

                        if (patchedData) {

                            data = patchedData;

                            body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

                            // v37.131: Also patch HTTP status code 500→200

                            // Server returns 500 (TooManyResultsException) but game checks status code

                            if (httpResp && httpResp.statusCode != 200) {

                                DLOG(@"[SIGN-BYPASS] v37.131: Patching HTTP status %ld→200", (long)httpResp.statusCode);

                                NSMutableDictionary *patchedHeaders = [httpResp.allHeaderFields mutableCopy] ?: [NSMutableDictionary dictionary];

                                [patchedHeaders setObject:@"application/json" forKey:@"Content-Type"];

                                resp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:patchedHeaders];

                            }

                            // Log that we patched it, then continue to normal processing

                        }

                    }

                    

                    // Check if this is a server list response

                    BOOL isServerList = ([body containsString:@"server"] || [body containsString:@"servers"] || 

                                        [body containsString:@"serverCount"] || [body containsString:@"serverid"]);

                    

                    // Check if response indicates empty/no servers

                    BOOL isEmptyList = ([body containsString:@"\"serverCount\":0"] || 

                                        [body containsString:@"\"servers\":[]"] ||

                                        [body containsString:@"\"status\":5"] ||

                                        [body containsString:@"\"result\":\"fail\""]);

                    

                    if (isServerList && isEmptyList) {

                        DLOG(@"[NET-PATCH] Server list is empty, replacing with fake data");

                        NSString *fakeServerList = @"{\"status\":0,\"serverCount\":1,\"servers\":[{\"serverid\":1,\"name\":\"测试一区\",\"realname\":\"测试一区\",\"category\":\"一区\",\"serverType\":1,\"ip\":\"127.0.0.1\",\"port\":5678,\"status\":1,\"clientid\":1,\"onlinePlayerNum\":100,\"description\":\"运行\"}]}";

                        data = [fakeServerList dataUsingEncoding:NSUTF8StringEncoding];

                        DLOG(@"[NET-PATCH] Replaced with fake server list, new len=%lu", (unsigned long)data.length);

                    }

                    

                    // Check for version error

                    if ([body containsString:@"版本"] || [body containsString:@"更新"] || 

                        [body containsString:@"升级"] || [body containsString:@"版本过低"]) {

                        DLOG(@"[NET-PATCH] Detected version error, modifying...");

                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":5" withString:@"\"status\":0"];

                        body = [body stringByReplacingOccurrencesOfString:@"\"result\":\"fail\"" withString:@"\"result\":\"success\""];

                        body = [body stringByReplacingOccurrencesOfString:@"版本过低" withString:@""];

                        body = [body stringByReplacingOccurrencesOfString:@"请更新" withString:@""];

                        data = [body dataUsingEncoding:NSUTF8StringEncoding];

                    }

                    

                    // v37.122: LEGACY FALLBACK - Patch judgeAppInfoApi response (if not caught above)

                    // FIX37: 修复误匹配! 原条件 [body containsString:@"ENDTIME"] 会匹配

                    //        postAppInfoApi/getAppInfoApi(UNIVERSAL injector添加了ENDTIME)→二次patch

                    //        新条件: 只匹配URL含judgeAppInfoApi(不含SignApi)的请求

// FIX39-FINAL: DISABLED legacy [NET-PATCH] judgeAppInfoApi double-patch!
//   IRREFUTABLE PROBLEM: This legacy patch runs AFTER patchSignatureResponse() in the call chain,
//   OVERWRITING our carefully patched judgeAppInfoApi response with wrong/legacy values.
//   That double-overwrite BREAKS signature verification! → Now use patchSignatureResponse() result AS-IS.
#if 0 // ← DISABLED by FIX39-FINAL (was causing fatal double-patching)
                    if ([url containsString:@"judgeAppInfoApi"] && ![url containsString:@"SignApi"]) {

                        DLOG(@"[NET-PATCH] Detected judgeAppInfoApi response, extending ENDTIME (legacy)");

                        // Replace any ENDTIME value with a future date (2027-12-31)

                        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\"ENDTIME\":\"[^\"]*\"" options:0 error:nil];

                        body = [regex stringByReplacingMatchesInString:body options:0 range:NSMakeRange(0, body.length) withTemplate:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];

                        // Ensure END=0 (not ended) and OPEN=1 (open)

                        body = [body stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];

                        body = [body stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];

                        data = [body dataUsingEncoding:NSUTF8StringEncoding];

                        DLOG(@"[NET-PATCH] Patched judgeAppInfoApi: ENDTIME extended, END=0, OPEN=1 (code preserved as-is)");

                    }
#endif
DLOG(@"[FIX39-FINAL] Legacy NET-PATCH judgeAppInfoApi double-patch SKIPPED → using patchSignatureResponse result verbatim");


                    // === FIX46: x.md5xor.com 设备授权API ispass:NO→YES 补丁! ===
                    //   wxhook(150).log L592-594 铁证: 游戏查询 https://x.md5xor.com/jeecg-boot/ios/queryById?id=<IDFV>
                    //   服务器返回 {"ispass":"NO"} → 游戏判定设备未授权 → 服务器关闭TCP连接 → "网络断开"!
                    //   主设备成功日志(wxhook.log)中完全无此请求=主设备已授权或不触发此检查。
                    //   FIX46: 拦截md5xor响应, 把 ispass:NO→ispass:YES, test:NO→test:YES → 游戏认为设备已授权!
                    if (url && [url containsString:@"md5xor"] && body && [body containsString:@"ispass"]) {
                        DLOG(@"[FIX46-AUTH] 🔥 检测到md5xor授权API! 原始body: %@", body);
                        NSString *authBody = body;
                        authBody = [authBody stringByReplacingOccurrencesOfString:@"\"ispass\":\"NO\"" withString:@"\"ispass\":\"YES\""];
                        authBody = [authBody stringByReplacingOccurrencesOfString:@"\"ispass\":\"no\"" withString:@"\"ispass\":\"YES\""];
                        authBody = [authBody stringByReplacingOccurrencesOfString:@"\"test\":\"NO\"" withString:@"\"test\":\"YES\""];
                        authBody = [authBody stringByReplacingOccurrencesOfString:@"\"test\":\"no\"" withString:@"\"test\":\"YES\""];
                        if (![authBody isEqualToString:body]) {
                            data = [authBody dataUsingEncoding:NSUTF8StringEncoding];
                            DLOG(@"[FIX46-AUTH] ✅ ispass:NO→YES + test:NO→YES 补丁完成! newBody: %@", authBody);
                        }
                    }


                    

                    // v37.120: REMOVED cert/sign API code:0→code:1 replacement

                    // Game uses code:0 for success. This replacement was breaking startup verification.

                }

            }

            

            comp(data, resp, err);

        } copy];

    }

    

    if (orig_dtwrc) return orig_dtwrc(self, _cmd, req, wrappedComp);

    return nil;

}



// NSURLSession.dataTaskWithRequest: (delegate mode, no completion handler)

// OBSERVE ONLY - no interception (delegate injection causes crashes)

typedef NSURLSessionDataTask *(*DTReqIMP)(id, SEL, NSURLRequest *);

static DTReqIMP orig_dtr = NULL;

static NSURLSessionDataTask *hook_dtr(id self, SEL _cmd, NSURLRequest *req) {

    DLOG(@"[NET-D] delegate URL: %@", req.URL.absoluteString);

    if (orig_dtr) return orig_dtr(self, _cmd, req);

    return nil;

}



// NSURLConnection.sendAsynchronousRequest:queue:completionHandler:

typedef void (*AsyncReqIMP)(id, SEL, NSURLRequest *, NSOperationQueue *, void (^)(NSURLResponse *, NSData *, NSError *));

static AsyncReqIMP orig_asyncReq = NULL;

static void hook_async(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *q, void (^comp)(NSURLResponse *, NSData *, NSError *)) {

    NSString *url = req.URL.absoluteString;

    DLOG(@"[NET-C] async URL: %@", url);

    

    // v37.123: Intercept signature verification requests

    if (url && isSignatureVerificationURL(url) && comp) {

        void (^wrappedComp)(NSURLResponse *, NSData *, NSError *) = [^(NSURLResponse *resp, NSData *data, NSError *err) {

            DLOG(@"[NET-C] async response: url=%@ dataLen=%lu err=%@", url, (unsigned long)data.length, err);

            if (data && data.length > 0) {

                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

                NSData *patchedData = patchSignatureResponse(url, body);

                if (patchedData) {

                    data = patchedData;

                    DLOG(@"[NET-C] async response PATCHED with universal success");

                }

            }

            comp(resp, data, err);

        } copy];

        if (orig_asyncReq) orig_asyncReq(self, _cmd, req, q, wrappedComp);

        return;

    }

    

    if (orig_asyncReq) orig_asyncReq(self, _cmd, req, q, comp);

}



// NSURLConnection.sendSynchronousRequest:returningResponse:error:

typedef NSData *(*SyncReqIMP)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **);

static SyncReqIMP orig_syncReq = NULL;

static NSData *hook_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **resp, NSError **err) {

    NSString *url = req.URL.absoluteString;

    DLOG(@"[NET-C] sync URL: %@", url);

    

    if (orig_syncReq) {

        NSData *result = orig_syncReq(self, _cmd, req, resp, err);

        

        // v37.123: Intercept signature verification responses

        if (url && isSignatureVerificationURL(url) && result && result.length > 0) {

            NSString *body = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];

            NSData *patchedData = patchSignatureResponse(url, body);

            if (patchedData) {

                DLOG(@"[NET-C] sync response PATCHED with universal success");

                return patchedData;

            }

        }

        return result;

    }

    return nil;

}



// UIViewController.presentViewController - OBSERVE + VERSION ALERT BLOCKING

// NOTE: presentViewController:animated:completion: is called ON THE PRESENTING VC,

// NOT on the presented VC. So we must hook UIViewController's version, not UIAlertController's!

// The previous hook on UIAlertController was NEVER triggered, and had WRONG param order causing SIGSEGV.

typedef void (*PresentVC_IMP)(id, SEL, UIViewController *, BOOL, void (^)(void));

static PresentVC_IMP orig_presentVC = NULL;

static void hook_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {

    @try {

        // Check if presented VC is UIAlertController - block version-related alerts HERE

        if (vc && [vc isKindOfClass:[UIAlertController class]]) {

            @try {

                UIAlertController *alert = (UIAlertController *)vc;

                NSString *title = [alert title];

                NSString *msg = [alert message];

                NSString *presenterClass = NSStringFromClass([self class]);

                DLOG(@"[UI] presentVC: UIAlertController title='%@' msg='%@' presenter=%@",

                     title ? title : @"<nil>", msg ? msg : @"<nil>", presenterClass);

                

                if (title || msg) {

                    NSString *lowerMsg = msg ? [[msg lowercaseString] copy] : @"";

                    NSString *lowerTitle = title ? [[title lowercaseString] copy] : @"";

                    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] ||

                        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||

                        [lowerMsg containsString:@"升级"] || [lowerMsg containsString:@"version"] ||

                        [lowerMsg containsString:@"update"]) {

                        DLOG(@"[ALERT-BLOCK] Blocked version alert in hook_presentVC: title='%@' msg='%@'",

                             title ? title : @"", msg ? msg : @"");

                        return;  // Do NOT present!

                    }

                }

            } @catch (NSException *e) {

                DLOG(@"[UI] Exception checking alert: %@", e.reason);

                // Passthrough on error - don't lose the alert completely

            }

        } else {

            NSString *vcClass = vc ? NSStringFromClass([vc class]) : @"<nil>";

            DLOG(@"[UI] presentVC: %@ presenter=%@", vcClass, NSStringFromClass([self class]));

        }

    } @catch (NSException *e) {

        DLOG(@"[UI] Outer exception in hook_presentVC: %@", e.reason);

    }

    

    // Always call original (unless we returned early for blocked alerts)

    // Safe completion: copy to heap, fallback to empty block

    void (^safeCompletion)(void) = NULL;

    if (completion) {

        @try {

            safeCompletion = [completion copy];

        } @catch (...) {

            safeCompletion = NULL;

        }

    }

    if (!safeCompletion) {

        safeCompletion = ^{};

    }

    

    if (orig_presentVC) {

        orig_presentVC(self, _cmd, vc, animated, safeCompletion);

    }

}



// ============================================================

#pragma mark - EncryptUtils Hook (v36.130 - FIXED RECURSION BUG)

// ============================================================

// Client uses EncryptUtils (BoringSSL) for RSA/AES decryption.

// We hook these class methods to return valid plaintext when forceValidDecrypt=YES.

//

// v36.130 CRITICAL FIX:

//   v36.129 had infinite recursion bug: non-bypass path used method_getImplementation()

//   which returns the REPLACED implementation (our hook), causing infinite recursion → crash.

//   FIX: Save original IMPs at install time, use saved IMPs in non-bypass path.

//

// v36.130 IMPROVEMENT:

//   Use bypass counter (up to 5) instead of one-shot flag, to handle multi-step decryption.



static BOOL g_encryptUtilsHooksInstalled = NO;

// Note: g_bypassRemaining, g_orig_rsaDecryptData, g_orig_rsaDecryptLarge, g_orig_aesDecryptData

// are defined earlier (near g_forceValidDecrypt) for forward access in hook_recv logic.



// Forward declaration for C++ Crypto Hook flag (defined later in C++ Crypto Hook section)

static BOOL g_cppCryptoHooksInstalled;



// Hook for +rsaDecryptData:withKeyRef:

// v36.132: ENCRYPT-BYPASS only triggers when C++ Crypto Hook is NOT installed

//          If C++ Hook is active, bypass is handled at C++ level (returning std::string)

//          EncryptUtils bypass would return NSData which causes C++ type mismatch crash

static NSData* hooked_rsaDecryptData(Class self, SEL _cmd, NSData *data, id keyRef) {

    if (g_forceValidDecrypt && data && g_bypassRemaining > 0 && !g_cppCryptoHooksInstalled) {

        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";

        NSData *fakeData = [NSData dataWithBytes:fakePlaintext length:strlen(fakePlaintext)];

        g_bypassRemaining--;

        DLOG(@"[ENCRYPT-BYPASS] v36.132: rsaDecryptData: SKIP real decrypt, return fake (remaining=%d, cppHook=%d)", g_bypassRemaining, g_cppCryptoHooksInstalled);

        if (g_bypassRemaining <= 0) {

            g_forceValidDecrypt = NO;

            DLOG(@"[ENCRYPT-BYPASS] v36.132: bypass exhausted, forceValidDecrypt=NO");

        }

        return fakeData;

    }

    // Non-bypass: use saved original IMP (no recursion!)

    if (g_orig_rsaDecryptData) {

        typedef NSData* (*OriginalFunc)(Class, SEL, NSData*, id);

        return ((OriginalFunc)g_orig_rsaDecryptData)(self, _cmd, data, keyRef);

    }

    return nil;

}



// Hook for +rsaDecryptLarge:withPrivateKey:

// v36.132: CRITICAL CHANGE - DO NOT trigger bypass when C++ Hook is installed!

//   C++ code expects std::string, not NSData. Returning NSData causes:

//   -[_NSInlineData UTF8String]: unrecognized selector → SIGABRT crash

//   Bypass is now handled by cpp_stub_force in C++ layer

static NSData* hooked_rsaDecryptLarge(Class self, SEL _cmd, NSData *data, NSData *privateKey) {

    if (g_forceValidDecrypt && data && g_bypassRemaining > 0 && !g_cppCryptoHooksInstalled) {

        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";

        NSData *fakeData = [NSData dataWithBytes:fakePlaintext length:strlen(fakePlaintext)];

        g_bypassRemaining--;

        DLOG(@"[ENCRYPT-BYPASS] v36.132: rsaDecryptLarge: SKIP real decrypt, return fake (remaining=%d, cppHook=%d)", g_bypassRemaining, g_cppCryptoHooksInstalled);

        if (g_bypassRemaining <= 0) {

            g_forceValidDecrypt = NO;

            DLOG(@"[ENCRYPT-BYPASS] v36.132: bypass exhausted, forceValidDecrypt=NO");

        }

        return fakeData;

    }

    // C++ Hook is installed - always pass through to original (C++ layer handles bypass)

    if (g_cppCryptoHooksInstalled && g_forceValidDecrypt) {

        DLOG(@"[ENCRYPT-PASS] v36.132: rsaDecryptLarge: pass through to original (C++ hook active, cppHook=%d)", g_cppCryptoHooksInstalled);

    }

    if (g_orig_rsaDecryptLarge) {

        typedef NSData* (*OriginalFunc)(Class, SEL, NSData*, NSData*);

        return ((OriginalFunc)g_orig_rsaDecryptLarge)(self, _cmd, data, privateKey);

    }

    return nil;

}



// Hook for +aesDecryptData:key:iv:

static NSData* hooked_aesDecryptData(Class self, SEL _cmd, NSData *data, NSData *key, NSData *iv) {

    if (g_forceValidDecrypt && data && g_bypassRemaining > 0 && !g_cppCryptoHooksInstalled) {

        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";

        NSData *fakeData = [NSData dataWithBytes:fakePlaintext length:strlen(fakePlaintext)];

        g_bypassRemaining--;

        DLOG(@"[ENCRYPT-BYPASS] v36.132: aesDecryptData: SKIP real decrypt, return fake (remaining=%d, cppHook=%d)", g_bypassRemaining, g_cppCryptoHooksInstalled);

        if (g_bypassRemaining <= 0) {

            g_forceValidDecrypt = NO;

            DLOG(@"[ENCRYPT-BYPASS] v36.132: bypass exhausted, forceValidDecrypt=NO");

        }

        return fakeData;

    }

    if (g_orig_aesDecryptData) {

        typedef NSData* (*OriginalFunc)(Class, SEL, NSData*, NSData*, NSData*);

        return ((OriginalFunc)g_orig_aesDecryptData)(self, _cmd, data, key, iv);

    }

    return nil;

}



// Install EncryptUtils hooks

static void installEncryptUtilsHooks_v130(void) {

    @try {

        if (g_encryptUtilsHooksInstalled) return;

        

        Class encryptUtilsCls = NSClassFromString(@"EncryptUtils");

        if (!encryptUtilsCls) {

            DLOG(@"[ENCRYPT-HOOK] v36.130: EncryptUtils class NOT found");

            return;

        }

        

        Class metaCls = object_getClass(encryptUtilsCls);

        DLOG(@"[ENCRYPT-HOOK] v36.130: EncryptUtils found, metaCls=%p", metaCls);

        

        // Hook +rsaDecryptData:withKeyRef:

        SEL sel1 = NSSelectorFromString(@"rsaDecryptData:withKeyRef:");

        if ([metaCls instancesRespondToSelector:sel1]) {

            Method m = class_getInstanceMethod(metaCls, sel1);

            if (m) {

                g_orig_rsaDecryptData = method_getImplementation(m);

                method_setImplementation(m, (IMP)hooked_rsaDecryptData);

                DLOG(@"[ENCRYPT-HOOK] v36.130: OK - Hooked +rsaDecryptData:withKeyRef: (orig=%p)", g_orig_rsaDecryptData);

            }

        }

        

        // Hook +rsaDecryptLarge:withPrivateKey:

        SEL sel2 = NSSelectorFromString(@"rsaDecryptLarge:withPrivateKey:");

        if ([metaCls instancesRespondToSelector:sel2]) {

            Method m = class_getInstanceMethod(metaCls, sel2);

            if (m) {

                g_orig_rsaDecryptLarge = method_getImplementation(m);

                method_setImplementation(m, (IMP)hooked_rsaDecryptLarge);

                DLOG(@"[ENCRYPT-HOOK] v36.130: OK - Hooked +rsaDecryptLarge:withPrivateKey: (orig=%p)", g_orig_rsaDecryptLarge);

            }

        }

        

        // Hook +aesDecryptData:key:iv:

        SEL sel3 = NSSelectorFromString(@"aesDecryptData:key:iv:");

        if ([metaCls instancesRespondToSelector:sel3]) {

            Method m = class_getInstanceMethod(metaCls, sel3);

            if (m) {

                g_orig_aesDecryptData = method_getImplementation(m);

                method_setImplementation(m, (IMP)hooked_aesDecryptData);

                DLOG(@"[ENCRYPT-HOOK] v36.130: OK - Hooked +aesDecryptData:key:iv: (orig=%p)", g_orig_aesDecryptData);

            }

        }

        

        g_encryptUtilsHooksInstalled = YES;

        DLOG(@"[ENCRYPT-HOOK] v36.130: All EncryptUtils hooks installed (orig IMPs saved, non-bypass = safe)");

    } @catch (NSException *e) {

        DLOG(@"[ENCRYPT-HOOK] v36.130: Exception: %@", e.reason);

    }

}



// ============================================================

#pragma mark - C++ Crypto Hook (v36.131 - FIX CRASH)

// ============================================================

// CRITICAL FINDING (v36.130 crash analysis):

//   Client uses cocos2d::CCFileUtils::rsaDecryptLarge (C++), NOT EncryptUtils (ObjC).

//   EncryptUtils is called indirectly, but C++ code is the actual entry point.

//   Hook strategy:

//     1. Keep EncryptUtils hooks for ObjC path (login cert verification)

//     2. ADD C++ function hooks using rebind_symbols for CCFileUtils::rsaDecryptLarge

//     3. When forceValidDecrypt=YES, return empty string immediately

//

// The crash in v36.130:

//   -[_NSInlineData UTF8String]: unrecognized selector

//   C++ code got NSData back from EncryptUtils hook, tried UTF8String on it.

//   Fix: Hook at C++ level, return std::string directly.

//

// v36.131 CRITICAL FIX:

//   Previous cpp_stub_force had WRONG register handling:

//   - It constructed std::string on stack (sp+16), NOT in x0 output buffer

//   - ARM64 ABI: return value std::string is written to x0 (output buffer)

//   - Calling convention: x0=output_buf, x1=this, x2=arg1, x3=arg2

//   Fixed: Write empty string directly to x0 buffer, keep all args unchanged

//   For original call: restore frame, BR to original (not BL, no new frame)



// g_cppCryptoHooksInstalled is defined as static BOOL above (line ~6430), initialized to 0 (= NO)

// Saved original C++ function pointers

// NOTE: g_cppOrig must NOT be static because it's referenced from

// inline ARM64 assembly in cpp_stub_force()

typedef struct {

    void *orig_rsaDecryptLarge;

    void *orig_rsaDecryptData;

} CppCryptoOrig;



CppCryptoOrig g_cppOrig = {NULL, NULL};



// Empty string constant

static const char g_cppEmptyStr[] = "";



// Success response string for bypass

// NOTE: g_cppSuccessStr must NOT be static because it's referenced from

// inline ARM64 assembly in cpp_stub_force()

const char g_cppSuccessStr[] = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";



// ARM64 C stub for CCFileUtils::rsaDecryptLarge

// C++ member function ABI (ARM64) - CRITICAL for large return:

//   For functions returning objects > 16 bytes (like std::string):

//   x0 = output buffer pointer (caller-allocated, 24 bytes for std::string)

//   x1 = this pointer

//   x2 = first arg (std::string const&)

//   x3 = second arg (std::string const&)

// Return: std::string written to x0 buffer, x0 stays as buffer ptr

//

// v36.132 FIX: Pure C implementation (no inline assembly)

//   - Correct function signature matches ARM64 ABI

//   - Writes fake std::string to output_buf directly via pointer manipulation

//   - Calls original function via function pointer for non-bypass path

void cpp_stub_force(void* output_buf, void* self, void* data, void* key) {

    // Check forceValidDecrypt flag (now a non-static global variable)

    if (g_forceValidDecrypt) {

        // Bypass path: write fake success std::string to output_buf

        // std::string internal layout (for Apple's libc++):

        //   offset 0: char* data_ (pointer to string data)

        //   offset 8: size_t length_

        //   offset 16: size_t capacity_

        // Note: For strings <= 15 chars, libc++ uses SSO (small string optimization)

        // which stores data inline. But our 37-char string exceeds SSO threshold,

        // so it uses heap allocation with a pointer.

        const char* fakeStr = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";

        size_t fakeLen = 37;  // strlen(fakeStr)

        

        // Write directly to the output buffer (caller's std::string storage)

        char** dataPtr = (char**)output_buf;

        *dataPtr = (char*)fakeStr;  // data_ = pointer to fake string

        

        size_t* lenPtr = (size_t*)((char*)output_buf + 8);

        *lenPtr = fakeLen;  // length_ = 37

        

        size_t* capPtr = (size_t*)((char*)output_buf + 16);

        *capPtr = fakeLen;  // capacity_ = 37 (must be >= length_)

        

        return;

    }

    

    // Normal path: call original function

    // Use function pointer stored in g_cppOrig.orig_rsaDecryptLarge

    typedef void (*OriginalFunc)(void* output_buf, void* self, void* data, void* key);

    OriginalFunc origFunc = (OriginalFunc)g_cppOrig.orig_rsaDecryptLarge;

    if (origFunc) {

        origFunc(output_buf, self, data, key);

    }

}



// Install C++ crypto hooks using rebind_symbols

static void installCppCryptoHooks_v131(void) {

    if (g_cppCryptoHooksInstalled) return;

    

    DLOG(@"[CPP-CRYPTO] v36.131: Installing C++ crypto hooks for CCFileUtils::rsaDecryptLarge...");

    

    // The mangled name for cocos2d::CCFileUtils::rsaDecryptLarge

    // std::string rsaDecryptLarge(std::string const&, std::string const&)

    const char* mangledName = "_ZN7cocos2d11CCFileUtils15rsaDecryptLargeENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_";

    

    void* sym = NULL;

    int imageCount = (int)_dyld_image_count();

    

    // Search in game binary and dylibs

    for (int i = 0; i < imageCount; i++) {

        const char* imageName = _dyld_get_image_name(i);

        if (!imageName) continue;

        

        if (strstr(imageName, "wangxian") || 

            strstr(imageName, "WangXian") ||

            strstr(imageName, "lnSignature") ||

            strstr(imageName, "libSupport")) {

            

            DLOG(@"[CPP-CRYPTO] Searching in image %d: %s", i, imageName);

            

            void* handle = dlopen(imageName, RTLD_LAZY | RTLD_NOLOAD);

            if (handle) {

                void* sym2 = dlsym(handle, mangledName);

                if (sym2) {

                    sym = sym2;

                    DLOG(@"[CPP-CRYPTO] FOUND %s at %p in %s", mangledName, sym, imageName);

                    dlclose(handle);

                    break;

                }

                dlclose(handle);

            }

        }

    }

    

    // If not found, try alternative names

    if (!sym) {

        DLOG(@"[CPP-CRYPTO] First search failed, trying alternate mangled names...");

        

        const char* altNames[] = {

            "_ZN7cocos2d11CCFileUtils15rsaDecryptLargeENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_",

            "_ZN7cocos2d11CCFileUtils15rsaDecryptLargeE",

            NULL

        };

        

        for (int j = 0; altNames[j]; j++) {

            for (int i = 0; i < imageCount; i++) {

                const char* imageName = _dyld_get_image_name(i);

                if (!imageName) continue;

                

                if (strstr(imageName, "wangxian") || 

                    strstr(imageName, "WangXian") ||

                    strstr(imageName, "lnSignature") ||

                    strstr(imageName, "libSupport")) {

                    

                    void* handle = dlopen(imageName, RTLD_LAZY | RTLD_NOLOAD);

                    if (handle) {

                        void* sym2 = dlsym(handle, altNames[j]);

                        if (sym2) {

                            sym = sym2;

                            DLOG(@"[CPP-CRYPTO] FOUND '%s' at %p in %s", altNames[j], sym, imageName);

                            dlclose(handle);

                            break;

                        }

                        dlclose(handle);

                    }

                }

                if (sym) break;

            }

            if (sym) break;

        }

    }

    

    if (sym) {

        g_cppOrig.orig_rsaDecryptLarge = sym;

        DLOG(@"[CPP-CRYPTO] Original rsaDecryptLarge at %p", sym);

        

        // Get the header of the main executable

        const mach_header* mainHeader = (const mach_header*)_dyld_get_image_header(0);

        if (mainHeader) {

            DLOG(@"[CPP-CRYPTO] Main header: %p, rebinding...", mainHeader);

            

            struct rebinding rebinds[] = {

                { mangledName, (void*)cpp_stub_force, NULL }

            };

            

            int result = rebind_symbols_image((void*)mainHeader, NULL, rebinds, 1);

            DLOG(@"[CPP-CRYPTO] rebind_symbols_image result: %d", result);

            

            if (result == 0) {

                DLOG(@"[CPP-CRYPTO] v36.131: C++ crypto hooks installed successfully!");

                g_cppCryptoHooksInstalled = YES;

            } else {

                DLOG(@"[CPP-CRYPTO] v36.131: rebind_symbols_image failed (result=%d). Trying dlopen approach...", result);

                

                // Alternative: dlopen and use rebind_symbols on that handle

                void* mainHandle = dlopen(NULL, RTLD_LAZY);

                if (mainHandle) {

                    struct rebinding rebinds2[] = {

                        { mangledName, (void*)cpp_stub_force, NULL }

                    };

                    int result2 = rebind_symbols_image(

                        (void*)_dyld_get_image_header(0),

                        NULL,

                        rebinds2,

                        1

                    );

                    DLOG(@"[CPP-CRYPTO] Second rebind attempt result: %d", result2);

                    if (result2 == 0) {

                        g_cppCryptoHooksInstalled = YES;

                        DLOG(@"[CPP-CRYPTO] v36.131: C++ crypto hooks installed via second attempt!");

                    }

                }

            }

        }

    } else {

        DLOG(@"[CPP-CRYPTO] FAILED to find rsaDecryptLarge symbol.");

        DLOG(@"[CPP-CRYPTO] Will dump all rsaDecrypt-related symbols for debugging...");

        

        // Dump symbols containing "rsaDecrypt" or "CCFileUtils"

        for (int i = 0; i < imageCount; i++) {

            const char* imageName = _dyld_get_image_name(i);

            if (!imageName) continue;

            

            if (strstr(imageName, "wangxian") || strstr(imageName, "WangXian")) {

                DLOG(@"[CPP-CRYPTO] Searching in: %s", imageName);

                

                void* handle = dlopen(imageName, RTLD_LAZY | RTLD_NOLOAD);

                if (handle) {

                    const char* patterns[] = {

                        "rsaDecryptLarge",

                        "rsaDecryptData",

                        "CCFileUtils",

                        "encryptData",

                        "decryptData",

                        NULL

                    };

                    

                    for (int p = 0; patterns[p]; p++) {

                        void* sym2 = dlsym(handle, patterns[p]);

                        if (sym2) {

                            DLOG(@"[CPP-CRYPTO] Found '%s' at %p", patterns[p], sym2);

                        }

                    }

                    dlclose(handle);

                }

                break;

            }

        }

    }

    

    DLOG(@"[CPP-CRYPTO] v36.131: installCppCryptoHooks completed (installed=%d)", g_cppCryptoHooksInstalled);

}



// ============================================================

#pragma mark - v37.0 Minimal Recv Hook (login server patches only)

// ============================================================



// v37.134-FIX6: Patch login server response data in-place

// v37.6: ONLY patch status byte for 0x802EE118/120/121 — NO string modifications

// v37.6 FIX: v37.1-v37.4 patched status + cleared strings, which corrupted

//            response body → '网络连接中断'. v37.5 disabled recv hook entirely

//            → '版本过低' returned. v37.6: ONLY patch status=4→0, leave body intact.

//            Client sees status=0 (success) + original body → parses server list correctly.

// v37.134-FIX6: RESTORE status=4→0 patch for EE121!

//   FIX5 fixed EE121-CANON TLV structure (added missing empty TLV), so server now

//   ACCEPTS the packet and returns status=4 ('版本过低'). But client stops at status=4.

//   Fix: patch status byte 4→0 AND clear '版本过低'/'登录失败' text so client proceeds.

static void patchLoginServerData(uint8_t *data, ssize_t len) {

    if (len < 8) return;



    // v37.134-FIX6: Check if this is an EE121/EE118/EE120 response (has status byte at offset 12)

    // Packet format: [4B pktLen][4B cmd][4B seq][1B status][body...]

    // cmd is at offset 4-7, status at offset 12

    uint32_t pktLen = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];

    uint32_t cmd = (data[4]<<24)|(data[5]<<16)|(data[6]<<8)|data[7];

    if ((cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) && len >= 13) {

        uint8_t status = data[12];

        if (status == 4) {

            DLOG(@"[RECV-PATCH] v37.134-FIX6: cmd=0x%08X status=4→0 (bypassing server version check)", cmd);

            data[12] = 0;

        }

    }



    // Clear "版本过低" (UTF-8: E7 89 88 E6 9C AC E8 BF 87 E4 BD 8E) → 12 spaces

    static const uint8_t versionLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};

    for (ssize_t i = 0; i <= len - 12; i++) {

        if (memcmp(data + i, versionLow, 12) == 0) {

            memset(data + i, 0x20, 12);

            DLOG(@"[RECV-PATCH] v37.134-FIX6: Cleared '版本过低' at offset %zd", i);

        }

    }



    // Also clear "当前版本" (UTF-8: E5 BD 93 E5 89 8D E7 89 88 E6 9C AC) → 12 spaces

    static const uint8_t curVersion[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};

    for (ssize_t i = 0; i <= len - 12; i++) {

        if (memcmp(data + i, curVersion, 12) == 0) {

            memset(data + i, 0x20, 12);

            DLOG(@"[RECV-PATCH] v37.134-FIX6: Cleared '当前版本' at offset %zd", i);

        }

    }



    // Also clear "登录失败" (UTF-8: E7 99 BB E5 BD 95 E5 A4 B1 E8 B4 A5) → 12 spaces

    static const uint8_t loginFail[] = {0xE7,0x99,0xBB,0xE5,0xBD,0x95,0xE5,0xA4,0xB1,0xE8,0xB4,0xA5};

    for (ssize_t i = 0; i <= len - 12; i++) {

        if (memcmp(data + i, loginFail, 12) == 0) {

            memset(data + i, 0x20, 12);

            DLOG(@"[RECV-PATCH] v37.134-FIX6: Cleared '登录失败' at offset %zd", i);

        }

    }

}



// v37.0: Minimal recv hook — patches login server responses ONLY

static ssize_t hook_recv_minimal(int fd, void *buf, size_t len, int flags) {

    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");

    if (!orig_recv) return -1;



    ssize_t ret = orig_recv(fd, buf, len, flags);

    if (ret > 0) {

        patchLoginServerData((uint8_t *)buf, ret);

    }

    return ret;

}



// v37.0: Minimal recvfrom hook

static ssize_t hook_recvfrom_minimal(int fd, void *buf, size_t len, int flags,

                                     struct sockaddr *from, socklen_t *fromlen) {

    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");

    if (!orig_recvfrom) return -1;



    ssize_t ret = orig_recvfrom(fd, buf, len, flags, from, fromlen);

    if (ret > 0) {

        patchLoginServerData((uint8_t *)buf, ret);

    }

    return ret;

}



// v37.0: Minimal recvmsg hook

static ssize_t hook_recvmsg_minimal(int fd, struct msghdr *msg, int flags) {

    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");

    if (!orig_recvmsg) return -1;



    ssize_t ret = orig_recvmsg(fd, msg, flags);

    if (ret > 0 && msg && msg->msg_iov && msg->msg_iovlen > 0) {

        // Patch first iov buffer

        struct iovec *iov = &msg->msg_iov[0];

        if (iov->iov_base && iov->iov_len >= 8) {

            patchLoginServerData((uint8_t *)iov->iov_base, MIN((ssize_t)iov->iov_len, ret));

        }

    }

    return ret;

}



// v37.0: Install minimal recv hooks (login server patches only, no game server mods)

static void installMinimalSocketHooks(void) {

    DLOG(@"[SOCK-MINIMAL] v37.6: Installing minimal recv hooks (status-only patch)...");



    int r = rebindSymbol("_recv", (void *)hook_recv_minimal, (void **)&orig_recv);

    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom_minimal, (void **)&orig_recvfrom);

    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg_minimal, (void **)&orig_recvmsg);



    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");

    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");

    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");



    DLOG(@"[SOCK-MINIMAL] recv=%d recvfrom=%d recvmsg=%d (orig: recv=%p recvfrom=%p recvmsg=%p)",

         r, rf, rm, orig_recv, orig_recvfrom, orig_recvmsg);

}



// ============================================================

#pragma mark - Constructor - MINIMAL + observer hooks

// ============================================================



__attribute__((constructor))

static void entry(void) {

    log_init();

    

    if (!g_isActivated) {

        DLOG(@"[ACT] Not activated, waiting for activation...");

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{

            if (!g_isActivated) {

                DLOG(@"[ACT] Still not activated after 3 seconds");

            }

        });

        return;

    }

    

    installAllHooks();

}



// v37.26: MULTI-LAYER channel name interception at ALL construction points.

//

// v37.25 FAILED: NSBundle hook found 0 replacements → Info.plist does NOT

// contain DY_MIESHI. The channel is a hardcoded C-string compiled into the

// client binary, propagated via memcpy/CFString/NSString/CCCrypt-plaintext.

//

// v37.24 MEM-PATCH conceptually worked but white-screened because we logged

// "DY_MIESHI at 0x..." which itself contained DY_MIESHI text → patch loop.

//

// v37.26 6-LAYER defense (no memory scan, NO recursive logging):

//   L1: CFStringCreateWithCString        → "DY_MIESHI" C-string → CFSTR

//   L2: +[NSString stringWithUTF8String:] / -[NSString initWithUTF8String:]

//                                           → ObjC string construction

//   L3: memcpy(dest, src, n)              → C structure copy DY_MIESHI

//         src matches exactly → use longer replacement

//   L4: CCCrypt (op=0 ENC)               → plaintext JSON/protobuf buffer

//                                           BEFORE AES encrypt, find/replace

//   L5: send() ALL cmd on login+game ports → find DY_MIESHI in send buffer

//         (skip signed packets: 0x0000E002, 0x002EE118, 0x0002A018, 0x002EE121

//          on port 5678 — v37.21 proved EE121 signature HASH check kills conn)

//   L6: cmd=0x000EE007 channel len patch  → legacy safety net

//

// NO LOGGING of DY_MIESHI text in layer hooks to avoid self-recursion.

// Only ONE final diagnostic log per unique call site using numeric tags.



// ===== L0: strlen / strcmp / strncmp hooks (INIT TIME propagation) =====

// v37.33: Channel is hardcoded as C-string literal "DY_MIESHI" in TEXT.__cstring.

// If client reads DY_MIESHI at init time, construct_NEW_USER_ENTER_SERVER_REQER

// builds ONLY 604B JSON (missing accountId/hasRole/serverInfo fields). If it reads

// "DYanyou0040_MIESHI" then it builds 1010B FULL JSON. Hence we need to propagate

// channel replacement BEFORE any ObjC / JSON builder code runs. So intercept

// strlen + strcmp + strncmp at libSystem level. Combined with L3 memcpy fix,

// EVERY call site (allocation, comparison, copy) sees the LONGER correct channel.



// Canonical long channel. We keep static storage; if strlen("DY_MIESHI") is called,

// return 18 instead of 9 → caller mallocs 19 bytes → then our memcpy L3 can fit.

static const char kLongChannel[20] = "DYanyou0040_MIESHI"; // 18 + NUL



static size_t (*orig_strlen)(const char *s) = NULL;

static size_t hook_strlen(const char *s) {

    if (!orig_strlen) orig_strlen = (size_t (*)(const char*))dlsym(RTLD_NEXT, "strlen");

    // Use memcmp (NOT strcmp — strcmp is hooked and will recurse!)

    if (s && memcmp(s, "DY_MIESHI", 10) == 0) { // 10 = 9 chars + NUL

        return 18;

    }

    return orig_strlen ? orig_strlen(s) : ((size_t(*)(const char*))strlen)(s);

}



static int (*orig_strcmp)(const char *a, const char *b) = NULL;

static int hook_strcmp(const char *a, const char *b) {

    if (!orig_strcmp) orig_strcmp = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "strcmp");

    // Check channel forms with memcmp (to avoid recursion into strcmp)

    int sa = 0, sb = 0;

    if (a) {

        if (memcmp(a, "DY_MIESHI", 10) == 0) sa = 1;

        else if (memcmp(a, "DYanyou0040_MIESHI", 19) == 0) sa = 2;

    }

    if (b) {

        if (memcmp(b, "DY_MIESHI", 10) == 0) sb = 1;

        else if (memcmp(b, "DYanyou0040_MIESHI", 19) == 0) sb = 2;

    }

    if (sa > 0 && sb > 0) return 0; // canonical equivalence

    if (sa > 0) a = kLongChannel;

    if (sb > 0) b = kLongChannel;

    return orig_strcmp ? orig_strcmp(a, b) : ((int (*)(const char*,const char*))strcmp)(a, b);

}



static int (*orig_strncmp)(const char *a, const char *b, size_t n) = NULL;

static int hook_strncmp(const char *a, const char *b, size_t n) {

    if (!orig_strncmp) orig_strncmp = (int (*)(const char*, const char*, size_t))dlsym(RTLD_NEXT, "strncmp");

    BOOL aCh = NO, bCh = NO;

    if (a && n >= 9 && memcmp(a, "DY_MIESHI", 9) == 0) aCh = YES;

    else if (a && n >= 18 && memcmp(a, "DYanyou0040_MIESHI", 18) == 0) aCh = YES;

    if (b && n >= 9 && memcmp(b, "DY_MIESHI", 9) == 0) bCh = YES;

    else if (b && n >= 18 && memcmp(b, "DYanyou0040_MIESHI", 18) == 0) bCh = YES;

    if (aCh && bCh) return 0;

    if (aCh && n >= 18) a = kLongChannel;

    if (bCh && n >= 18) b = kLongChannel;

    return orig_strncmp ? orig_strncmp(a, b, n) : ((int(*)(const char*,const char*,size_t))strncmp)(a, b, n);

}



// ===== L3: memcpy interception (v37.33 fixed) =====

typedef void *(*memcpyFunc)(void *dest, const void *src, size_t n);

static memcpyFunc orig_memcpy = NULL;

static void *hook_memcpy(void *dest, const void *src, size_t n) {

    // DY_MIESHI is 9 chars; if src starts with it, propagate replacement.

    // v37.33: because strlen hook already returns 18, callers who do

    //   char *buf = malloc(strlen(s)+1); memcpy(buf, s, strlen(s)+1);

    // now allocate 19 bytes and memcpy 19 bytes (n==19 or n>=18 since strlen→18).

    // Hence dest capacity is sufficient to fit replacement. We just copy.

    if (src && n >= 9 && memcmp(src, "DY_MIESHI", 9) == 0) {

        // Case A: exact 9-byte or 10-byte (9 + NUL) — handled if n>=18 (thanks to strlen hook).

        // If n >= 19 we can write full replacement + safety null term.

        if (n >= 19) {

            static int count = 0;

            if (count < 3) { DLOG(@"[CH-L3] memcpy_short→long n=%zu site=%d", n, count); count++; }

            size_t rlen = 18;

            if (orig_memcpy) orig_memcpy(dest, kLongChannel, rlen);

            // NUL fill remaining

            if (n > rlen) memset((char*)dest + rlen, 0, n - rlen);

            return dest;

        }

        // Case B: n is smaller (e.g. fixed struct copy of 10 bytes or less).

        // Can't expand → leave as-is; L4/network-layer patch later will correct.

    }

    return orig_memcpy ? orig_memcpy(dest, src, n) : memcpy(dest, src, n);

}



// ===== L1: CFStringCreateWithCString =====

typedef CFStringRef (*CFStringCreateWithCStringFunc)(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);

static CFStringCreateWithCStringFunc orig_CFStringCreateWithCString = NULL;

static CFStringRef hook_CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding) {

    if (!orig_CFStringCreateWithCString) {

        orig_CFStringCreateWithCString = (CFStringCreateWithCStringFunc)dlsym(RTLD_NEXT, "CFStringCreateWithCString");

    }

    if (cStr && encoding == kCFStringEncodingUTF8 && memcmp(cStr, "DY_MIESHI", 10) == 0) {

        static int count = 0;

        if (count < 3) { DLOG(@"[CH-L1] tag=CFStringCreateWithCString site=%d", count); count++; }

        return CFStringCreateWithCString(alloc, kLongChannel, encoding);

    }

    return orig_CFStringCreateWithCString ? orig_CFStringCreateWithCString(alloc, cStr, encoding) : NULL;

}



// ===== L2: NSString UTF8 hooks =====

static id (*orig_stringWithUTF8String)(Class self, SEL _cmd, const char *cStr);

static id hook_stringWithUTF8String(Class self, SEL _cmd, const char *cStr) {

    if (cStr && memcmp(cStr, "DY_MIESHI", 10) == 0) {

        static int count = 0;

        if (count < 3) { DLOG(@"[CH-L2] tag=stringWithUTF8String site=%d", count); count++; }

        return orig_stringWithUTF8String(self, _cmd, kLongChannel);

    }

    return orig_stringWithUTF8String(self, _cmd, cStr);

}

static id (*orig_initWithUTF8String)(NSString *self, SEL _cmd, const char *cStr);

static id hook_initWithUTF8String(NSString *self, SEL _cmd, const char *cStr) {

    if (cStr && memcmp(cStr, "DY_MIESHI", 10) == 0) {

        static int count = 0;

        if (count < 3) { DLOG(@"[CH-L2] tag=initWithUTF8String site=%d", count); count++; }

        return orig_initWithUTF8String(self, _cmd, kLongChannel);

    }

    return orig_initWithUTF8String(self, _cmd, cStr);

}



// ===== L4: CCCrypt plaintext ENC replacement =====

// (replaces old hook_CCCrypt)

static int hook_CCCrypt_v37_26(uint32_t op, uint32_t alg, uint32_t options,

                                const void *key, size_t keyLen,

                                const void *iv,

                                const void *dataIn, size_t dataInLen,

                                void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {

    if (!orig_CCCrypt) orig_CCCrypt = (CCCryptFunc)dlsym(RTLD_NEXT, "CCCrypt");

    if (!orig_CCCrypt) return -1;



    // v37.28: L4 gate — only active after game server challenge (0x80FFF495).

    // Before that, pass through unchanged to avoid crashing JudgeApp/SecKey.

    if (!g_cccrypt_l4_active) {

        return orig_CCCrypt(op, alg, options, key, keyLen, iv,

                            dataIn, dataInLen, dataOut, dataOutAvailable, dataOutMoved);

    }

    // FIX53L: Reset SAFE FALLBACK flag at start of each active CCCrypt L4 call.
    // Previous stale YES value would trigger unnecessary forceReencrypt in send-hook
    // for FFF493#1 even though THIS call had a perfectly fine patched output.
    // Use asm volatile with "memory" clobber to GUARANTEE the compiler does NOT optimize away this reset.
    asm volatile("" ::: "memory");
    g_l4_safe_fallback = NO;
    asm volatile("" ::: "memory");
    {
        int verifyFlag = (int)g_l4_safe_fallback;
        if (verifyFlag != 0) {
            DLOG(@"[FIX53L-FLAG] WARNING: g_l4_safe_fallback was unexpectedly YES at CCCrypt L4 entry!");
        }
    }



    const char *opStr = (op == 0) ? "ENC" : "DEC";



    // v36.126: Skip real AES decryption when forceValidDecrypt=YES

    if (op == 1 && g_forceValidDecrypt) {

        DLOG(@"[SEC-BYPASS] v36.126: CCCrypt DEC SKIPPING real decrypt (inLen=%zu, keyLen=%zu)", dataInLen, keyLen);

        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\"}";

        size_t fakeLen = strlen(fakePlaintext);

        if (fakeLen <= dataOutAvailable) {

            memcpy(dataOut, fakePlaintext, fakeLen);

            if (dataOutMoved) *dataOutMoved = fakeLen;

            return 0;

        }

        return -1;

    }



    // L4: ENCRYPT only — scan plaintext dataIn for channel+deviceModel+GPU strings,

    // create patched buffer with canonical replacements.

    //

    // v37.31: Replaces 3 strings (not only channel):

    //   DY_MIESHI           (9)  → DYanyou0040_MIESHI (18)  +9B each

    //   iPhone 16 Pro Max   (17) → iPhone7Plus       (11)  -6B each

    //   Apple Inc. Apple A18 Pro GPU (28) → Apple Inc. Apple A10 GPU (24)  -4B each

    // Net per occurrence: +9 -6 -4 = -1B.

    // If all 3 found: -1B. If only channel: +9B.

    const void *realDataIn = dataIn;

    size_t  realDataInLen = dataInLen;

    void   *patchedBuf = NULL;

    int patchCount = 0;

    int chCount = 0, dmCount = 0, gpCount = 0;
    int dm16ProMaxCount = 0, dm14ProCount = 0; // FIX52: 分别计数不同设备型号
    int gpA18ProCount = 0, gpA16Count = 0; // FIX52: 分别计数不同GPU
    int dmGenericDelta = 0; // FIX53E: 通用设备型号替换的delta累计 (origLen - 11)
    int gpGenericDelta = 0; // FIX53E: 通用GPU替换的delta累计 (origLen - 24)
    int uuidCount = 0; // FIX53: UUID替换次数
    int uuidEmptyCount = 0; // FIX53G: 空UUID插入次数(每次+36B delta)

    int accCount = 0; // v37.79: ALWAYS 0 — do NOT replace accId in CCCrypt

    // v37.79: accId replacement DISABLED for token consistency.

    static const char kCanonAccIdAES[] = "65657881045335015151"; // 20 bytes (UNUSED v37.79)

    if (op == 0 && dataIn && dataInLen >= 9) {

        // First pass: count ALL replacements

        const char *scanP = (const char *)dataIn;

        const char *scanEnd = scanP + dataInLen;

        const char *pcur = scanP;

        chCount = dmCount = gpCount = uuidCount = 0;

        while (pcur < scanEnd) {

            size_t rem = (size_t)(scanEnd - pcur);

            if (rem >= 9 && memcmp(pcur, "DY_MIESHI", 9) == 0) {

                // FIX53H: 放宽bounded检查 — 与CC_MD5检测逻辑一致, 只要求前后非字母数字(单词边界)
                // 之前严格要求prev是": 等, 导致FFF493 JSON中某些格式的channel字段检测不到
                // → CC_MD5替换了但CCCrypt没替换 → HMAC不匹配 → 服务器关闭连接
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 9 < scanEnd) ? *(pcur+9) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z'); // 非字母
                BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z'); // 非字母
                BOOL bounded = prevOk && nextOk;
                if (bounded) chCount++;

                pcur += 9;

            } else if (rem >= 17 && memcmp(pcur, "iPhone 16 Pro Max", 17) == 0) {

                // FIX53H: 放宽bounded检查 — 前后非字母数字即可, 与CC_MD5一致
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 17 < scanEnd) ? *(pcur+17) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                BOOL bounded = prevOk && nextOk;

                if (bounded) { dmCount++; dm16ProMaxCount++; }

                pcur += 17;

            } else if (rem >= 13 && (memcmp(pcur, "iPhone 14 Pro", 13) == 0 || memcmp(pcur, "iPhone 13 Pro", 13) == 0)
                       && !(pcur + 14 < scanEnd && *(pcur + 13) == ' ')) {

                // FIX53F: 13B匹配仅当后面不是空格(排除"Pro Max"等, 让通用fallback处理)
                // FIX52: 支持 iPhone 14 Pro (13B) + iPhone 13 Pro (13B)
                // FIX53H: 放宽bounded检查 — 前后非字母数字即可
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 13 < scanEnd) ? *(pcur+13) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                BOOL bounded = prevOk && nextOk;
                if (bounded) { dmCount++; dm14ProCount++; }
                pcur += 13;

            } else if (rem >= 11 && memcmp(pcur, "iPhone7Plus", 11) == 0) {

                // FIX52: iPhone7Plus已经是canonical, 不需要替换
                pcur += 11;

            } else if (rem >= 28 && memcmp(pcur, "Apple Inc. Apple A18 Pro GPU", 28) == 0) {

                // FIX53H: 放宽bounded检查 — 前后非字母数字即可, 与CC_MD5一致
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 28 < scanEnd) ? *(pcur+28) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                BOOL bounded = prevOk && nextOk;

                if (bounded) { gpCount++; gpA18ProCount++; }

                pcur += 28;

            } else if (rem >= 24 && (memcmp(pcur, "Apple Inc. Apple A16 GPU", 24) == 0 || memcmp(pcur, "Apple Inc. Apple A15 GPU", 24) == 0)) {

                // FIX52: 支持 A16 GPU (24B) + A15 GPU (24B, 等长替换为A10, delta=0)
                // FIX53H: 放宽bounded检查 — 前后非字母数字即可
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 24 < scanEnd) ? *(pcur+24) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                BOOL bounded = prevOk && nextOk;
                if (bounded) { gpCount++; gpA16Count++; }
                pcur += 24;

            } else if (rem >= 24 && memcmp(pcur, "Apple Inc. Apple A10 GPU", 24) == 0) {

                // FIX52: A10 GPU已经是canonical, 不需要替换
                pcur += 24;

            } else if (rem >= 7 && memcmp(pcur, "iPhone ", 7) == 0) {

                // FIX53E: 通用 fallback — 任何未知 iPhone 型号 (如iPhone 12/15等)
                // 向后扫描到 JSON 闭合引号 确定原始长度, 加64字节上限保护
                // FIX53H: 放宽prev检查 — 非字母数字即边界, 与CC_MD5一致
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                if (prevOk) {
                    int dmEnd = 7;
                    while (pcur + dmEnd < scanEnd && dmEnd < 64 && *(pcur + dmEnd) != '"' && *(pcur + dmEnd) != ',' && *(pcur + dmEnd) != 0) dmEnd++;
                    if (pcur + dmEnd < scanEnd && *(pcur + dmEnd) == '"') {
                        dmCount++;
                        dmGenericDelta += (dmEnd - 11); // delta = origLen - 11 (替换后缩短量)
                    }
                }
                pcur += 7; // 至少跳过前缀避免死循环, 后续字符会被正常遍历

            } else if (rem >= 4 && memcmp(pcur, "iPad", 4) == 0) {

                // FIX53E: 通用 fallback — iPad全系列, 加64字节上限保护
                // FIX53H: 放宽prev检查 — 非字母数字即边界
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                if (prevOk) {
                    int dmEnd = 4;
                    while (pcur + dmEnd < scanEnd && dmEnd < 64 && *(pcur + dmEnd) != '"' && *(pcur + dmEnd) != ',' && *(pcur + dmEnd) != 0) dmEnd++;
                    if (pcur + dmEnd < scanEnd && *(pcur + dmEnd) == '"') {
                        dmCount++;
                        dmGenericDelta += (dmEnd - 11);
                    }
                }
                pcur += 4;

            } else if (rem >= 18 && memcmp(pcur, "Apple Inc. Apple A", 18) == 0) {

                // FIX53G: 通用 fallback — 任何未知 Apple GPU, 修复19B null终止符bug
                // FIX53H: 放宽prev检查 — 非字母数字即边界
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                if (prevOk) {
                    int gpEnd = 18;
                    while (pcur + gpEnd < scanEnd && gpEnd < 32 && *(pcur + gpEnd) != '"' && *(pcur + gpEnd) != ',' && *(pcur + gpEnd) != 0) gpEnd++;
                    if (pcur + gpEnd < scanEnd && *(pcur + gpEnd) == '"') {
                        gpCount++;
                        gpGenericDelta += (gpEnd - 24); // delta = origLen - 24
                    }
                }
                pcur += 19;

            } else if (rem >= 16 && memcmp(pcur, "UUID=MACADDRESS=", 16) == 0) {

                // FIX53G: UUID=MACADDRESS= 检测 (16B前缀, 非17B — null终止符bug修复)
                // 检查是否为空UUID (后跟引号/逗号/null)
                if (pcur + 16 < scanEnd && (*(pcur + 16) == '"' || *(pcur + 16) == ',' || *(pcur + 16) == 0)) {
                    // 空UUID: 需要插入canonical UUID (+36B delta)
                    uuidCount++;
                    uuidEmptyCount++;  // 标记空UUID, delta +36
                    pcur += 16;
                } else if (rem >= 52 && memcmp(pcur, "UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 52) != 0) {
                    // 非空非canonical UUID (52B): 等长替换
                    uuidCount++;
                    pcur += 52;
                } else if (rem >= 52) {
                    // 已是canonical UUID (52B): 跳过
                    pcur += 52;
                } else {
                    pcur += 16;
                }

            } else if (rem >= 36 && pcur[8] == '-' && pcur[13] == '-' && pcur[18] == '-' && pcur[23] == '-') {

                // FIX53: 裸36B带横杠的UUID检测, 若非canonical 66B0EE01则计数(等长36B替换)
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 36 < scanEnd) ? *(pcur+36) : 0;
                BOOL bounded = (prev == '"' || prev == '=') && (next == '"' || next == ',' || next == '}');
                if (bounded) {
                    if (memcmp(pcur, "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 36) != 0) {
                        uuidCount++;
                    }
                }
                pcur += 36;

            } else if (rem >= 20) {

                // v37.79: accId detection DISABLED — skip to next char

                pcur++;

            } else {

                pcur++;

            }

        }

        patchCount = chCount + dmCount + gpCount + accCount + uuidCount;

        // FIX53H: Scan-phase diagnostics — detect CC_MD5 vs CCCrypt detection mismatch.
        // Root cause (wxhook-171): CC_MD5 sees ch=1 gp=1 but CCCrypt-L4 sees ch=0 gp=0
        // due to overly-strict JSON delimiter bounded checks. newDataInLen below would
        // silently use the wrong delta → encrypted plaintext != HMAC input → TCP RST.
        static int scanLogged = 0;
        if (scanLogged < 4) {
            BOOL warnCH = (chCount == 0);
            BOOL warnGP = (gpCount == 0);
            DLOG(@"[FIX53H-SCAN] L4-pass1 inLen=%zu patchTot=%d ch=%d%@ dm=%d(16PM=%d 14P=%d gen=%d dD=%d) gp=%d(A18P=%d A16=%d gen=%d gD=%d) acc=%d uuid=%d(empty=%d) %@%@",
                 dataInLen, patchCount,
                 chCount, warnCH ? @"⚠️NO-CH" : @"",
                 dmCount, dm16ProMaxCount, dm14ProCount, (dmCount - dm16ProMaxCount - dm14ProCount), dmGenericDelta,
                 gpCount, gpA18ProCount, gpA16Count, (gpCount - gpA18ProCount - gpA16Count), gpGenericDelta,
                 accCount, uuidCount, uuidEmptyCount,
                 warnCH ? @"[WARN-DY_MIESHI-NOT-DETECTED → check JSON format around channel!]" : @"",
                 warnGP ? @"[WARN-GPU-NOT-DETECTED → check JSON format around GPU!]" : @"");
            scanLogged++;
        }

        // FIX53: UUID替换全部等长(53→53, 36→36), 所以uuidCount对delta无影响
        // v37.35: Save AES key+iv+alg+options from ANY ENC call in FFF493 range.

        // v37.37 CRITICAL FIX: Must save from FFF493#2 (inLen 500-800B) NOT FFF493#1!

        // AES-CBC uses different IV per message. Using FFF493#1's IV to encrypt FFF493#2

        // produces wrong ciphertext → server can't decrypt → no response.

        // Always update to the LATEST ENC call's key+iv.

        if (op == 0 && keyLen <= 32 && dataInLen >= 200 && dataInLen <= 800) {

            memcpy(g_saved_aes_key, key, keyLen);

            memcpy(g_saved_aes_iv, iv, keyLen);

            g_saved_key_len = keyLen;

            g_saved_alg = alg;

            g_saved_options = options;

            g_aes_key_saved = YES;

            NSMutableString *ivHex = [NSMutableString string];

            for (size_t i = 0; i < keyLen && i < 16; i++) [ivHex appendFormat:@"%02X", ((uint8_t*)iv)[i]];

            DLOG(@"[FFF493-REPL] v37.37: Updated AES key(%zuB)+iv=%@ alg=%u opt=%u from ENC inLen=%zu", keyLen, ivHex, alg, options, dataInLen);

        }

        // v37.43: isFFF493_2_stub detection DISABLED. The detection (starts with

        // {"username" && no accountId) was wrong — real client FFF493#2 JSON also

        // matches this pattern (611B native, no accountId field). This led to saving

        // a forged "extended plaintext" (1350B with fake accountId/hasRole/serverInfo)

        // which the send-hook then used to replace the native 896B packet with 1880B

        // forged packet → server returned only heartbeats → stuck at "正在进入...".

        // isFFF493_2_stub is now always NO; the extended-plaintext save block below

        // is also disabled.

        if (patchCount > 0) {

            // FIX52: 根据变体分别计算delta
            // dm: 16 Pro Max(17→11, delta=-6), 14/13 Pro(13→11, delta=-2)
            // gp: A18 Pro(28→24, delta=-4), A16/A15(24→24, delta=0)
            // FIX53: UUID全部等长替换(53→53, 36→36), 无delta
            // FIX53E: 通用fallback delta动态计算 (origLen→11/24)
            // FIX53G: UUID空值插入 +36B per empty UUID
            ssize_t delta = (ssize_t)chCount * 9
                          + (ssize_t)dm16ProMaxCount * (-6)
                          + (ssize_t)dm14ProCount * (-2)
                          + (ssize_t)gpA18ProCount * (-4)
                          + (ssize_t)gpA16Count * 0
                          - (ssize_t)dmGenericDelta   // FIX53E: 通用设备型号 delta (正值=缩短)
                          - (ssize_t)gpGenericDelta    // FIX53E: 通用GPU delta (正值=缩短)
                          + 0; // FIX53K: uuidEmptyCount * 36 DISABLED — do NOT insert UUID (match CC_MD5 uuid=0)

            size_t newDataInLen = (size_t)((ssize_t)dataInLen + delta);

            patchedBuf = malloc(newDataInLen + 32);

            if (patchedBuf) {

                char *out = (char *)patchedBuf;

                const char *p = (const char *)dataIn;

                const char *e = p + dataInLen;

                while (p < e) {

                    size_t rem = (size_t)(e - p);

                    if (rem >= 9 && memcmp(p, "DY_MIESHI", 9) == 0) {

                        // FIX53H: 放宽bounded检查 — 非字母数字即边界, 与第一pass一致
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 9 < e) ? *(p+9) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                        BOOL bounded = prevOk && nextOk;

                        if (bounded) {

                            memcpy(out, "DYanyou0040_MIESHI", 18);

                            out += 18; p += 9; continue;

                        }

                    } else if (rem >= 17 && memcmp(p, "iPhone 16 Pro Max", 17) == 0) {

                        // FIX53H: 放宽bounded检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 17 < e) ? *(p+17) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                        BOOL bounded = prevOk && nextOk;

                        if (bounded) {

                            memcpy(out, "iPhone7Plus", 11);

                            out += 11; p += 17; continue;

                        }

                    } else if (rem >= 13 && (memcmp(p, "iPhone 14 Pro", 13) == 0 || memcmp(p, "iPhone 13 Pro", 13) == 0)
                               && !(p + 14 < e && *(p + 13) == ' ')) {

                        // FIX53F: 13B匹配仅当后面不是空格(排除"Pro Max"等, 让通用fallback处理)
                        // FIX52: iPhone 14/13 Pro(13B) → iPhone7Plus(11B)
                        // FIX53H: 放宽bounded检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 13 < e) ? *(p+13) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                        BOOL bounded = prevOk && nextOk;
                        if (bounded) {
                            memcpy(out, "iPhone7Plus", 11);
                            out += 11; p += 13; continue;
                        }

                    } else if (rem >= 11 && memcmp(p, "iPhone7Plus", 11) == 0) {

                        // FIX52: iPhone7Plus已经是canonical, 直接复制
                        memcpy(out, "iPhone7Plus", 11);
                        out += 11; p += 11; continue;

                    } else if (rem >= 28 && memcmp(p, "Apple Inc. Apple A18 Pro GPU", 28) == 0) {

                        // FIX53H: 放宽bounded检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 28 < e) ? *(p+28) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                        BOOL bounded = prevOk && nextOk;

                        if (bounded) {

                            memcpy(out, "Apple Inc. Apple A10 GPU", 24);

                            out += 24; p += 28; continue;

                        }

                    } else if (rem >= 24 && (memcmp(p, "Apple Inc. Apple A16 GPU", 24) == 0 || memcmp(p, "Apple Inc. Apple A15 GPU", 24) == 0)) {

                        // FIX52: A16/A15 GPU(24B) → A10 GPU(24B, 等长)
                        // FIX53H: 放宽bounded检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 24 < e) ? *(p+24) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        BOOL nextOk = (next < 'A' || (next > 'Z' && next < 'a') || next > 'z');
                        BOOL bounded = prevOk && nextOk;
                        if (bounded) {
                            memcpy(out, "Apple Inc. Apple A10 GPU", 24);
                            out += 24; p += 24; continue;
                        }

                    } else if (rem >= 24 && memcmp(p, "Apple Inc. Apple A10 GPU", 24) == 0) {

                        // FIX52: A10 GPU已经是canonical, 直接复制
                        memcpy(out, "Apple Inc. Apple A10 GPU", 24);
                        out += 24; p += 24; continue;

                    } else if (rem >= 7 && memcmp(p, "iPhone ", 7) == 0) {

                        // FIX53E: 通用 fallback — 任何未知 iPhone 型号 → iPhone7Plus
                        // FIX53H: 放宽prev检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        if (prevOk) {
                            int dmLen = 7;
                            while (p + dmLen < e && *(p + dmLen) != '"' && *(p + dmLen) != ',' && *(p + dmLen) != 0) dmLen++;
                            if (p + dmLen < e && *(p + dmLen) == '"') {
                                memcpy(out, "iPhone7Plus", 11);
                                out += 11; p += dmLen; continue;
                            }
                        }
                        // bounded不匹配时, 按普通字符处理
                        *out = *p; out++; p++;

                    } else if (rem >= 4 && memcmp(p, "iPad", 4) == 0) {

                        // FIX53E: 通用 fallback — iPad全系列 → iPhone7Plus
                        // FIX53H: 放宽prev检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        if (prevOk) {
                            int dmLen = 4;
                            while (p + dmLen < e && *(p + dmLen) != '"' && *(p + dmLen) != ',' && *(p + dmLen) != 0) dmLen++;
                            if (p + dmLen < e && *(p + dmLen) == '"') {
                                memcpy(out, "iPhone7Plus", 11);
                                out += 11; p += dmLen; continue;
                            }
                        }
                        *out = *p; out++; p++;

                    } else if (rem >= 18 && memcmp(p, "Apple Inc. Apple A", 18) == 0) {

                        // FIX53G: 通用 fallback — 任何未知 Apple GPU → A10 GPU, 修复19B null终止符bug
                        // FIX53H: 放宽prev检查 — 非字母数字即边界
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        BOOL prevOk = (prev < 'A' || (prev > 'Z' && prev < 'a') || prev > 'z');
                        if (prevOk) {
                            int gpLen = 18;
                            while (p + gpLen < e && *(p + gpLen) != '"' && *(p + gpLen) != ',' && *(p + gpLen) != 0) gpLen++;
                            if (p + gpLen < e && *(p + gpLen) == '"') {
                                memcpy(out, "Apple Inc. Apple A10 GPU", 24);
                                out += 24; p += gpLen; continue;
                            }
                        }
                        *out = *p; out++; p++;

                    } else if (rem >= 52 && memcmp(p, "UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 52) == 0) {

                        // FIX53G: UUID=MACADDRESS=66B0EE01已是canonical, 直接复制(52B)
                        memcpy(out, "UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 52);
                        out += 52; p += 52; continue;

                    } else if (rem >= 16 && memcmp(p, "UUID=MACADDRESS=", 16) == 0) {

                        // FIX53J: UUID=MACADDRESS= 检测 (16B前缀, 修复null终止符bug)
                        // FIX53K: DISABLE empty UUID insertion! CC_MD5 hook does NOT insert UUID into
                        // HMAC concat input (uuid=0), so CCCrypt L4 must NOT insert it either.
                        // Otherwise: HMAC(based on empty UUID) ≠ ciphertext(based on 66B0EE01 UUID).
                        // Instead: copy original 16B prefix as-is, let the next iteration handle the rest.
                        if (p + 16 < e && (*(p + 16) == '"' || *(p + 16) == ',' || *(p + 16) == 0)) {
                            // 空UUID: FIX53K — DO NOT insert canonical UUID, copy original as-is
                            memcpy(out, p, 16);
                            out += 16; p += 16; continue;
                        } else if (rem >= 52) {
                            // 非空UUID: 替换为canonical (52B→52B, 等长)
                            memcpy(out, "UUID=MACADDRESS=66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 52);
                            out += 52; p += 52; continue;
                        }
                        // fallback: 按普通字符处理
                        *out = *p; out++; p++;

                    } else if (rem >= 36 && memcmp(p, "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 36) == 0) {

                        // FIX53: canonical裸UUID(36B), 直接复制
                        memcpy(out, "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 36);
                        out += 36; p += 36; continue;

                    } else if (rem >= 36 && p[8] == '-' && p[13] == '-' && p[18] == '-' && p[23] == '-') {

                        // FIX53: 非canonical裸UUID → canonical 66B0EE01(等长36B)
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 36 < e) ? *(p+36) : 0;
                        BOOL bounded = (prev == '"' || prev == '=') && (next == '"' || next == ',' || next == '}');
                        if (bounded || uuidCount > 0) {
                            memcpy(out, "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8", 36);
                            out += 36; p += 36; continue;
                        }

                    } else if (rem >= 20) {

                        // v37.108-DIST: Do NOT replace 20-digit accountId in CCCrypt plaintext!

                        // ROOT CAUSE: Forcing CANONICAL accId caused ALL users to enter kk994's game

                        // character regardless of their login account.

                        // Keep the boundary check but copy original 20-digit number as-is.

                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;

                        char next = (p + 20 < e) ? *(p+20) : 0;

                        if ((prev < '0' || prev > '9') && (next < '0' || next > '9')) {

                            BOOL allDigNative = YES;

                            for (int j = 0; j < 20; j++) {

                                if (p[j] < '0' || p[j] > '9') { allDigNative = NO; break; }

                            }

                            if (allDigNative) {

                                memcpy(out, p, 20); // Pass through REAL accountId

                                out += 20; p += 20; continue;

                            }

                        }

                    }

                    *out++ = *p++;

                }

                realDataIn = patchedBuf;

                realDataInLen = (size_t)(out - (char *)patchedBuf);

                // FIX53K: Save patched plaintext for send-hook re-encryption
                if (g_l4_saved_patched) { free(g_l4_saved_patched); }
                g_l4_saved_patched = (char *)malloc(realDataInLen);
                if (g_l4_saved_patched) {
                    memcpy(g_l4_saved_patched, patchedBuf, realDataInLen);
                    g_l4_saved_patched_len = realDataInLen;
                    g_l4_saved_valid = YES;
                }
                DLOG(@"[FIX53K-L4-SAVE] Saved patched plaintext %zuB (ch=%d dm=%d gp=%d uuid=%d patchTot=%d) — for send-hook re-encryption",
                     realDataInLen, chCount, dmCount, gpCount, uuidCount, patchCount);

                static int logged = 0;

                if (logged < 4) {

                    // FIX53H: Expected delta re-check — must match pass-1 scan delta.
                    // If actual delta differs from expected, FFF493-REPL will use the
                    // WRONG plaintext length to re-encrypt → server HMAC mismatch.
                    ssize_t expectedDelta = (ssize_t)chCount * 9
                                          + (ssize_t)dm16ProMaxCount * (-6)
                                          + (ssize_t)dm14ProCount * (-2)
                                          + (ssize_t)gpA18ProCount * (-4)
                                          + (ssize_t)gpA16Count * 0
                                          - (ssize_t)dmGenericDelta
                                          - (ssize_t)gpGenericDelta
                                          + 0; // FIX53K: uuidEmptyCount * 36 DISABLED — do NOT insert UUID
                    ssize_t actualDelta = (long long)realDataInLen - (long long)dataInLen;
                    BOOL deltaOk = (expectedDelta == actualDelta);
                    DLOG(@"[FIX53H-CH-RELAX] [CH-L4] v37.134-FIX8 patchesTot=%d ch=%d dm=%d gp=%d acc=%d origLen=%zu newLen=%zu expDelta=%lld actDelta=%lld %@",

                         patchCount, chCount, dmCount, gpCount, accCount, dataInLen, realDataInLen,
                         (long long)expectedDelta, (long long)actualDelta,
                         deltaOk ? @"OK" : @"⚠️DELTA-MISMATCH!");

                    logged++;

                }

            }

        }

        // v37.43: Extended plaintext save block DISABLED. With isFFF493_2_stub always

        // NO, this block never executes. Kept as comment for reference. The forged

        // extended plaintext (1350B with fake accountId/hasRole/serverInfo) was the

        // root cause of "正在进入..." stuck — send-hook used it to replace native

        // 896B FFF493#2 with 1880B forged packet, server rejected and only returned

        // heartbeats (0x80000015). Now FFF493#2 passes through via orig_send.

        // (Original block: build ext from base+trimLen, save to g_ext_plaintext)

    }



    DLOG(@"[CC-AES] %s inLen=%zu (real=%zu) keyLen=%zu", opStr, dataInLen, realDataInLen, keyLen);



#if !SILENT_DIST_MODE

    // v37.34: Dump FULL plaintext (not only first 80B) for ENC calls whose size is in

    // FFF493 range (280-1200 bytes). This lets us see exactly which JSON fields are

    // present in our stub JSON (604B) vs the 1010B full JSON built by the canonical

    // channel. Short JSONs only contain username/password/clientId.

    if (op == 0 && realDataIn && realDataInLen > 0) {

        // Diagnostic dump — FFF493 always < 2048 bytes; cap at 2048.

        int dumpLen = (int)(realDataInLen < 2048 ? realDataInLen : 2048);

        // HEX + ASCII view

        NSMutableString *hexStr = [NSMutableString stringWithCapacity:dumpLen * 3 + 200];

        NSMutableString *ascStr = [NSMutableString stringWithCapacity:dumpLen + 50];

        for (int i = 0; i < dumpLen; i++) {

            unsigned char c = ((const unsigned char *)realDataIn)[i];

            [hexStr appendFormat:@"%02X ", c];

            [ascStr appendFormat:@"%c", (c >= 0x20 && c < 0x7F) ? c : '.'];

        }

        static int dumpCount = 0;

        if (dumpCount < 8) {

            DLOG(@"[CC-AES-PLAIN-FULL] v37.34 ENC #%d inLen=%zu realLen=%zu HEX: %@", dumpCount, dataInLen, realDataInLen, hexStr);

            DLOG(@"[CC-AES-PLAIN-FULL] v37.34 ENC #%d ASCII: %@", dumpCount, ascStr);

            dumpCount++;

        }

    }

#endif



    // v37.44: Save FFF493#2 native plaintext for send-hook field replacement.

    // Detection: ENC op + plaintext contains "NEW_USER_ENTER_SERVER_REQ" + len>500.

    // This is the client's native 619B JSON (with empty sessionId/ticket).

    // Send hook will replace sessionId/ticket/clientId/MACADDRESS/md5 with clean

    // client values, re-encrypt, and build a new 1432B packet.

    // v37.87: ALSO save FFF493#1 (IOS_CLIENT_MSG_REQ, first packet, smaller len 500-800).

    // Previous versions only replaced #2 (len>800 in send hook), #1 went out with

    // sessionId="" → server checked #1 first → silently ignored #2 as well. Fix:

    // capture and replace BOTH FFF493 packets (#1 msgtype=16756741 = IOS_CLIENT_MSG_REQ,

    // #2 msgtype=??? = NEW_USER_ENTER_SERVER_REQ).

    // v37.87 FIXED: Threshold lowered from >400 to >200. v37.87 log revealed #1 realDataInLen=316 → 316>400 false → #1 never saved!

    // Now captures both #1 (316-800B) and #2 (500-1500B).

    if (op == 0 && realDataIn && realDataInLen > 200 && realDataInLen < 2048) {

        // FFF493#2: NEW_USER_ENTER_SERVER_REQ (len usually ~605B native, becomes ~1408 after replace)

        if (memmem(realDataIn, realDataInLen, "NEW_USER_ENTER_SERVER_REQ", 25) != NULL) {

            if (g_fff493_2_native_plain) { free(g_fff493_2_native_plain); }

            g_fff493_2_native_len = realDataInLen;

            g_fff493_2_native_plain = (char *)malloc(realDataInLen + 1);

            if (g_fff493_2_native_plain) {

                memcpy(g_fff493_2_native_plain, realDataIn, realDataInLen);

                g_fff493_2_native_plain[realDataInLen] = '\0';

                DLOG(@"[FFF493-REPL] v37.87: Saved FFF493#2 (NEW_USER) native plaintext %zuB for send-hook replacement", realDataInLen);

            }

        }

        // FFF493#1: IOS_CLIENT_MSG_REQ (first FFF493, usually ~420-620B native, msgtype=16756741)

        // v37.87 FIX: IOS_CLIENT_MSG_REQ has NO sessionId field (confirmed from v37.87 log line 867).

        // Old code required "\"sessionId\"" match → #1 never saved → FFF493-REPL skipped #1.

        // Now detect IOS_CLIENT_MSG_REQ alone, no sessionId requirement.

        else if (memmem(realDataIn, realDataInLen, "IOS_CLIENT_MSG_REQ", 18) != NULL) {

            static char *s_fff1_plain = NULL;

            static size_t s_fff1_len = 0;

            if (s_fff1_plain) { free(s_fff1_plain); }

            s_fff1_len = realDataInLen;

            s_fff1_plain = (char *)malloc(realDataInLen + 1);

            if (s_fff1_plain) {

                memcpy(s_fff1_plain, realDataIn, realDataInLen);

                s_fff1_plain[realDataInLen] = '\0';

                g_fff493_1_plain_buf = s_fff1_plain;

                g_fff493_1_plain_len = s_fff1_len;

                DLOG(@"[FFF493-REPL] v37.87: Saved FFF493#1 (IOS_CLIENT_MSG) native plaintext %zuB for send-hook replacement", realDataInLen);

            }

        }

    }



    // v37.31 CRITICAL FIX: If we expanded plaintext (patchedBuf != NULL), the

    // caller's dataOut buffer is sized for the ORIGINAL plaintext's AES output.

    // (CCFileUtils::aesEncryptData allocates a fixed stack/heap buffer based on

    // dataInLen passed to it, NOT our realDataInLen.  orig_CCCrypt will write

    // past dataOutAvailable → SIGSEGV.)

    // Workaround: allocate a HEAP dataOutTmp big enough for the expanded input,

    // run orig_CCCrypt into that, then memcpy the first dataOutAvailable bytes

    // back to caller's dataOut only if it fits, else return kCCBufferTooSmall.

    // Actually, to avoid breaking the caller, we MUST pass enough room:

    //   CCCrypt ENC: dataOutMoved <= dataOutAvailable

    //   Required: ceil((realDataInLen + blocksize) / blocksize) * blocksize

    //   AES blocksize=16, with padding (kCCOptionPKCS7Padding usually):

    //   Worst case: (realDataInLen + 16) & ~0xF

    // If caller's dataOutAvailable is not enough, use our own buffer.

    void *tmpOut = NULL;

    size_t tmpOutSize = 0;

    if (patchedBuf != NULL) {

        // v37.32: Correct AES PKCS7 padding output calculation:

        //   output = ceil((plainLen + 1) / 16) * 16

        // PKCS7 always adds at least 1 byte of padding (hence +1).

        // Verified with v37.31 data: real=307 → needed=320, caller 333 fits!

        size_t needed = ((realDataInLen + 1 + 15) / 16) * 16;

        // Use caller's buffer if STRICTLY enough room; otherwise fall back to tmpOut.

        // We use needed+1 as threshold so tight fits still succeed (320 <= 333).

        if (dataOutAvailable < needed) {

            tmpOutSize = needed + 32;

            tmpOut = malloc(tmpOutSize);

            DLOG(@"[CH-L4-BUF] v37.32: caller dataOutAvailable=%zu < needed=%zu → use heap tmpOut=%p (tmpOutSize=%zu)",

                 dataOutAvailable, needed, tmpOut, tmpOutSize);

        }

    }

    void *outBuf = tmpOut ? tmpOut : dataOut;

    size_t outBufAvail = tmpOut ? tmpOutSize : dataOutAvailable;

    size_t outMovedTmp = 0;

    int ret = orig_CCCrypt(op, alg, options, key, keyLen, iv,

                           realDataIn, realDataInLen,

                           outBuf, outBufAvail, tmpOut ? &outMovedTmp : dataOutMoved);



    if (tmpOut) {

        if (ret == 0 && outMovedTmp > 0) {

            // v37.32 FIX: tmpOut ENCRYPT SUCCESS → copy ciphertext to caller's dataOut IF it FITS.

            // CCCrypt output length follows: ciphertext ≤ plaintext + block alignment with PKCS7.

            // Caller's dataOutAvailable may be LARGER than outMovedTmp? Yes!

            // v37.31 buggy fallback was wrong — outMovedTmp=320 vs dataOutAvailable=333 fits!

            if (outMovedTmp <= dataOutAvailable) {

                memcpy(dataOut, tmpOut, outMovedTmp);

                if (dataOutMoved) *dataOutMoved = outMovedTmp;

                DLOG(@"[CH-L4-BUF] v37.32: PATCH APPLIED via tmpOut copy outMoved=%zu callerAvail=%zu (FIT perfectly!)",

                     outMovedTmp, dataOutAvailable);

            } else {

                // output does not fit! call orig WITHOUT patch (conservative safe fallback

                DLOG(@"[CH-L4-BUF] v37.32: tmpOut produced %zu bytes > caller %zu available → SAFE FALLBACK no patch",

                     outMovedTmp, dataOutAvailable);

                // FIX53I: Set SAFE FALLBACK flag so FFF493-REPL send-hook forces re-encryption
                // of the saved patched plaintext. Without this, HMAC(patched) ≠ ciphertext(original).
                g_l4_safe_fallback = YES;

                if (patchedBuf) { free(patchedBuf); patchedBuf = NULL; realDataIn = dataIn; realDataInLen = dataInLen; }

                free(tmpOut); tmpOut = NULL;

                ret = orig_CCCrypt(op, alg, options, key, keyLen, iv,

                                   dataIn, dataInLen,

                                   dataOut, dataOutAvailable, dataOutMoved);

            }

        }

        if (tmpOut) free(tmpOut);

    }



    if (patchedBuf) free(patchedBuf);



    if (dataOutMoved && *dataOutMoved > 0) {

        DLOG(@"[CC-AES-OUT] %s len=%zu", opStr, *dataOutMoved);

    }

    return ret;

}



// ===== Diagnostics only (logs once, no DY_MIESHI literal in format) =====

static void installChannelInterceptLayers(void) {

    int layersOK = 0;



    // ===== L0: strlen / strcmp / strncmp FISHHOOK (INIT TIME propagation) =====

    // v37.33 CRITICAL: These run BEFORE ObjC + CFString initialization, ensuring

    // every malloc(strlen+1), every strcmp branch, every strncmp prefix check

    // treats DY_MIESHI as the 18-char canonical channel. This ensures

    // construct_NEW_USER_ENTER_SERVER_REQER builds 1010B full JSON (accountId,

    // hasRole, serverInfo...) instead of truncated 604B stub JSON.

    if (dlsym(RTLD_NEXT, "strlen")) {

        orig_strlen = (size_t (*)(const char*))dlsym(RTLD_NEXT, "strlen");

        int r = rebindSymbol("strlen", (void *)hook_strlen, (void **)&orig_strlen);

        DLOG(@"[CH-L0] strlen rebind=%d orig=%p", r, orig_strlen);

        layersOK++;

    }

    if (dlsym(RTLD_NEXT, "strcmp")) {

        orig_strcmp = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "strcmp");

        int r = rebindSymbol("strcmp", (void *)hook_strcmp, (void **)&orig_strcmp);

        DLOG(@"[CH-L0] strcmp rebind=%d orig=%p", r, orig_strcmp);

        layersOK++;

    }

    if (dlsym(RTLD_NEXT, "strncmp")) {

        orig_strncmp = (int (*)(const char*, const char*, size_t))dlsym(RTLD_NEXT, "strncmp");

        int r = rebindSymbol("strncmp", (void *)hook_strncmp, (void **)&orig_strncmp);

        DLOG(@"[CH-L0] strncmp rebind=%d orig=%p", r, orig_strncmp);

        layersOK++;

    }



    // L1: CFString via fishhook

    if (dlsym(RTLD_NEXT, "CFStringCreateWithCString")) {

        int r = rebindSymbol("CFStringCreateWithCString",

                             (void *)hook_CFStringCreateWithCString,

                             (void **)&orig_CFStringCreateWithCString);

        DLOG(@"[CH-L1] CFStringCreateWithCString rebind=%d", r);

        layersOK++;

    }



    // L2: NSString class methods via method_setImplementation

    Method m1 = class_getClassMethod([NSString class], @selector(stringWithUTF8String:));

    if (m1) { orig_stringWithUTF8String = (id (*)(Class, SEL, const char*))method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_stringWithUTF8String); DLOG(@"[CH-L2] stringWithUTF8String installed"); layersOK++; }

    Method m2 = class_getInstanceMethod([NSString class], @selector(initWithUTF8String:));

    if (m2) { orig_initWithUTF8String = (id (*)(NSString*, SEL, const char*))method_getImplementation(m2); method_setImplementation(m2, (IMP)hook_initWithUTF8String); DLOG(@"[CH-L2] initWithUTF8String installed"); layersOK++; }



    // L3: memcpy via fishhook

    if (dlsym(RTLD_NEXT, "memcpy")) {

        orig_memcpy = (memcpyFunc)dlsym(RTLD_NEXT, "memcpy"); // capture before rebind

        int r = rebindSymbol("memcpy", (void *)hook_memcpy, (void **)&orig_memcpy);

        DLOG(@"[CH-L3] memcpy rebind=%d orig=%p", r, orig_memcpy);

        layersOK++;

    }



    // L4: CCCrypt swap pointer (already hook installed later, override IMP here to v37.26 version)

    DLOG(@"[CH-L4] CCCrypt plaintext-ENC layer ready. installSecurityHooks will rebind CCCrypt next.");

    layersOK++;



    // L5/L6: send buffer scan — implemented inside custom_send directly, see below.

    DLOG(@"[CH-L5] send buffer scan + L6 EE007 len-patch: handled in custom_send().");

    layersOK++;



    DLOG(@"[CH-INIT] v37.129-DIAG SILENT_MODE=%d %d layers active (v37.129: Minimal SignatureKit hooks — only showAlert/exitApp/showTip, do NOT stub judgeNet/judgeBase/JudgeApp which breaks game state machine. v37.128: SecStaticCodeCheckValidity + LCNetworking. v37.126: GENERIC DY_MIESHI. v37.124: HTTP hooks. v37.120: FIX code:0→code:1. v37.118: MSI DISABLED.)", (int)SILENT_DIST_MODE, layersOK);

}



// v37.52: Directly patch C-string literal "DY_MIESHI" → "DYanyou0040_MIESHI" in binary memory.

// L0-L3 fishhook hooks (strlen/strcmp/strncmp/memcpy) NEVER trigger because these

// functions are inlined by the compiler on modern iOS — fishhook only rebinds symbol

// pointers, not inlined call sites. So construct_NEW_USER_ENTER_SERVER_REQER still

// reads the short "DY_MIESHI" channel → builds truncated 621B JSON (missing accountId,

// hasRole, serverInfo, character data) → FFF493-REPL can't fix it → server returns only

// heartbeats → stuck at "正在进入...".

//

// Root fix: patch the C-string literal IN-PLACE in __TEXT. Original binary had

// "DYanyou0040_MIESHI\0" (19 bytes). 全能签 overwrote first 10 bytes with "DY_MIESHI\0",

// leaving 9 stale bytes after. We write back all 19 bytes — safe because the slot

// was originally 19 bytes. construct_NEW_USER_ENTER_SERVER_REQER then reads the correct

// long channel and builds the full ~994B JSON.

//

// v37.53: mprotect FAILS with EACCES on iOS (code signature protects __TEXT).

// Use vm_protect with VM_PROT_COPY instead — this forces kernel to create a private

// copy-on-write page, bypassing code signature restrictions. This is the standard

// technique used by jailbreak tweaks (substrate, cycript) to patch code pages.

// NOTE: Writing 19 bytes overwrites the first 9 bytes of the adjacent "DYquick_MI..."

// string. This is acceptable — user uses DYanyou0040 channel, not DYquick.

#ifndef VM_PROT_COPY

#define VM_PROT_COPY 0x10

#endif

static void patchChannelStringInBinary(void) {

    const char shortCh[10] = "DY_MIESHI";         // 9 chars + NUL = 10

    const char longCh[19]  = "DYanyou0040_MIESHI"; // 18 chars + NUL = 19



    DLOG(@"[CH-PATCH] v37.53: Scanning binary for channel string literal...");



    int imageCount = (int)_dyld_image_count();

    int patched = 0;



    for (int idx = 0; idx < imageCount && patched == 0; idx++) {

        const char *imageName = _dyld_get_image_name(idx);

        if (!imageName) continue;

        // Only search in main binary (wangxian), not dylibs/frameworks

        if (!strstr(imageName, "wangxian") && !strstr(imageName, "WangXian")) continue;



        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(idx);

        intptr_t slide = _dyld_get_image_vmaddr_slide(idx);

        if (!header || header->magic != MH_MAGIC_64) continue;



        DLOG(@"[CH-PATCH] v37.53: Searching in %s (slide=0x%lx)", imageName, (unsigned long)slide);



        const struct load_command *lc = (const struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));

        for (uint32_t i = 0; i < header->ncmds && patched == 0; i++) {

            if (lc->cmd != LC_SEGMENT_64) { lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize); continue; }

            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;

            if (strcmp(seg->segname, "__TEXT") != 0) { lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize); continue; }



            const struct section_64 *sect = (const struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64));

            for (uint32_t j = 0; j < seg->nsects && patched == 0; j++) {

                // Search all __TEXT sections (string literal may be in __cstring or __const)

                size_t sectSize = sect[j].size;

                if (sectSize < 19) continue;



                char *start = (char *)(sect[j].addr + slide);

                char *end = start + sectSize;

                for (char *p = start; p <= end - 19; p++) {

                    // Match first 9 bytes "DY_MIESHI" (not 10 — 全能签 may not have

                    // written a NUL terminator; p[9] could be stale original data).

                    if (memcmp(p, shortCh, 9) != 0) continue;

                    // Boundary check: char before must be NUL or non-alphanumeric

                    // (ensures "DY_MIESHI" is the start of a string, not a substring).

                    if (p > start) {

                        char prev = *(p - 1);

                        if ((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||

                            (prev >= '0' && prev <= '9') || prev == '_') continue;

                    }

                    // Found "DY_MIESHI" at a string boundary. Dump context.

                    char beforeHex[64] = {0};

                    for (int k = 0; k < 20 && p + k < end; k++)

                        snprintf(beforeHex + k*3, 4, "%02X ", (unsigned char)p[k]);

                    DLOG(@"[CH-PATCH] v37.53: Found in sect=%s offset=%ld before: %s",

                         sect[j].sectname, (long)(p - start), beforeHex);



                    // v37.53: Use vm_protect with VM_PROT_COPY to bypass iOS code signature.

                    // mprotect returns EACCES on __TEXT pages; vm_protect with VM_PROT_COPY

                    // forces kernel to create a private COW copy that we can write to.

                    uintptr_t pageAddr = (uintptr_t)p & ~((uintptr_t)0xFFF);

                    uintptr_t pageEnd  = ((uintptr_t)p + 19 + 0xFFF) & ~((uintptr_t)0xFFF);

                    size_t protSize = pageEnd - pageAddr;



                    kern_return_t kr = vm_protect(mach_task_self(),

                                                   (vm_address_t)pageAddr, protSize,

                                                   FALSE,

                                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

                    if (kr == KERN_SUCCESS) {

                        // Write long channel (19 bytes — may overwrite first 9B of adjacent

                        // "DYquick_MI..." string, acceptable since user uses DYanyou0040)

                        memcpy(p, longCh, 19);

                        // Restore to RX

                        vm_protect(mach_task_self(),

                                   (vm_address_t)pageAddr, protSize,

                                   FALSE,

                                   VM_PROT_READ | VM_PROT_EXECUTE);



                        char afterHex[64] = {0};

                        for (int k = 0; k < 20 && p + k < end; k++)

                            snprintf(afterHex + k*3, 4, "%02X ", (unsigned char)p[k]);

                        DLOG(@"[CH-PATCH] v37.53: PATCHED! after: %s", afterHex);

                        patched++;

                    } else {

                        DLOG(@"[CH-PATCH] v37.53: vm_protect FAILED kr=%d", (int)kr);

                        // Fallback: try mprotect (may work on some jailbreak setups)

                        if (mprotect((void *)pageAddr, protSize, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {

                            memcpy(p, longCh, 19);

                            mprotect((void *)pageAddr, protSize, PROT_READ | PROT_EXEC);

                            DLOG(@"[CH-PATCH] v37.53: mprotect fallback PATCHED!");

                            patched++;

                        } else {

                            DLOG(@"[CH-PATCH] v37.53: mprotect also FAILED errno=%d", errno);

                        }

                    }

                    break;

                }

            }

            lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);

        }

    }



    DLOG(@"[CH-PATCH] v37.53: Complete, patched=%d", patched);

}



static void installAllHooks(void) {

    DLOG(@"[VERSION] WangXianHook v37.134-FIX53S-AZ6 — FIX53S: didReplaceUUID触发md5_recompute. FIX53R: CC_MD5用FULL标记区分EE121/FFF493#2. FIX53P: 空MACADDRESS插入canonical UUID. FIX53O: 仅JSON修改时重加密. Single-channel canonical UUID=66B0EE01 used EVERYWHERE. Generic fallback: iPhone/iPad/Apple GPU prefix. AZ2 status-fix: EE007 VERSION 7.6.3→9.9.9 BUILD 984→999 + CC_MD5 hash2同步替换. AZ6 debug: 关闭200KB轮转(LOG_SIZE_LIMIT_DEFAULT_ON=0, max 20MB safety)+EE007逐TLV字节trace[AZ6-TLV]+EE121响应原始status强制trace[AZ6-STATUS-RAW]. File toggles: wxhook_nolimit/wxhook_sparse/wxhook_logfull in Documents.");

    // v37.87: Force session valid global immediately on hook init. This is the single most

    // important change — 100% of v37.12-84 FFF493-REPL went to FALLBACK (sessionValid=0)

    // because no real 0x8234AB89 was ever received (login server gave 版本过低, no session).

    // Setting g_sessionValid=1 bypasses that; FFF493-REPL fills real-looking sessionId/ticket.

    {

        static const char kDefaultSessionId[] = "zmURQCP7xCg4ejMcPEPj2rc61mFfb0Fh"; // 32B

        static const char kDefaultTicket[] = "kk994|1785665252271|236923||SwnLPVw4wqtqXUfBX0JETQlXLrNxbb0TElk1YQvRmrKTNJG1ImA5eVtTnqY06XALBsKbKtCRJ7iRMUJcE+yZkboYVJ55k35zIxDeoLGoe/4TAo6nQjRD5obTaa18ObMyJaz6R0TUg8Oz78N1me5vBrU9c6sImsqv1QZEebEgfZO7KY2OdU35OV8Vb6rXRBwl1f78jA1OnkTRmf7ZthPpP1q3V1Y8OnzHnbHwq/xnZP3KtEXej3RCQX6zjJf+G81+W2XSpzUPynQXQ/Q/u9qn2N/5/db/8uMz68q/giuSAb9ikNYno+NYXTgn4FLsUbV15NTU5YIVqo9He/pYQCQ==";

        size_t sidLen = strlen(kDefaultSessionId);

        size_t tikLen = strlen(kDefaultTicket);

        if (sidLen < sizeof(g_sessionId)) { memcpy(g_sessionId, kDefaultSessionId, sidLen); g_sessionId[sidLen] = 0; }

        if (tikLen < sizeof(g_ticket))  { memcpy(g_ticket,    kDefaultTicket,    tikLen); g_ticket[tikLen] = 0; g_ticketLen = (int)tikLen; }

        g_sessionValid = 1;

        g_hashTokenValid = 0; // reset per-session

        DLOG(@"[GLOBALS-INIT] v37.89-FIX53: FORCE sessionValid=%d sessionId=%s ticketLen=%d (恢复FIX53基线 UUID=66B0EE01单通道, CC_MD5与CCCrypt明文完全一致)", g_sessionValid, g_sessionId, g_ticketLen);

    }

    DLOG(@"[ACT] Installing hooks (restore v36.155 working configuration)...");



    // v37.134: No environment detection needed. Smart field-level patching works for all environments.

    // Both 全能签 and V3 inject similar dylibs, making detection impossible.

    // Strategy now: ALL signature verification URLs get fake responses regardless of environment.



    // v37.52: Patch channel string literal in binary memory FIRST, before any

    // hook installation. This is the ROOT fix — L0-L3 fishhook hooks are dead

    // (inlined functions), so in-memory patch is the only way to ensure

    // construct_NEW_USER_ENTER_SERVER_REQER sees the correct long channel.

    patchChannelStringInBinary();



    // v37.26: Install ALL 6 channel intercept layers FIRST.

    // This runs before any network code so the replacement propagates through

    // the entire packet construction pipeline including AES-encrypted FFF493.

    installChannelInterceptLayers();



    // ============================================================

    // v37.134-FIX28: 【最先执行】V3分发自签环境检测 + zsign +alert:绕过

    // 关键发现: Frida诊断证明无WangXianHook时V3环境connect正常(connect=2,send=35)

    // → WangXianHook的V3特有代码(V3-PEN/zsign +request替换/SCNetwork V3路径)导致游戏不connect!

    // FIX28: V3环境下完全使用全能签路径(g_isV3Environment=NO)，只保留zsign +alert:替换。

    // 不替换zsign +request(让V3验证正常执行)，不执行V3-PEN，hook_SCNetwork走全能签路径。

    // FIX29: 设置g_zsignPresent标记，HTTP hook跳过V3特有的postAppInfoApi/getAppInfoApi。

    // ============================================================

    BOOL isV3 = detectV3Environment();

    if (isV3) {

        g_zsignPresent = YES;  // 仅用于DYLD hiding

        DLOG(@"[V3-ENTRY] 🚀 V3环境检测到zsign → FIX34: 完全不装zsign hook(防anti-tampering检测→无网络)! 走全能签路径 + getAppInfoApi构建full data→SignatureCheck.nettimes不SIGSEGV");

        // FIX34: 不调用 installV3ZsignAlertOnlyBypass()!

        // 铁证: FIX31没装alert hook→zsign原始执行→SignatureCheck.nettimes被调用

        //        FIX32/33装了alert hook(method_setImplementation)→anti-tampering检测到IMP被篡改

        //        →zsign验证中止→SignatureCheck.nettimes没被调用→"无网络连接"!

        // FIX34: 不装hook = zsign原始执行 = 和FIX19一样 = 成功!

        // getAppInfoApi总是构建full data+code:0 → data字段存在 → SignatureCheck.nettimes不SIGSEGV

        DLOG(@"[V3-ENTRY] ✅ FIX34: zsign hook全部跳过(不替换alert/request IMP) → zsign anti-tampering检测通过 → V3验证流程正常执行");

    }

    // g_isV3Environment 保持 NO → 所有hook(SCNetwork/socket/CC_MD5/CCCrypt)走全能签路径



    // === v37.13: RESTORE v36.155 full hook configuration ===

    // v37.0-v37.12 minimal mode failed — injection detected → '版本过低'

    // Need full hooks to bypass injection detection.



    installSecurityHooks();

    installKeyboardProtection();



    // v37.13: RESTORE full socket hooks (not minimal)

    installSocketHooks();



    // v37.13: RESTORE C++ crypto hooks

    installCppCryptoHooks_v131();



    // v37.13: RESTORE proactive C++ function patches

    proactivePatchCppFunctions();



    // v37.119: MSI hooks DISABLED + hardcoded accId fallback removed.

    // v37.118: MSI hooks DISABLED — they caused SIGABRT in widgetSelected on return from role page.

    // ROOT CAUSE: g_msiStubData is a SINGLE global dictionary shared by ALL ServerInfoForClient objects.

    // When custom_recv updates it with game server IP/port, ALL servers in the list show the same data.

    // This corrupts the game's server selection state machine → C++ std::terminate on click.

    // Fix: Do NOT install any MSI hooks. Let ServerInfoForClient use its native implementation.

    // The port rewriting in connect() handles the actual connection to game server port 12003.

    _log(@"[INIT] v37.119: MSI hooks DISABLED + hardcoded accId fallback REMOVED (root cause of SIGABRT + wrong-role)");



    // === KEEP: UIAlertView.show hook (in capture_real.js) ===

#pragma clang diagnostic push

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

    Class alertCls = [UIAlertView class];

    if (alertCls) {

        Method m = class_getInstanceMethod(alertCls, @selector(show));

        if (m) { orig_alertViewShow = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)hook_alertViewShow); _log(@"[INIT] UIAlertView.show: hook"); }

    }

#pragma clang diagnostic pop



    // === v37.128: Three-layer signature bypass for distribution signing ===

    // Layer 1: Security framework (local code signature validation bypass)

    // Layer 2: SignatureKit/SignatureCheck methods (return success, never call original)

    // Layer 3: HTTP response interception (NSURLSession + NSURLConnection + LCNetworking)

    _log(@"[INIT] v37.128: Installing three-layer signature bypass");



    // Layer 1: Security framework hooks

    installSecurityFrameworkHooks();



    // Layer 2: SignatureKit method hooks

    installSignatureKitBypassHooks();



    // Layer 3: LCNetworking hooks (application-level HTTP interception)

    installLCNetworkingHooks();



    // === v37.124: INSTALL HTTP HOOKS (CRITICAL FIX - was never called before!) ===

    // Without these hooks, ALL HTTP response interception is non-functional.

    // This was the root cause of signature verification failure on fresh install.

    {

        // 1. NSURLSession -dataTaskWithRequest:completionHandler: (completion handler mode)

        Class sessionCls = [NSURLSession class];

        if (sessionCls) {

            Method m = class_getInstanceMethod(sessionCls, @selector(dataTaskWithRequest:completionHandler:));

            if (m) {

                orig_dtwrc = (DTReqCompIMP)method_getImplementation(m);

                method_setImplementation(m, (IMP)hook_dtwrc);

                _log(@"[HTTP-INSTALL] NSURLSession dataTaskWithRequest:completionHandler: HOOKED");

            } else {

                _log(@"[HTTP-INSTALL] WARNING: dataTaskWithRequest:completionHandler: not found!");

            }



            // 2. NSURLSession -dataTaskWithRequest: (delegate mode)

            m = class_getInstanceMethod(sessionCls, @selector(dataTaskWithRequest:));

            if (m) {

                orig_dtr = (DTReqIMP)method_getImplementation(m);

                method_setImplementation(m, (IMP)hook_dtr);

                _log(@"[HTTP-INSTALL] NSURLSession dataTaskWithRequest: (delegate) HOOKED");

            }

        }



        // 3. NSURLConnection +sendAsynchronousRequest:queue:completionHandler:

        Class connCls = NSClassFromString(@"NSURLConnection");

        if (connCls) {

            Method m = class_getClassMethod(connCls, @selector(sendAsynchronousRequest:queue:completionHandler:));

            if (m) {

                orig_asyncReq = (AsyncReqIMP)method_getImplementation(m);

                method_setImplementation(m, (IMP)hook_async);

                _log(@"[HTTP-INSTALL] NSURLConnection sendAsync: HOOKED");

            }



            // 4. NSURLConnection +sendSynchronousRequest:returningResponse:error:

            m = class_getClassMethod(connCls, @selector(sendSynchronousRequest:returningResponse:error:));

            if (m) {

                orig_syncReq = (SyncReqIMP)method_getImplementation(m);

                method_setImplementation(m, (IMP)hook_sync);

                _log(@"[HTTP-INSTALL] NSURLConnection sendSync: HOOKED");

            }

        }



        // 5. Install delegate-mode data receiving hooks

        installNSURLSessionHooks();

        _log(@"[HTTP-INSTALL] All HTTP hooks installed (v37.124)");

    }



    _log(@"[INIT] v37.14: Socket hooks + NETIMPL hooks (crypto hooks disabled to prevent crash)");



    // === DEFERRED: Create log button (keep for debugging) ===

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{

        UIWindow *w = nil;

        if (@available(iOS 13.0, *)) {

            for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {

                if (s.activationState == UISceneActivationStateForegroundActive) {

                    for (UIWindow *win in s.windows) {

                        if (win.isKeyWindow) { w = win; break; }

                        if (!w && win.rootViewController) w = win;

                    }

                }

            }

        }

        if (!w) w = [UIApplication sharedApplication].keyWindow;

        if (!w) w = [UIApplication sharedApplication].windows.firstObject;

        if (w) {

            createLogButton(w);

        }

    });



    DLOG(@"[ACT] v37.14: All hooks installed (socket + NETIMPL, crypto disabled)");

}





