// AZwangxian Tweak.x
// 反检测hook + 全量日志捕捉 + 悬浮窗导出
// 版本: 1.0.0

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>

// ============================================================================
// 日志系统
// ============================================================================

static NSString *logFilePath(void) {
    NSString *dir = @"/var/mobile/Library/AZwangxian";
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir]) {
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    NSString *dateStr = [[NSDate date] description];
    dateStr = [dateStr stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    dateStr = [dateStr stringByReplacingOccurrencesOfString:@":" withString:@"-"];
    return [NSString stringWithFormat:@"%@/azwangxian_%@.log", dir, dateStr];
}

static NSString *currentLogPath = nil;
static NSLock *logLock = nil;

static void az_init_log(void) {
    @synchronized([NSObject class]) {
        if (!logLock) {
            logLock = [[NSLock alloc] init];
            currentLogPath = logFilePath();
            // 启动横幅
            NSString *banner = [NSString stringWithFormat:
                @"\n========== AZwangxian Tweak v1.0.0 ==========\n"
                @"启动时间: %@\n进程: %@\n日志路径: %@\n"
                @"=============================================\n",
                [NSDate date],
                [[NSBundle mainBundle] bundleIdentifier],
                currentLogPath];
            [banner writeToFile:currentLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"AZHOOK %@", banner);
        }
    }
}

static void az_log(NSString *level, NSString *tag, NSString *fmt, ...) {
    if (!currentLogPath) az_init_log();
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *line = [NSString stringWithFormat:@"[%@] [%@] [%@] %@\n",
        [NSDate date], level, tag, msg];
    [logLock lock];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:currentLogPath];
    if (!fh) {
        [line writeToFile:currentLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:currentLogPath];
    } else {
        [fh seekToEndOfFile];
    }
    if (fh) {
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
    [logLock unlock];
    NSLog(@"AZHOOK [%@][%@] %@", level, tag, msg);
}

#define AZ_INFO(tag, ...)  az_log(@"INFO",  tag, __VA_ARGS__)
#define AZ_WARN(tag, ...)  az_log(@"WARN",  tag, __VA_ARGS__)
#define AZ_ERROR(tag, ...) az_log(@"ERROR", tag, __VA_ARGS__)
#define AZ_HOOK(tag, ...)  az_log(@"HOOK",  tag, __VA_ARGS__)
#define AZ_NET(tag, ...)   az_log(@"NET",   tag, __VA_ARGS__)
#define AZ_BYPASS(tag,...) az_log(@"BYPASS",tag, __VA_ARGS__)

// hex dump辅助
static NSString *az_hexdump(const void *data, size_t len) {
    if (!data || len == 0) return @"<empty>";
    size_t limit = len > 256 ? 256 : len;
    const uint8_t *p = (const uint8_t *)data;
    NSMutableString *hex = [NSMutableString string];
    NSMutableString *ascii = [NSMutableString string];
    for (size_t i = 0; i < limit; i++) {
        [hex appendFormat:@"%02x ", p[i]];
        if (p[i] >= 0x20 && p[i] <= 0x7e) [ascii appendFormat:@"%c", p[i]];
        else [ascii appendFormat:@"."];
        if ((i + 1) % 16 == 0) {
            [hex appendString:@" "];
            [hex appendString:ascii];
            [hex appendString:@"\n"];
            [ascii setString:@""];
        }
    }
    if (ascii.length > 0) {
        [hex appendString:@" "];
        [hex appendString:ascii];
    }
    if (len > 256) [hex appendFormat:@"\n... (共%zu字节)", len];
    return hex;
}

// ============================================================================
// 1. 反调试hook
// ============================================================================

// 1.1 ptrace PT_DENY_ATTACH
static int (*orig_ptrace)(int, pid_t, caddr_t, int) = NULL;
static int az_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31 /* PT_DENY_ATTACH */) {
        AZ_BYPASS(@"ptrace", @"PT_DENY_ATTACH 拦截返回0");
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

// 1.2 sysctl 检测调试器 (P_TRACED flag)
static int (*orig_sysctl)(int *, u_int, char *, size_t *, void *, size_t) = NULL;
static int az_sysctl(int *name, u_int namelen, char *oldp, size_t *oldlenp,
                     void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    // CTL_KERN / KERN_PROC / KERN_PROC_PID
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && oldp && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info->kp_proc.p_flag & P_TRACED) {
            info->kp_proc.p_flag &= ~P_TRACED;
            AZ_BYPASS(@"sysctl", @"清除 P_TRACED 标志");
        }
    }
    return ret;
}

// 1.3 task_for_pid
static kern_return_t (*orig_task_for_pid)(mach_port_t, pid_t, mach_port_t *) = NULL;
static kern_return_t az_task_for_pid(mach_port_t target, pid_t pid, mach_port_t *t) {
    AZ_BYPASS(@"task_for_pid", @"拦截 pid=%d 返回KERN_FAILURE", pid);
    if (t) *t = MACH_PORT_NULL;
    return KERN_FAILURE;
}

// 1.4 fork/vfork 检测
static pid_t (*orig_fork)(void) = NULL;
static pid_t az_fork(void) {
    AZ_BYPASS(@"fork", @"拦截fork返回-1");
    return -1;
}

// ============================================================================
// 2. 越狱/Frida 痕迹检测hook
// ============================================================================

static NSArray *blacklistKeywords(void) {
    static NSArray *kw = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        kw = @[
            @"frida", @"gum", @"agent", @"gadget", @"dopamine", @"systemhook",
            @"preboot", @"substrate", @"mobilesubstitute", @"substitute",
            @"ellekit", @"tweakloader", @"libhooker", @"cydia", @"sileo",
            @"zebra", @"trollstore", @"checkra1n", @"basebin", @"procursus",
            @"backrun", @"back_run", @"常驻", @"libmonhuawei",
            @"libwjhook", @"libinjector"
        ];
    });
    return kw;
}

static bool is_blacklisted(NSString *str) {
    if (!str) return false;
    NSString *lower = [str lowercaseString];
    for (NSString *kw in blacklistKeywords()) {
        if ([lower containsString:kw]) return true;
    }
    return false;
}

// 2.1 open/stat/access/lstat/fopen 路径检测
static bool path_is_blacklisted(const char *path) {
    if (!path) return false;
    return is_blacklisted([NSString stringWithUTF8String:path]);
}

// open hook
static int (*orig_open)(const char *, int, ...) = NULL;
static int az_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }
    if (path_is_blacklisted(path)) {
        AZ_BYPASS(@"open", @"拦截路径: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_open(path, flags, mode);
}

// access hook
static int (*orig_access)(const char *, int) = NULL;
static int az_access(const char *path, int mode) {
    if (path_is_blacklisted(path)) {
        AZ_BYPASS(@"access", @"拦截路径: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

// stat hook
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int az_stat(const char *path, struct stat *buf) {
    if (path_is_blacklisted(path)) {
        AZ_BYPASS(@"stat", @"拦截路径: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, buf);
}

// lstat hook
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int az_lstat(const char *path, struct stat *buf) {
    if (path_is_blacklisted(path)) {
        AZ_BYPASS(@"lstat", @"拦截路径: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, buf);
}

// fopen hook
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *az_fopen(const char *path, const char *mode) {
    if (path_is_blacklisted(path)) {
        AZ_BYPASS(@"fopen", @"拦截路径: %s", path);
        return NULL;
    }
    return orig_fopen(path, mode);
}

// 2.2 dladdr hook (检测Frida库)
typedef int (*dladdr_t)(const void *, Dl_info *);
static dladdr_t orig_dladdr = NULL;
static int az_dladdr_depth = 0;
static int az_dladdr(const void *addr, Dl_info *info) {
    // 重入保护
    @synchronized([NSObject class]) {
        az_dladdr_depth++;
        if (az_dladdr_depth > 1) {
            az_dladdr_depth--;
            return orig_dladdr(addr, info);
        }
    }
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname) {
        NSString *path = [NSString stringWithUTF8String:info->dli_fname];
        if (is_blacklisted(path)) {
            AZ_BYPASS(@"dladdr", @"检测到敏感库: %@", path);
            // 清除信息返回0
            memset(info, 0, sizeof(Dl_info));
            az_dladdr_depth--;
            return 0;
        }
    }
    @synchronized([NSObject class]) {
        az_dladdr_depth--;
    }
    return ret;
}

// 2.3 dlopen hook
static void *(*orig_dlopen)(const char *, int) = NULL;
static void *az_dlopen(const char *path, int mode) {
    if (path && path_is_blacklisted(path)) {
        AZ_BYPASS(@"dlopen", @"拦截加载: %s", path);
        return NULL;
    }
    return orig_dlopen(path, mode);
}

// 2.4 _dyld_get_image_name hook
static const char *(*orig_dyld_image_name)(uint32_t) = NULL;
static const char *az_dyld_image_name(uint32_t index) {
    const char *name = orig_dyld_image_name(index);
    if (name && path_is_blacklisted(name)) {
        // 返回一个空路径替代
        AZ_BYPASS(@"dyld", @"隐藏镜像: %s @index=%u", name, index);
        return "";
    }
    return name;
}

// ============================================================================
// 3. CC_MD5 密钥替换hook
// ============================================================================

static unsigned char *replace_key_in_md5_input(unsigned char *data, unsigned long len) {
    // 在签名输入中替换 kk994624 → 33333333
    if (!data || len < 8) return NULL;
    const unsigned char src[] = {'k','k','9','9','4','6','2','4'};
    const unsigned char dst[] = {'3','3','3','3','3','3','3','3'};
    int count = 0;
    for (unsigned long i = 0; i + 8 <= len; i++) {
        bool match = true;
        for (int j = 0; j < 8; j++) {
            if (data[i+j] != src[j]) { match = false; break; }
        }
        if (match) {
            for (int j = 0; j < 8; j++) data[i+j] = dst[j];
            count++;
            i += 7;
        }
    }
    if (count > 0) {
        AZ_BYPASS(@"CC_MD5", @"KEY-REPLACE 替换kk994624→33333333 共%d处 长度=%lu", count, len);
    }
    return data;
}

static unsigned char *(*orig_CC_MD5)(const void *, CC_LONG, unsigned char *) = NULL;
static unsigned char *az_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    // 检查是否包含 kk 关键字，若包含则替换密钥
    static unsigned char *buf = NULL;
    static size_t bufSize = 0;
    @synchronized([NSObject class]) {
        if (len > 0 && len < 8192) {
            // 检查是否含kk
            const unsigned char *p = (const unsigned char *)data;
            bool hasKk = false;
            for (CC_LONG i = 0; i + 8 <= len; i++) {
                if (p[i]=='k' && p[i+1]=='k') { hasKk = true; break; }
            }
            if (hasKk) {
                if (bufSize < len) {
                    buf = realloc(buf, len);
                    bufSize = len;
                }
                if (buf) {
                    memcpy(buf, data, len);
                    replace_key_in_md5_input(buf, len);
                    AZ_HOOK(@"CC_MD5", @"签名输入含kk 长度=%u 前缀:\n%@",
                        len, az_hexdump(buf, len > 256 ? 256 : len));
                    data = buf;
                }
            }
        }
    }
    unsigned char *ret = orig_CC_MD5(data, len, md);
    return ret;
}

// ============================================================================
// 4. close 系统调用hook (选服处理)
// ============================================================================

static NSArray *blockCloseSources(void) {
    return @[
        @"doConnectServer", @"HandleSelectServer", @"connectFail",
        @"connectToServer", @"connectToGateway", @"heartbeat",
        @"tick", @"drawScene", @"quitFromServer", @"quitFromGateway"
    ];
}

static NSArray *normalCloseSources(void) {
    return @[
        @"widgetSelected", @"handleSelectServer", @"doLogin",
        @"handleTouch", @"ccTouch", @"touchesBegan", @"touchesEnded"
    ];
}

static int (*orig_close)(int) = NULL;
static int az_close(int fd) {
    if (fd <= 2) return orig_close(fd);
    // 获取调用者符号
    void *ret = __builtin_return_address(0);
    Dl_info info;
    bool known = dladdr(ret, &info);
    NSString *sym = known && info.dli_sname ? [NSString stringWithUTF8String:info.dli_sname] : @"";
    // 判断来源
    bool isBlock = false;
    for (NSString *s in blockCloseSources()) {
        if ([sym containsString:s]) { isBlock = true; break; }
    }
    if (isBlock) {
        AZ_BYPASS(@"close", @"BLOCK源 fd=%d [%@] 阻止关闭", fd, sym);
        errno = EBADF;
        return -1;
    }
    return orig_close(fd);
}

// ============================================================================
// 5. exit/signal 防闪退hook
// ============================================================================

static void (*orig_exit)(int) = NULL;
static void az_exit(int status) {
    AZ_WARN(@"exit", @"拦截exit status=%d", status);
    // 不真正退出
}

static int (*orig_kill)(pid_t, int) = NULL;
static int az_kill(pid_t pid, int sig) {
    if (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM) {
        AZ_BYPASS(@"kill", @"拦截信号 pid=%d sig=%d", pid, sig);
        return 0;
    }
    return orig_kill(pid, sig);
}

// ============================================================================
// 6. 悬浮窗 + 日志导出
// ============================================================================

@interface AZFloatingWindow : UIWindow
@property (nonatomic, strong) UIButton *logButton;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, assign) BOOL logViewVisible;
+ (instancetype)sharedWindow;
- (void)showFloatingButton;
- (void)toggleLogView;
- (void)exportLog;
@end

@implementation AZFloatingWindow

+ (instancetype)sharedWindow {
    static AZFloatingWindow *win = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        UIScreen *screen = [UIScreen mainScreen];
        win = [[AZFloatingWindow alloc] initWithFrame:screen.bounds];
        win.windowLevel = UIWindowLevelAlert + 100;
        win.backgroundColor = [UIColor clearColor];
        win.hidden = NO;
        [win showFloatingButton];
        AZ_INFO(@"UI", @"悬浮窗已创建 frame=%@", NSStringFromCGRect(win.frame));
    });
    return win;
}

- (void)showFloatingButton {
    if (_logButton) return;
    _logButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _logButton.frame = CGRectMake([UIScreen mainScreen].bounds.size.width - 80, 100, 60, 60);
    _logButton.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:0.85];
    _logButton.layer.cornerRadius = 30;
    _logButton.clipsToBounds = YES;
    _logButton.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [_logButton setTitle:@"日志" forState:UIControlStateNormal];
    [_logButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [_logButton addTarget:self action:@selector(toggleLogView)
        forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:_logButton];
    // 添加拖动手势
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
        initWithTarget:self action:@selector(handlePan:)];
    [_logButton addGestureRecognizer:pan];
    // 添加长按导出
    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc]
        initWithTarget:self action:@selector(handleLongPress:)];
    longPress.minimumPressDuration = 1.0;
    [_logButton addGestureRecognizer:longPress];
    AZ_INFO(@"UI", @"悬浮按钮已显示");
}

- (void)handlePan:(UIPanGestureRecognizer *)ges {
    CGPoint translation = [ges translationInView:self];
    _logButton.center = CGPointMake(_logButton.center.x + translation.x,
                                     _logButton.center.y + translation.y);
    [ges setTranslation:CGPointZero inView:self];
    // 边界限制
    CGRect frame = self.bounds;
    CGFloat x = _logButton.center.x;
    CGFloat y = _logButton.center.y;
    if (x < 30) x = 30;
    if (x > frame.size.width - 30) x = frame.size.width - 30;
    if (y < 30) y = 30;
    if (y > frame.size.height - 30) y = frame.size.height - 30;
    _logButton.center = CGPointMake(x, y);
}

- (void)handleLongPress:(UILongPressGestureRecognizer *)ges {
    if (ges.state == UIGestureRecognizerStateBegan) {
        [self exportLog];
    }
}

- (void)toggleLogView {
    if (_logViewVisible) {
        [_logView removeFromSuperview];
        _logView = nil;
        _logViewVisible = NO;
        return;
    }
    _logViewVisible = YES;
    CGRect screen = [UIScreen mainScreen].bounds;
    _logView = [[UITextView alloc]
        initWithFrame:CGRectMake(10, 60, screen.size.width - 20, screen.size.height - 130)];
    _logView.backgroundColor = [UIColor colorWithRed:0 green:0 blue:0 alpha:0.85];
    _logView.textColor = [UIColor colorWithRed:0.7 green:1.0 blue:0.7 alpha:1.0];
    _logView.font = [UIFont fontWithName:@"Menlo" size:9];
    _logView.editable = NO;
    _logView.layer.cornerRadius = 8;
    // 加载日志
    NSString *content = [NSString stringWithContentsOfFile:currentLogPath
        encoding:NSUTF8StringEncoding error:nil];
    if (!content) content = @"<无日志>";
    _logView.text = content;
    // 滚到底部
    NSRange range = NSMakeRange(content.length - 1, 1);
    [_logView scrollRangeToVisible:range];
    // 添加工具栏
    UIToolbar *toolbar = [[UIToolbar alloc]
        initWithFrame:CGRectMake(0, screen.size.height - 70, screen.size.width, 50)];
    toolbar.items = @[
        [[UIBarButtonItem alloc] initWithTitle:@"导出" style:UIBarButtonItemStylePlain
            target:self action:@selector(exportLog)],
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
            target:nil action:nil],
        [[UIBarButtonItem alloc] initWithTitle:@"清空" style:UIBarButtonItemStylePlain
            target:self action:@selector(clearLog)],
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
            target:nil action:nil],
        [[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStylePlain
            target:self action:@selector(toggleLogView)]
    ];
    [self addSubview:_logView];
    [self addSubview:toolbar];
    AZ_INFO(@"UI", @"显示日志视图 行数=%lu", (unsigned long)content.length);
}

- (void)clearLog {
    [@"" writeToFile:currentLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    _logView.text = @"";
    AZ_INFO(@"UI", @"日志已清空");
}

- (void)exportLog {
    if (!currentLogPath) return;
    NSURL *url = [NSURL fileURLWithPath:currentLogPath];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *root = [self rootViewController];
        if (!root) {
            // 尝试拿到keyWindow的vc
            UIWindow *keyWin = nil;
            for (UIWindow *w in [UIApplication sharedApplication].windows) {
                if (!w.hidden && w != self) { keyWin = w; break; }
            }
            root = keyWin.rootViewController;
        }
        if (!root) {
            AZ_ERROR(@"UI", @"无法获取rootViewController");
            return;
        }
        UIActivityViewController *avc = [[UIActivityViewController alloc]
            initWithActivityItems:@[url]
            applicationActivities:nil];
        [root presentViewController:avc animated:YES completion:^{
            AZ_INFO(@"UI", @"分享面板已展示");
        }];
    });
}

@end

// ============================================================================
// 7. NSLog hook (捕捉系统日志)
// ============================================================================

static void (*orig_NSLog)(NSString *, ...) = NULL;
static void az_NSLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    AZ_HOOK(@"NSLog", @"%@", msg);
}

// ============================================================================
// 8. MSHookFunction 注册
// ============================================================================

static void az_install_hooks(void) {
    AZ_INFO(@"INIT", @"开始安装hooks...");
    
    // 1. 反调试
    MSHookFunction((void *)ptrace, (void *)az_ptrace, (void **)&orig_ptrace);
    MSHookFunction((void *)sysctl, (void *)az_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)task_for_pid, (void *)az_task_for_pid, (void **)&orig_task_for_pid);
    MSHookFunction((void *)fork, (void *)az_fork, (void **)&orig_fork);
    AZ_INFO(@"INIT", @"反调试hook安装完成");
    
    // 2. 越狱/Frida检测
    MSHookFunction((void *)open, (void *)az_open, (void **)&orig_open);
    MSHookFunction((void *)access, (void *)az_access, (void **)&orig_access);
    MSHookFunction((void *)stat, (void *)az_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)az_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)fopen, (void *)az_fopen, (void **)&orig_fopen);
    MSHookFunction((void *)dlopen, (void *)az_dlopen, (void **)&orig_dlopen);
    MSHookFunction((void *)dladdr, (void *)az_dladdr, (void **)&orig_dladdr);
    MSHookFunction((void *)_dyld_get_image_name, (void *)az_dyld_image_name, (void **)&orig_dyld_image_name);
    AZ_INFO(@"INIT", @"越狱/Frida检测hook安装完成");
    
    // 3. CC_MD5
    MSHookFunction((void *)CC_MD5, (void *)az_CC_MD5, (void **)&orig_CC_MD5);
    AZ_INFO(@"INIT", @"CC_MD5 hook安装完成");
    
    // 4. close
    MSHookFunction((void *)close, (void *)az_close, (void **)&orig_close);
    AZ_INFO(@"INIT", @"close hook安装完成");
    
    // 5. exit/signal
    MSHookFunction((void *)exit, (void *)az_exit, (void **)&orig_exit);
    MSHookFunction((void *)kill, (void *)az_kill, (void **)&orig_kill);
    AZ_INFO(@"INIT", @"exit/signal hook安装完成");
    
    AZ_INFO(@"INIT", @"所有hooks安装完成 ✓");
}

// ============================================================================
// 9. 入口
// ============================================================================

static void az_init_on_main(void) {
    az_init_log();
    az_install_hooks();
    // 延迟显示悬浮窗，等待UI加载
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
        [AZFloatingWindow sharedWindow];
    });
}

%ctor {
    // 立即初始化日志
    az_init_log();
    AZ_INFO(@"INIT", @"AZwangxian tweak loaded (ctor) bundleID=%@",
        [[NSBundle mainBundle] bundleIdentifier]);
    // 等待主线程Runloop启动后安装hook
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidBecomeActiveNotification
        object:nil queue:nil usingBlock:^(NSNotification *n) {
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            az_init_on_main();
        });
    }];
}
