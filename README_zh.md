# dl_interceptor

[English](README.md) | [中文](README_zh.md)

Android native 库 + 注入器 (Injector)，通过 Hook linker 中的 `soinfo::call_constructors()` 和 `soinfo::call_destructors()` 函数，来监控 ELF 文件 `.init` / `.init_array` 及 `.fini` / `.fini_array` 的执行。

本工具可以在构造函数/析构函数执行的前后提供 **pre** (执行前) 和 **post** (执行后) 的回调，支持对每一个 init_array 条目的执行进行追踪，并具有断点机制和内存 Dump 功能 —— 所有的功能都集成在一个独立的二进制注入器中。

## 特性

- 可以在 `.init` + `.init_array` （和 `.fini` + `.fini_array`）执行前后触发回调
- 对每一个 init_array 条目进行精准追踪，记录绝对地址和相对地址
- 使用 xDL 进行符号解析 (存在时会显示函数名)
- **断点功能** — 可以在执行任意 init_array 条目之前暂停进程（发 SIGSTOP）
- **内存 Dump** — 可以在执行任意 init_array 之前将发生重定位后的 .so 文件内存予以导出
- **Init array Hooks** — 替换、跳过或包装 (Wrap) 特定的 init 函数
- 支持架构：**armeabi-v7a**, **arm64-v8a**, **x86**, **x86_64**
- 支持 Android 版本：5.0–16 (API 21–36)
- 运行时动态扫描 `soinfo` 结构体 —— 无需硬编码偏移量，兼容 AOSP 以及各大厂商修改过的 linker
- 基于内置在源码中的头文件形式 inline hook 引擎 (`mini_hook.hpp`) 构建
- 包含被注入 `.so` 的单文件版注入器（基于 ptrace，无需在外部准备其他文件）

## 快速开始

```powershell
# 自动检测设备架构，按需编译、推送到手机并注入到指定包名的应用中 (需要 root)
./run.ps1 -p com.example.app
```

## 注入器用法

```
di_injector [选项]

必填:
  -p <package>    目标应用的包名

选填:
  -b <lib:N>      在 init_array 处的指定条目设置断点 (基于 1 的索引，可指定多个)
  -d <lib:N>      在执行 init_array 指定条目时 Dump 对象内存 (基于 1，可指定多个)
  -a <activity>   用于调起应用的 Activity 名 (默认: 自动检测)
  -t <timeout>    等待进程启动的超时时间 ms (默认: 10000)
  -n              注入到一个已在运行的进程中 (不重启进程)
  -h              显示帮助信息
```

### 示例

```bash
# 基本注入 — 监控所有库的加载情况
di_injector -p com.example.app

# 在 libfoo.so 的第1个 init_array 函数执行前下断点暂停进程
di_injector -p com.example.app -b libfoo.so:1
# 恢复执行可使用命令: kill -CONT <pid>

# 在 libfoo.so 的第1个 init_array 条目处导出内存 Dump
di_injector -p com.example.app -d libfoo.so:1
# 导出文件存放在: /data/local/tmp/libfoo.so_dump_1.so

# 结合断点与 Dump 使用
di_injector -p com.example.app -b libfoo.so:1 -d libfoo.so:1

# 截获某个库的所有 init_array 条目断点
di_injector -p com.example.app -b libfoo.so:*

# 对多个目标设置不同操作
di_injector -p com.example.app -b libfoo.so:1 -d libbar.so:3
```

### 索引约定

所有对 init_array 描述的索引都是 **从 1 开始的**:
- `libfoo.so:1` = 第 1 个 init_array 条目
- `libfoo.so:18` = 第 18 个条目
- `libfoo.so:*` 或者单纯 `libfoo.so` = 作用于所有条目

## 工作原理

```
dlopen("libfoo.so")
│
├── Linker 加载改 ELF 至内存中
├── Linker 解析并应用重定位规则 (填充 GOT/PLT)
│
├── >>> PRE 回调被触发 <<<
├── >>> 处理各个 init_array hook 任务 (断点/Dump/函数替换) <<<
│
├── Linker 运行 .init
├── Linker 运行 .init_array[1], [2], ... [N]
│   (每个条目都会输出带有绝对/相对地址及函数名的追踪日志)
│
├── >>> POST 回调被触发 <<<
│
└── dlopen() 结束并返回
```

### 注入流程

1. 借助 `am force-stop` → `am start` 重启目标应用
2. 每 5ms 对 `/proc` 轮询，尽可能在非常早期的阶段捕获 PID
3. 调用 `ptrace(ATTACH)` 冻结整个进程
4. 使用远程 `mmap` + 远程 `dlopen` 让目标进程加载 `libdl_interceptor.so`
5. 通过远程 `dlsym` 定位并使对端调用 `dl_interceptor_init()`
6. 如果用户提交了相关的请求，则进行后续对 `dl_interceptor_set_breakpoint()` 或 `dl_interceptor_set_dumppoint()` 的远程调用
7. `ptrace(DETACH)` — 目标进程恢复运行并使钩子正常生效

### 偏移量探测

该库利用运行时扫描内存来确定 `soinfo` 结构体内具体的字段偏移量:
1. 采用 **xDL** 解析 linker 库以找到 `soinfo::call_constructors()` 的符号
2. 借助 `mini_hook.hpp` 对找到的函数入口安装 inline hook
3. 主动加载一个非常小的用于触发行为的哑 (dummy) `.so` 文件，让 `call_constructors()` 跑起来，接着对内存中 `soinfo` 的固定特征数据扫描来推断偏移
4. 这种方式做到了极好地兼容 Android 源码以及被各类厂商深度修改定制过的 linker (如三星、小米、华为等均可正常运行)

## C API 用法

```c
#include "dl_interceptor.h"

// 执行初始化 (务必只调用一次)
int dl_interceptor_init(void);

// 注册库加载的回调机制 (pre = .init前, post = .init_array后)
int dl_interceptor_register_dl_init_callback(pre, post, data);
int dl_interceptor_unregister_dl_init_callback(pre, post, data);
int dl_interceptor_register_dl_fini_callback(pre, post, data);
int dl_interceptor_unregister_dl_fini_callback(pre, post, data);

// 针对每一个 init_array 的条目级别 Hook (可独立审查、替换或跳过其中执行的 init 函数)
int dl_interceptor_register_init_array_hook(hook, data);
int dl_interceptor_unregister_init_array_hook(hook, data);

// 设定断点 (在执行任意指定条目之前发送 SIGSTOP，需指定为从 1 开始的索引)
int dl_interceptor_set_breakpoint(lib_name, index);
void dl_interceptor_clear_breakpoints(void);

// 设定内存 Dump 捕获点 (从 1 起始的索引用法)
int dl_interceptor_set_dumppoint(lib_name, index);
void dl_interceptor_clear_dumppoints(void);
```

## 编译指南

### 环境要求

- Android NDK (r21+)
- CMake 3.22.1+
- Ninja
- Python 3 (编译期间会被 bin2hex 使用)

### 编译 & 运行脚本

我们强烈推荐使用 `run.ps1` 脚本来快速运行构建。该脚本会自动读取连接到的 `adb` 设备的架构并对缺少的 ABI 执行进行相应的构建部署，最后自动应用参数来注入：

```powershell
# 对应用直接实施注入
./run.ps1 -p com.example.app

# 将其他参数传给注入器
./run.ps1 -p com.example.app -b libfoo.so:1 -d libfoo.so:1
```

如果你只想进行手动构建而不想立即运行，那你也可以使用 `build_ndk.ps1`：

```powershell
# 构建所有 ABI 变体 (自动监测 SDK/NDK 环境)
./build_ndk.ps1

# 指定特定 ABI 或是清除全部构建
./build_ndk.ps1 -Abi arm64-v8a
./build_ndk.ps1 -Clean
```

脚本的依赖自动检测按照如下规律检索路径:
- `ANDROID_SDK_ROOT` / `ANDROID_HOME` 环境变量
- 通用常见的 SDK 安装路径 (`%LOCALAPPDATA%\Android\Sdk`, `C:\Android\Sdk`, `D:\Android\Sdk`)
- `<sdk>/ndk/` 下最新的 NDK 版本号
- `<sdk>/cmake/` 下最新的 CMake 版本

### 引入该项目到你现存的 CMakeLists.txt

```cmake
add_subdirectory(dl_interceptor)
target_link_libraries(your_lib PRIVATE dl_interceptor)
```

## 工程目录结构

```
dl_interceptor/
├── CMakeLists.txt                 # 库的构建脚本
├── build_ndk.ps1                  # 构建脚本主体 (自动识别 SDK/NDK)
├── include/
│   └── dl_interceptor.h           # 公开对接的 C API
├── src/
│   ├── dl_interceptor.cpp         # 核心代码部分
│   └── mini_hook.hpp              # Header-only 形态的轻量 inline hook 引擎
├── injector/
│   ├── CMakeLists.txt             # 注入器构建文件 (会把生成的 .so 以 bin2hex 直接嵌入进体积中)
│   ├── injector.cpp               # 搭载了 ptrace 注入逻辑的业务代码
│   └── bin2hex.py                 # 将二进制包转为 C 头文件的 python 工具
├── nothing/
│   ├── jni/
│   │   ├── dl_interceptor_nothing.c  # 为诱导行为发明的虚假 .so
│   │   ├── Android.mk
│   │   └── Application.mk
│   └── libs/                      # 各平台预先编译好的 Dummy 虚假 .so
└── third_party/
    └── xdl/                       # 用于对付符号解析问题的库
```

## 产出物文件位置

在被成功编译出来之后，主要的注入器文件存放于：
```
build/injector-<abi>/di_injector    # 已内含被嵌入 .so 载荷的单体原生可执行程序
```

因为使用了代码内生提取技术，注入器在运行时会自动析出它打包的 `.so` 组件至 `/data/local/tmp/`。**所以你不需要额外再通过 adb 去推送那些附属文件。**

## 注意事项

- **非常依赖 root 权限**（它需要能够对其他进程进行 `ptrace` 并执行 `dlopen` 指令）
- 在你请求实施 `-d`（dump）动作时，系统的 SELinux 将会非常短暂地切为 permissive 宽容模式，你可以使用 `setenforce 1` 手动重新调回。
- 所有被 Dump 出的镜像文件均会被放置于 `/data/local/tmp/<libname>_dump_<N>.so`
- Dummy 虚假库 `libdl_interceptor_nothing.so` 的运行会基于它能在 `/data/local/tmp/` 找到而被成功调用执行（这也是由注入器自动提前操作放好的）
- **查看输出日志 (Check Logs)**：注入器以及整个拦截库模块本身有关输出、Hook 追踪、执行等相关信息将输出到系统级的机器日志中。你应该通过在 logcat 选择 `DLInterceptor` 的 tag 关键字标签来进行滤查并读取 (例如我们可以调用：`adb logcat -s DLInterceptor`)。

## 致谢

- **[xDL](https://github.com/hexhacking/xDL)**: 用于进行深层 `soinfo` 结构动态扫描并对 ELF 实施内部深度解析的极其优秀的系统原生库。
- **[aimardcr/dl_interceptor](https://github.com/aimardcr/dl_interceptor)**: 本项目底层理念的启发来源和结构上的灵感基础库。

## 开源协议

MIT
