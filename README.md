# AdGuard-Home-GoGoGo Manager

> **AdGuard-Home-GoGoGo Manager - 专为 AdGuard-Home-GoGoGo 打造的轻量现代化 Android 控制面板**

**[📥 点击直接下载安装包 (AdGuardHomeManager.apk)](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo-Manager/raw/main/releases/AdGuardHomeManager.apk)** · [Releases 页面](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo-Manager/releases) · [配套 Root 模块仓库 (AdGuard-Home-GoGoGo)](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo)

基于 Flutter 开发的 **AdGuard-Home-GoGoGo Manager**（应用桌面名称：`AdGuard Home GoGoGo`，快捷磁贴名称：`AGH GoGoGo`，包名：`com.wu.adgogogo`），专为 [AdGuard-Home-GoGoGo](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo) 全设备级去广告模块深度定制。

当前版本：`2.24.29`（`versionCode 199`，arm64-v8a 超轻量化体积仅 `8.5 MiB` / `8.87 MB`）。

---

## ✨ 核心功能亮点

1. **「🌐 海外模式 / 🇨🇳 国内模式」双入口一键无损热切换与有序队列**：
   - 在 **首页顶部快捷栏** 与 **设置 -> DNS 设置页顶部** 均内置双模分段切换开关（初次安装默认激活 **🌐 海外模式**）；
   - 点击即可调用模块底层 `switch_mode.sh` 白名单级热切换上游加密 DNS（Cloudflare/Google/Quad9 vs 阿里/腾讯 DoH）、规则加速源与 VPN 伴生策略，**100% 保留个人自定义规则、已修改的订阅列表与动态端口**；
   - 内置目标感知有序切换队列（相同目标并发请求自动合并共享结果、不同目标按序排队串行执行），彻底杜绝连点或超时引发的状态错乱与跨 `su` 重复重放。
2. **分应用白名单（App Allowlist）**：
   - 原生高性能加载手机已安装应用图标、名称与 UID（支持搜索、已勾选置顶及显示系统应用）；
   - 勾选保存后即时同步至模块内核 `iptables` 规则链（`-m owner --uid-owner`），被放行的应用直接绕过 DNS 与 SNI 拦截，零后台耗电。
3. **误杀排错助手（首页 -> 误杀排错）**：
   - **近期拦截域名一键放行**：自动聚合最近被 DNS 或 SNI 拦截的域名，支持一键带 `$important` 最高优先级放行并冲洗系统 DNS 缓存；
   - **网页链接域名嗅探器**：支持粘贴网页链接或分享口令，自动抓取网页源码及同源 `iframe` 中引用的所有主域名与静态资源/CDN 域名（智能过滤局域网私有 IP）；
   - **应用本地缓存域名扫描 + 冷启动抓包复现**：支持扫描目标应用私有目录缓存的接口域名，或一键清理 DNS 缓存并冷启动目标应用进行实时抓包排查；
   - **本地规则库关键词检索**：支持直接在 `/data/adb/agh/bin/data/filters/*.txt` 数十万条规则中按关键词检索并一键放行。
4. **免登录零配置直连、非阻塞 Root 探测 & 状态栏快捷磁贴 (`AGH GoGoGo`)**：
   - 彻底移除原版繁琐的多服务器数据库（`sqflite`）、首次引导向导与冗余图表组件，启动时通过缓存的可用 `su` 通道（含 3 秒探测超时与失败熔断冷却）自动读取 `/data/adb/agh/bin/AdGuardHome.yaml` 动态管理端口并秒级直连本地实例；
   - 系统下拉通知栏「`AGH GoGoGo`」快捷磁贴采用非阻塞并发互斥与超时销毁保护（`process.destroyForcibly()`），主界面退至后台或锁屏时自动暂停轮询，前台按需自适应刷新，极致省电。
5. **合一化 DNS 设置与模块运维工具箱**：
   - 单页整合 Upstream / Bootstrap / Fallback DNS、查询模式（负载均衡 / 并行请求 / 最快 IP）、乐观缓存、强力模式（SNI 阻断）及上游连通性测速；
   - 内置模块运行状态自检与 `agh.log` 日志查看器、一键刷新网络与防火墙规则、一键清理应用开屏广告缓存、以及一键智能补全/重置出厂默认自定义规则（所有模块级修改操作均受全局单飞互斥与真实退出码校验保护）。

---

## 🛠️ 构建方法

需要 Flutter `3.22+` 与 Android SDK：

```bash
flutter pub get
flutter build apk --release --target-platform android-arm64 --obfuscate --split-debug-info=build/symbols
```

构建产物位于 `build/app/outputs/flutter-apk/app-release.apk`。

## 维护与开源许可

- 作者与维护：[wu](https://github.com/WEIHEWU)
- 上游原版基础：[JGeek00/adguard-home-manager](https://github.com/JGeek00/adguard-home-manager)
- 开源协议：GNU General Public License v3.0 (GPL-3.0)，详见 [LICENSE.md](LICENSE.md)。
