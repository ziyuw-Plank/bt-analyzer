# BT Analyzer

[中文](#中文) | [English](#english)

An Android Bluetooth analyzer that drives a **USB Bluetooth 4.0 dongle (CSR8510 A10, 0A12:0001)** directly over the Android USB Host API using raw HCI. **No root required** for the dongle features.

---

## 中文

### 功能
- **控制器信息**：HCI Reset、本地版本 / BD_ADDR / 名称、经典 (LMP) 与 LE 特性、缓冲区大小、疑似山寨芯片提示。
- **BLE 扫描**：主动/被动扫描；按设备聚合（不刷屏）；名称、地址类型、RSSI 及实时趋势图；广播数据解析（Flags、UUID、厂商数据 + 公司 ID、iBeacon、Eddystone UID/URL/TLM、Apple Find My 等、发射功率与估算距离）；筛选与排序。
- **GATT**：LE 连接、服务/特征/描述符发现、读取（含 Read Blob）、写入（Write Request / Write Command，HEX 或 UTF-8）、订阅通知/指示并实时显示、MTU 交换、单连接抓包并导出 btsnoop；基于 Number Of Completed Packets 的 ACL 流控。
- **经典蓝牙**：带 RSSI/EIR 的查询与名称解析；建立/断开连接；配对（SSP 数字比较、配对码输入/显示、Just Works，传统 PIN）；链路密钥保存在应用私有存储并自动应答 Link Key Request；认证与加密；SDP 服务发现（服务名、UUID、RFCOMM 通道）；远端版本与特性。
- **HCI 日志**：彩色方向/类型标签、可读摘要、详情面板（字段解析 + 十六进制）、按类型 (CMD/EVT/ATT/L2CAP/SMP) 筛选、搜索、按句柄/地址筛选，导出 Wireshark 可读的 btsnoop。
- **手机内置蓝牙日志（需 root，严格只读）**：读取系统 HCI snoop 日志（含小米/HyperOS 轮转文件），完整解析查看、实时跟随、筛选、导出副本。
- Material 3 / Material You 原生风格，抽屉导航，中英双语（应用内切换）。

### CSR8510 A10 说明
蓝牙 4.0 双模（BR/EDR + LE），LE 仅支持 4.0 基础特性（无数据长度扩展/2M PHY/扩展广播），LE 包最大 27 字节。市面上大量为山寨芯片，部分 LE 连接或首次 Reset 不稳定。

### 安装
从 [Releases](../../releases) 下载 APK 安装（debug 签名）。通过 OTG 插入 Dongle，选择用 BT Analyzer 打开或在应用内点击“连接 Dongle”并授予 USB 权限。

### 只读声明
“手机日志”页仅通过 `su` 执行只读命令（`id`、`getprop`、`stat`、`find`、`cat`、`tail`）。**不会**写入、修改、删除、remount 或 setprop 任何系统内容。导出时先复制到应用私有目录，再保存到你选择的位置。开启 snoop 日志需由你在开发者选项中手动操作。

### 构建
`./gradlew assembleDebug`（JDK 17+，Android SDK 37）。

---

## English

### Features
- **Controller info**: HCI Reset, local version / BD_ADDR / name, BR/EDR (LMP) & LE features, buffer sizes, clone-chip heuristic.
- **BLE scan**: active/passive; results aggregated per device (no flooding); name, address type, RSSI with live chart; AD decoding (flags, UUIDs, manufacturer data + company IDs, iBeacon, Eddystone UID/URL/TLM, Apple Find My etc., Tx power & distance estimate); filter & sort.
- **GATT**: LE connect, service/characteristic/descriptor discovery, read (incl. Read Blob), write (Write Request / Write Command, hex or UTF-8), notifications/indications with live values, MTU exchange, per-connection capture with btsnoop export; ACL flow control via Number Of Completed Packets.
- **Classic**: inquiry with RSSI/EIR and name resolution; connect/disconnect; pairing (SSP numeric comparison, passkey entry/display, Just Works, legacy PIN); link keys stored in app-private storage and used for Link Key Request; authentication & encryption; SDP discovery (service names, UUIDs, RFCOMM channels); remote version & features.
- **HCI log**: colored direction/type badges, readable summaries, detail sheet (decoded fields + hex), filters (CMD/EVT/ATT/L2CAP/SMP), search, handle/address filter, btsnoop export for Wireshark.
- **Phone built-in BT log (root, strictly read-only)**: reads the system HCI snoop log (incl. Xiaomi/HyperOS rotated files), full decoded viewer, live follow, filters, export copy.
- Stock Material 3 / Material You look, navigation drawer, English & Simplified Chinese (in-app switch).

### CSR8510 A10 notes
Bluetooth 4.0 dual mode (BR/EDR + LE). LE is 4.0 baseline only (no DLE / 2M PHY / extended advertising), 27-byte LE packets. Many dongles on the market are clones; some have unstable LE connections or need a second HCI Reset.

### Install
Download the APK from [Releases](../../releases) (debug-signed). Plug the dongle in via OTG, open with BT Analyzer or tap "Connect dongle" and grant USB permission.

### Read-only statement
The Phone Log page only runs read-only commands via `su` (`id`, `getprop`, `stat`, `find`, `cat`, `tail`). It **never** writes, modifies, deletes, remounts or setprops anything on the system. Exports are copied into app-private storage first, then saved where you choose. Enabling the snoop log is left to you in Developer options.

### Build
`./gradlew assembleDebug` (JDK 17+, Android SDK 37).

## License

[MIT](LICENSE)
