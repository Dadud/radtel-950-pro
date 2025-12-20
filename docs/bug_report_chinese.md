# RT-950 Pro 固件错误报告及修复建议

**版本**: V0.24  
**日期**: 2024年12月20日  
**报告者**: 业余无线电社区  

---

## 错误 #1: TNC 类型 "KISS" 模式无法通过蓝牙发送数据 (严重)

### 问题描述

当用户在菜单中设置 `TNC Type = KISS` 时，APRS数据包**不会**通过蓝牙发送到APRSDroid等应用程序。只有设置 `TNC Type = WinAPRS` 时蓝牙才能工作。

这使得用户无法使用标准KISS协议连接APRSDroid。

### 问题根因

在函数 `FUN_080140c0` (地址 0x080140c0) 中，代码检查 TNC 类型是否等于 1：

**当前代码 (有问题):**
```c
// 地址: 0x08014745 (反编译)
if (*(char *)(DAT_08014150 + 0x1d) == '\x01') {  // 只检查类型 1 (WinAPRS)
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);  // 发送到蓝牙
}
```

**TNC 类型值:**
| 值 | 类型名称 | 蓝牙输出 |
|---|---------|---------|
| 0 | MacAPRS | ❌ 不工作 |
| 1 | WinAPRS | ✅ 工作 |
| 2 | APRS | ❌ 不工作 |
| 3 | KISS | ❌ 不工作 (应该工作!) |

### 修复建议

**方案 A: 让 KISS 模式也能工作 (推荐)**

```c
// 原始代码 (FUN_080140c0, 地址约 0x08014745)
// 原始:
if (*(char *)(DAT_08014150 + 0x1d) == '\x01') {
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}

// 修复后:
uint8_t tnc_type = *(uint8_t *)(DAT_08014150 + 0x1d);
if (tnc_type == 1 || tnc_type == 3) {  // WinAPRS(1) 或 KISS(3)
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}
```

**方案 B: 更灵活的检查 (最佳)**

```c
// 检查任何非零TNC类型都发送到蓝牙
uint8_t tnc_type = *(uint8_t *)(DAT_08014150 + 0x1d);
if (tnc_type > 0) {  // 任何启用的TNC模式
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}
```

### 汇编级修复

**原始指令 (地址 0x08014116):**
```asm
ram:08014114    407f            ldrb        r0,[r0,#0x1d]
ram:08014116    0128            cmp         r0,#0x1         ; 只比较 1
ram:08014118    02d1            bne         LAB_08014120    ; 不等于1则跳过
```

**修复指令:**
```asm
ram:08014114    407f            ldrb        r0,[r0,#0x1d]
ram:08014116    0028            cmp         r0,#0x0         ; 比较 0
ram:08014118    02d0            beq         LAB_08014120    ; 等于0则跳过 (任何非零都发送)
```

或者支持 KISS(3):
```asm
ram:08014114    407f            ldrb        r0,[r0,#0x1d]
ram:08014116    0328            cmp         r0,#0x3         ; 比较 3 (KISS)
ram:08014118    01d0            beq         SEND_BT         ; 如果是KISS则发送
ram:0801411a    0128            cmp         r0,#0x1         ; 比较 1 (WinAPRS)
ram:0801411c    02d1            bne         LAB_08014120    ; 都不是则跳过
SEND_BT:
```

---

## 错误 #2: 其他位置的 TNC 类型检查 (相关)

### 问题描述

同样的 `cmp r0,#0x1` 检查出现在多个位置：

| 地址 | 功能 |
|-----|------|
| 0x08014116 | KISS帧发送到蓝牙 |
| 0x08019650 | GPIO控制 (发射相关?) |
| 0x08021708 | 设置加载/保存 |
| 0x080263b0 | 其他TNC功能 |

### 修复建议

所有这些位置都需要同样的修复：将 `cmp r0,#0x1` 改为 `cmp r0,#0x0` 并改变跳转条件。

---

## 建议改进 #1: 蓝牙TNC连接检测

### 当前问题

代码在发送KISS帧之前没有检查蓝牙是否已连接。如果蓝牙未连接，数据会发送到无效的端口。

### 建议添加

```c
// 在发送KISS帧之前添加检查
bool bluetooth_connected = check_bluetooth_connection();
uint8_t tnc_type = *(uint8_t *)(DAT_08014150 + 0x1d);

if (bluetooth_connected && (tnc_type == 1 || tnc_type == 3)) {
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}
```

---

## 建议改进 #2: 添加 USB CDC TNC 模式

### 建议

目前KISS帧只能通过蓝牙发送。建议添加USB CDC选项，让用户可以通过USB线连接电脑上的APRS软件。

```c
// TNC输出路径选择
typedef enum {
    TNC_OUTPUT_BLUETOOTH = 0,
    TNC_OUTPUT_USB_CDC = 1,
    TNC_OUTPUT_ACCESSORY = 2  // 侧面接口
} TNC_Output_t;

void send_kiss_frame(uint8_t *data, uint16_t len) {
    uint8_t output = get_tnc_output_setting();
    
    switch (output) {
        case TNC_OUTPUT_BLUETOOTH:
            send_uart1(data, len);  // 蓝牙
            break;
        case TNC_OUTPUT_USB_CDC:
            send_usb_cdc(data, len);  // USB
            break;
        case TNC_OUTPUT_ACCESSORY:
            send_uart4(data, len);  // 侧面接口
            break;
    }
}
```

---

## 建议改进 #3: APRS TX 延迟优化

### 当前实现

```c
// FUN_08014154, 地址 0x08014154
void FUN_08014154(void) {
    byte bVar1 = *(byte *)(DAT_0801419c + 3);
    if (bVar1 < 5) {
        *(short *)(DAT_080141a0 + 0x30) = bVar1 * 0x32;  // 50ms 步进
    }
    // ... 更多代码
}
```

### 建议

TX延迟步进为50ms可能不够精细。建议改为25ms步进：

```c
// 修改后
if (bVar1 < 10) {  // 增加选项数量
    *(short *)(DAT_080141a0 + 0x30) = bVar1 * 0x19;  // 25ms 步进
}
```

---

## 建议改进 #4: KISS帧接收处理

### 当前状态

目前代码主要处理KISS帧的**发送**。接收路径(从蓝牙到radio TX)需要检查是否完整实现。

### 需要确认的功能

1. 蓝牙接收中断/轮询
2. KISS帧解析(去除0xC0分隔符和转义)
3. AX.25帧提取
4. AFSK调制和发射

---

## 完整修复补丁

### 二进制补丁 (针对 v0.24)

**补丁 #1: 允许KISS模式使用蓝牙输出**

| 地址 | 原始字节 | 修改字节 | 说明 |
|-----|---------|---------|------|
| 0x08014116 | 01 28 | 00 28 | 将 `cmp r0,#0x1` 改为 `cmp r0,#0x0` |
| 0x08014118 | 02 D1 | 02 D0 | 将 `bne` 改为 `beq` |

**效果**: 任何非零TNC类型都会通过蓝牙发送KISS帧

**注意**: 这些是 little-endian Thumb-2 指令

### 验证测试

修复后请测试:
1. 设置 TNC Type = KISS
2. 配对蓝牙并连接 APRSDroid
3. 接收APRS信号，确认APRSDroid能显示
4. 从APRSDroid发送位置，确认radio能发射

---

## 联系方式

如有问题请联系:
- GitHub: https://github.com/Dadud/radtel-950-pro
- 原始项目: https://github.com/nicsure/radtel-950-pro

感谢您对产品的持续改进！

---

## 附录: 相关函数地址 (v0.24)

| 函数 | 地址 | 功能 |
|-----|------|------|
| FUN_080140c0 | 0x080140c0 | KISS帧构建 |
| FUN_08024444 | 0x08024444 | USART1发送(蓝牙) |
| FUN_0802445c | 0x0802445c | 单字节发送 |
| DAT_08014150 | 0x2000A83C | 设置结构基址 |
| TNC类型偏移 | +0x1D | TNC类型字节 |

