# 串口监听工具

- 配合com0com或其他虚拟串口工具使用，依赖一对虚拟串口做监听和桥接
- 当前仅支持window平台
- 只有一个c文件

## 编译

- 方式1: `gcc uspy.c -o uartsniffer.exe -lkernel32`
- 方式2: make

## 使用

- 创建一对虚拟串口
- 普通监听：`./uartsniffer.exe -i COM6 -o COM7 -b 115200`
- 带解析器监听：`sniffer.exe -i COM6 -o COM7 -b 115200 -c e.cfg`

![png](./1.png)

**设计思路：**

- `{...}` 过滤条件：`len=N`、`idx3=0x05`、可组合（AND逻辑）
- `[type(label)]` 解析字段：按顺序消耗字节
- 多行规则

**`-c` 解析器配置文件语法规则：**

| 语法 | 说明 |
|------|------|
| `{len=9}` | 包长度必须为 9 字节 |
| `{idx0=0x01}` | 第 0 字节必须为 0x01 |
| `{len=9, idx0=0x01, idx2=0x05}` | 多条件 AND 组合 |
| `[u16(voltage)]` | 解析 2 字节 LE uint16，标签为 voltage |
| `[s16be(speed)]` | 解析 2 字节 BE int16 |
| `# rule_name` | 行末注释作为规则名称显示 |

**支持的数据类型：** `u8 s8 u16 s16 u16be s16be u32 s32 u32be s32be float double`
