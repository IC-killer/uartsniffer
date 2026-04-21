# 串口监听工具

- 配合com0com或其他虚拟串口工具使用，依赖一对虚拟串口做监听和桥接
- 当前仅支持window平台
- 只有一个c文件

## 编译

- `gcc uspy.c -o uartsniffer.exe -lkernel32`

## 使用

- 创建一对虚拟串口
- `./uartsniffer.exe -i COM6 -o COM7 -b 115200`

![png](./1.png)
