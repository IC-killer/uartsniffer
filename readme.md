# 串口监听工具

- 配合虚拟串口com0com使用
- 仅支持window平台

## 编译

- `gcc uspy.c -o uartsniffer.exe -lkernel32`

## 使用

- 创建一对虚拟串口
- `./uartsniffer.exe -i COM6 -o COM7 -b 115200`
