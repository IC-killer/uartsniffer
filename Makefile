# 编译器
CC = gcc

# 目标文件名
TARGET = uartsniffer.exe

# 源文件
SRCS = uspy.c

# 目标文件
OBJS = uspy.o

# 链接库
LIBS = -lkernel32

# 编译选项
CFLAGS = -Wall

# 默认目标
all: $(TARGET)

# 链接生成可执行文件
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

# 编译源文件生成目标文件
$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS) -o $(OBJS)

# 清理生成的文件
clean:
	del $(TARGET) $(OBJS) 2>nul || rm -f $(TARGET) $(OBJS)

# 重新编译
rebuild: clean all

# 运行
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean rebuild run
