# 步骤 1: 选择一个基础的 Linux 系统镜像
FROM ubuntu:22.04

# 步骤 2: 更新系统包列表，并安装 C++ 编译器 (g++) 和 OpenSSL 开发库 (libssl-dev)
# '-y' 参数会自动确认所有安装提示
RUN apt-get update && apt-get install -y g++ libssl-dev

# 步骤 3: 在迷你电脑（容器）里创建一个工作目录 /app
WORKDIR /app

# 步骤 4: 将你 GitHub 仓库里的所有文件 (server.cpp, crypto.cpp 等) 复制到 /app 目录
COPY . .

# 步骤 5: 运行我们之前用过的构建命令来编译代码
RUN g++ -std=c++17 -o chat_server server.cpp crypto.cpp -lssl -lcrypto -lpthread

# 步骤 6: 设置时区为亚洲/上海，避免日志时间错乱 (可选，但推荐)
ENV TZ=Asia/Shanghai

# 步骤 7: 告诉 Docker，我们的服务会监听 8888 端口
EXPOSE 8888

# 步骤 8: 定义启动容器时要执行的命令，也就是运行我们的服务器程序
CMD ["./chat_server"]
