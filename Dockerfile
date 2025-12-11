# 使用 Ubuntu 作为基础镜像
FROM ubuntu:latest

# 配置阿里云镜像源以加速软件包安装
RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

# 更新并安装必要的系统依赖
RUN apt-get update && apt-get install -y \
    curl \
    python3 \
    python3-pip \
    python3-requests \
    python3-urllib3 \
    && rm -rf /var/lib/apt/lists/*

# 安装 kubectl
COPY kubectl /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

# 创建工作目录
WORKDIR /app

# 复制 Python 脚本到容器中
COPY redfish-discovery-valid-only-ip.py /app/

# 设置脚本执行权限
RUN chmod +x /app/redfish-discovery-valid-only-ip.py

# 设置容器启动命令
CMD ["python3", "/app/redfish-discovery-valid-only-ip.py"]