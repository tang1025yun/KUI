#!/bin/bash

# 解析命令行传入参数
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --api) API_DOMAIN="$2"; shift ;;
        --ip) VPS_IP="$2"; shift ;;
        --token) ADMIN_TOKEN="$2"; shift ;;
    esac
    shift
done

if [ -z "$API_DOMAIN" ] || [ -z "$VPS_IP" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "缺少必要参数！请从 Web 面板直接复制完整命令。"
    exit 1
fi

echo ">> [1/4] 安装必要依赖及组件..."
apt-get update -y >/dev/null 2>&1
apt-get install -y curl wget python3 openssl >/dev/null 2>&1

echo ">> [2/4] 部署 Sing-box 核心服务..."
bash <(curl -fsSL https://sing-box.app/deb-install.sh) >/dev/null 2>&1

echo ">> [3/4] 初始化 Python 节点守护进程..."
mkdir -p /opt/kui

# 请务必替换此 URL 为你的通用 Github RAW 地址
wget -qO /opt/kui/agent.py "https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/YOUR_REPO/main/vps/agent.py"

# 生成守护进程配置
cat <<EOF > /opt/kui/config.json
{
  "api_url": "$API_DOMAIN/api/config",
  "report_url": "$API_DOMAIN/api/report",
  "ip": "$VPS_IP",
  "token": "$ADMIN_TOKEN"
}
EOF

echo ">> [4/4] 注册 Systemd 开机自启服务..."
cat <<EOF > /etc/systemd/system/kui-agent.service
[Unit]
Description=Serverless Gateway Python Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kui/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kui-agent >/dev/null 2>&1
systemctl restart kui-agent
systemctl enable sing-box >/dev/null 2>&1
systemctl restart sing-box

echo "================================================="
echo " 部署圆满完成！"
echo " 探针服务与配置同步 Agent 已在系统后台安全运行。"
echo " 请返回面板页面验证服务器上线状态并下发节点配置。"
echo "================================================="
