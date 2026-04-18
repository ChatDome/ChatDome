#!/bin/zsh

echo "============================================="
echo "       🛡️ ChatDome 自动更新与重启脚本       "
echo "============================================="

# 1. 设置工作目录 (默认为 ~/ChatDome)
CHATDOME_DIR="${HOME}/ChatDome"

if [ ! -d "$CHATDOME_DIR" ]; then
    echo "❌ 错误: 找不到 ChatDome 目录 ($CHATDOME_DIR)"
    echo "请修改脚本中的 CHATDOME_DIR 变量以匹配您的实际路径。"
    exit 1
fi

cd "$CHATDOME_DIR" || exit

# 2. 自动清除 ChatDome 进程
echo "[1/5] 正在停止旧的 ChatDome 进程..."
# 查找正在运行的 chatdome 进程并 kill 掉
PIDS=$(ps aux | grep '[c]hatdome' | awk '{print $2}')
if [ -n "$PIDS" ]; then
    echo "发现进程: $PIDS，正在终止..."
    kill -9 $PIDS
    echo "✅ 旧进程已终止"
else
    echo "ℹ️ 未发现运行中的 ChatDome 进程"
fi

# 3. 自动拉取 GitHub 代码
echo "[2/5] 正在从 GitHub 拉取最新代码..."
git fetch --all
git reset --hard origin/main
git pull
echo "✅ 代码更新完成"

# 4. 更新依赖/重新安装 (如果需要)
echo "[3/5] 更新 Python 环境依赖..."
cd "$CHATDOME_DIR/controlplane" || exit
# 假设您使用的是系统环境或已经激活的虚拟环境
# 如果使用了虚拟环境，请在此处 source venv/bin/activate
pip install -e .
echo "✅ 依赖更新完成"
cd "$CHATDOME_DIR" || exit

# 5. 自动启动 ChatDome 服务 (后台运行)
echo "[4/4] 正在启动 ChatDome 服务..."
# 使用 nohup 后台启动，将日志输出到 chatdome.log
nohup chatdome > chatdome.log 2>&1 &

# 获取新进程 ID
NEW_PID=$!
echo "✅ ChatDome 服务已启动！(PID: $NEW_PID)"
echo ""
echo "日志输出重定向至: ${CHATDOME_DIR}/chatdome.log"
echo "可以使用命令 'tail -f chatdome.log' 查看实时运行日志。"
echo "============================================="
