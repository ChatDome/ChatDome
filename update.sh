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

# 4. 仅同步 sentinel.checks 策略列表（其余配置不覆盖）
echo "[3/5] 正在同步告警检查策略 (sentinel.checks)..."
EXAMPLE_CONFIG="$CHATDOME_DIR/config.example.yaml"
TARGET_CONFIG="$CHATDOME_DIR/config.yaml"

if [ ! -f "$EXAMPLE_CONFIG" ]; then
    echo "⚠ 未找到 config.example.yaml，跳过策略同步"
else
    if [ ! -f "$TARGET_CONFIG" ]; then
        cp "$EXAMPLE_CONFIG" "$TARGET_CONFIG"
        echo "ℹ 未找到 config.yaml，已由模板创建: $TARGET_CONFIG"
    else
        BACKUP_PATH="$TARGET_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
        cp "$TARGET_CONFIG" "$BACKUP_PATH"
        echo "已备份旧配置: $BACKUP_PATH"

        if ! grep -q '^  sentinel:[[:space:]]*$' "$TARGET_CONFIG"; then
            echo "⚠ 当前 config.yaml 缺少 'chatdome.sentinel' 段，跳过策略同步"
        else
            CHECKS_TMP="$(mktemp)"
            MERGED_TMP="$(mktemp)"

            awk '
                /^    checks:[[:space:]]*$/ {
                    in_checks = 1
                }
                {
                    if (in_checks) {
                        if (captured && $0 ~ /^    [a-zA-Z0-9_]+:[[:space:]]*($|#)/ && $0 !~ /^    checks:/) {
                            exit
                        }
                        print
                        captured = 1
                    }
                }
            ' "$EXAMPLE_CONFIG" > "$CHECKS_TMP"

            if [ ! -s "$CHECKS_TMP" ]; then
                echo "⚠ 未在 config.example.yaml 提取到 sentinel.checks，跳过策略同步"
                rm -f "$CHECKS_TMP" "$MERGED_TMP"
            else
                awk -v checks_file="$CHECKS_TMP" '
                    BEGIN {
                        while ((getline line < checks_file) > 0) {
                            checks_block = checks_block line ORS
                        }
                        close(checks_file)
                    }
                    {
                        if ($0 ~ /^  sentinel:[[:space:]]*($|#)/) {
                            in_sentinel = 1
                            print
                            next
                        }

                        if (in_old_checks) {
                            if ($0 ~ /^    [a-zA-Z0-9_]+:[[:space:]]*($|#)/ && $0 !~ /^    checks:/) {
                                in_old_checks = 0
                                print checks_block
                                inserted = 1
                                print
                            }
                            next
                        }

                        if (in_sentinel && !inserted && $0 ~ /^    checks:[[:space:]]*($|#)/) {
                            in_old_checks = 1
                            next
                        }

                        if (in_sentinel && $0 ~ /^  [a-zA-Z0-9_]+:[[:space:]]*($|#)/ && $0 !~ /^  sentinel:/) {
                            if (!inserted) {
                                print checks_block
                                inserted = 1
                            }
                            in_sentinel = 0
                            print
                            next
                        }

                        print
                    }
                    END {
                        if (in_old_checks) {
                            print checks_block
                            inserted = 1
                        }
                        if (in_sentinel && !inserted) {
                            print checks_block
                            inserted = 1
                        }
                    }
                ' "$TARGET_CONFIG" > "$MERGED_TMP"

                mv "$MERGED_TMP" "$TARGET_CONFIG"
                rm -f "$CHECKS_TMP"
                echo "✓ 已同步 sentinel.checks（其余配置保持不变）"
            fi
        fi
    fi
fi

# 5. 更新依赖/重新安装 (如果需要)
echo "[4/5] 更新 Python 环境依赖..."
cd "$CHATDOME_DIR/controlplane" || exit
# 假设您使用的是系统环境或已经激活的虚拟环境
# 如果使用了虚拟环境，请在此处 source venv/bin/activate
pip install -e .
echo "✅ 依赖更新完成"
cd "$CHATDOME_DIR" || exit

# 6. 自动启动 ChatDome 服务 (后台运行)
echo "[5/5] 正在启动 ChatDome 服务..."
# 使用 nohup 后台启动，将日志输出到 chatdome.log
nohup chatdome > chatdome.log 2>&1 &

# 获取新进程 ID
NEW_PID=$!
echo "✅ ChatDome 服务已启动！(PID: $NEW_PID)"
echo ""
echo "日志输出重定向至: ${CHATDOME_DIR}/chatdome.log"
echo "可以使用命令 'tail -f chatdome.log' 查看实时运行日志。"
echo "============================================="
