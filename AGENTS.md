# ChatDome — AI 编码规范

## 总原则

你在开发一个给用户使用的工具，不是在和用户聊天。所有生成的代码、文本、注释都必须务实：

- 解决问题，不要表达情绪、展示礼貌套话或营造对话氛围。
- 不要写"很高兴为你..."、"希望这对你有帮助"、"让我来为你..."之类的话。这些是聊天机器人的语气，不是工具的输出。
- 提示信息的目标是让用户最快完成操作，不是让用户感到被关心。
- 代码注释的目标是让下一个开发者最快理解意图，不是展示你的思考过程有多完整。

## 用户可见文本（User-Facing Copy）

本项目的 Bash 菜单、CLI 输出、Telegram Bot 消息会直接展示给终端用户。
所有用户可见的文本**必须**遵守以下规则。

### 核心原则

1. **只说用户需要知道的事。** 不要解释系统内部的设计决策、历史原因或技术背景。
2. **每条信息必须可操作。** 告诉用户该做什么，而不是系统在想什么。
3. **一句话说完。** 能用一句话说清楚的，绝不用两句。

### 禁止出现的文本模式

| 禁止 | 原因 | 正确写法 |
|---|---|---|
| `现在不会自动推断该路径` | 暴露内部实现决策 | 直接删除，或转化为操作指引 |
| `请注意，由于 X 的变更，系统已不再支持 Y` | 向用户解释重构历史 | `请手动配置 Y` |
| `为了安全起见，建议您...` | 不必要的铺垫 | 直接写建议内容 |
| `这是因为 X，所以需要 Y` | 因果推理是 LLM 思维链，不是用户提示 | 只保留 `请执行 Y` |
| `（可选，通常不需要修改）` | 括号内的补充说明过长 | 写成独立的简短提示 |

### 风格对照

**❌ 不合格：**
```
[Notice] Detected legacy auth file: ~/.chatdome/auth.json
         The auto-detection logic has been removed; please specify the token file path manually in LLM settings.
```

**✅ 合格：**
```
Found existing auth file: ~/.chatdome/auth.json
Use this file? [Y/n]:
```

**❌ 不合格：**
```
Due to the configuration format upgrade, the old token path inference logic has been removed.
If you previously used Codex authentication, you now need to re-specify the path in the LLM management menu.
```

**✅ 合格：**
```
Token file not set. Run: LLM Management → Configure Codex OAuth.
```

## 代码注释

- 注释说明 **为什么**（why），不要复述代码在做什么（what）。
- 不要把设计讨论、替代方案对比或思考过程写进注释。
- 注释不是给用户看的。用户可见文本和代码注释是两件事，不要混淆。

**❌ 不合格：**
```python
# Because the previous version auto-detected the token path, but now we've
# switched to explicit configuration, we need to check for legacy files here
# and prompt the user if found.
if not token_file and legacy_path.exists():
```

**✅ 合格：**
```python
# Backward compat: offer to reuse existing token file
if not token_file and legacy_path.exists():
```

## 项目编码约定

### Shell (chatdome 菜单)

- 菜单项使用英文，保持简短。
- 用户输入后立即执行，不加多余的确认提示（除非操作是破坏性的）。

### Python (chatdome-cli.py / controlplane)

- CLI 输出使用 `print()`，emoji 前缀保持一致：`✅` 成功、`❌` 失败、`⚠️` 警告、`ℹ️` 提示。
- 配置读写通过 `chatdome-cli.py` 的子命令完成，不要在 Bash 菜单中直接操作 `config.yaml`。
- 遵循 `ChatDome-docs/docs/00-governance/coding-standards.md` 中的 Python 规范。
