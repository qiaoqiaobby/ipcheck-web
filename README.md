# ipcheck

网络环境诊断工具，一键检测 IP、DNS、代理、风控、时区，确保 AI 工具流畅运行。

[English](./README_EN.md)

![screenshot](./screenshot.png)

## 为什么需要这个工具

想让 Claude Code、OpenAI API、Cursor 等 AI 工具流畅稳定运行，网络环境配置至关重要。以下问题可能影响使用体验：

- **IPv6 泄露真实地址** — 代理通常只处理 IPv4，IPv6 会暴露你的实际位置
- **DNS 泄露** — 使用国内 DNS 会暴露真实地理位置
- **IP 风险过高** — 机房 IP 或被滥用的 IP 可能影响连接质量
- **时区不一致** — 本地时区配置与 IP 所在地不匹配

`ipcheck` 一键检测这些问题，确保你的 AI 工具流畅稳定运行，尤其 Claude 启动之前先检测下，原因你懂得，规避封号。

## 功能

| 检测项 | 说明 |
|--------|------|
| 局域网 IP / IPv6 | 检测本机 IP，确认 IPv6 是否已禁用 |
| DNS 服务器 | 识别 DNS 来源（国内/国外），标注已知 DNS 服务商 |
| 公网 IP 信息 | 出口 IP、国家、地区、ISP、运营商 |
| 代理检测 | 环境变量代理配置、系统代理、TUN/VPN 迹象、IP 是否被标记为代理 |
| IP 类型 | 住宅 IP / 机房 IP 识别 |
| IP 风险评分 | 通过 proxycheck.io 查询风险分数 |
| 滥用记录 | 通过 StopForumSpam 查询 IP 是否被举报 |
| 时区一致性 | 对比本地 CLI 时区与公网 IP 所在时区是否匹配 |
| 综合结论 | 汇总各项风险，一句话判断当前环境 Claude 使用风险高低 |

## 安装

```bash
pip install ai-ipcheck
```

升级到最新版：

```bash
pip install --upgrade ai-ipcheck
```

## 使用

```bash
ipcheck
```

### 环境要求

- Python 3.10+
- 支持 macOS / Linux / Windows

## 结果说明

**局域网 & DNS** — IPv6 建议禁用，大部分代理不处理 IPv6 流量，开启后可能同时暴露两个不同地区的 IP 地址。如果检测到国内 DNS，需要在代理软件中调整 DNS 设置。

**公网 IP 信息** — 显示经过代理后的出口 IP、所在国家/地区、ISP 和时区。这些信息直接影响 AI 服务对你请求来源的判断。

**代理检测** — `ipcheck` 会同时展示环境变量代理、macOS 系统代理和 TUN/VPN 迹象。系统代理只代表系统配置状态，不等于所有 CLI 流量都会继承；Codex、Claude Code 等带沙箱或独立网络栈的工具，可能需要显式设置 `HTTP_PROXY` / `HTTPS_PROXY`，或者开启 TUN 模式兜底。

**IP 风险评估** — 检测 IP 是住宅还是机房类型。机房 IP 不一定有问题，但会进一步查询风险评分和滥用记录。如果风险评分偏高，建议更换节点。

**时区一致性** — 对比本地 `$TZ` 环境变量（或系统时区）与公网 IP 所在时区。保持一致可以获得更好的服务体验。建议在 shell 配置中设置 `TZ` 为与 IP 所在地匹配的 IANA 时区（如 `America/Los_Angeles`）。

**综合结论** — 报告末尾会汇总 IPv6、DNS、IP 风险、时区四项，给出一句话定论：当前环境 Claude 使用是「低风险」还是「高风险」。建议启动 Claude 前先看这一行。

## License

[MIT](LICENSE) © 2026 stormzhang
