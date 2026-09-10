# Sing-box & Clash 统一规则枢纽 (Rule Hub V2)

现代化规则编排与双向自动化编译枢纽，集成了 **Clash / Mihomo** 与 **Sing-box** 全格式输出。

## 🌟 核心架构亮点

1. **单仓闭环驱动**：
   - 彻底废除跨仓库下载依赖，私有规则修改 1 次，秒级同时编译出全套 **Sing-box (`.json`, `.srs`)** 与 **Clash (`.yaml`, `.txt`)**。
2. **AI 规则全自动脱手 (Zero-Maintenance AI Rules)**：
   - 不再人工维护 AI 规则，自动对接上游专业 AI 代理库（`VPSDance/ai-proxy-rules`），每日同步 600+ 条最新主流 AI 服务规则（OpenAI、Claude、Gemini、Copilot、Cursor、Suno 等）。
3. **故障熔断保护 (Fail-Safe)**：
   - 上游外部网络偶发抖动或下载为空时，自动保留上一健康版本，绝不产生破坏性空规则。
4. **内容哈希感知 (Smart Diff)**：
   - 相同内容绝不变更磁盘时间戳，杜绝 Git 仓库无意义膨胀与脏提交。
5. **自动化测试门禁 (Self-Test Suite)**：
   - 每次编译后自动断言关键规则（如 Emby 折纸域名、出站格式），有误立即在 CI 中阻断发布。

## 📂 目录结构

```text
├── custom_rules/          # 👈 【用户私有规则】(日常修改只动这里，支持 .yaml/.txt/.json)
│   ├── nas.yaml          # NAS 局域网服务
│   ├── fuwuqi.yaml       # 自建/VPS 服务器
│   ├── vilm.yaml         # 国内直连白名单
│   ├── ddli.yaml         # 自定义代理/API 站点
│   ├── emby.yaml         # 自建/公益 Emby 节点
│   └── jujt.yaml         # 阻断/特殊策略
├── external_links.txt     # 👈 【外部公共大规则源】(第三方规则订阅列表，含 AI 聚合订阅)
├── build.py               # 👈 【工业级轻量构建引擎】(并发抓取/去重/格式分流/SRS编译/自检)
├── .github/workflows/     # 👈 【GitHub Actions 流水线】(定时构建/提交触发/手动运行)
├── clash_rules/           # 📦 【Clash / Mihomo 产物区】(*.yaml, *.txt)
└── rule/                  # 📦 【Sing-box 产物区】(*.json, *.srs)
```

## 🛠️ 日常操作指南

* **新增/修改 Emby 节点或私有域名**：
  直接编辑 `custom_rules/emby.yaml` 或 `custom_rules/ddli.yaml`，推送到 main 分支后 GitHub Actions 会在 20~30 秒内全自动编译发布。
* **增删外部上游订阅**：
  直接在 `external_links.txt` 增减 URL。
* **本地手动构建**：
  ```bash
  pip install pyyaml
  python build.py
  ```
