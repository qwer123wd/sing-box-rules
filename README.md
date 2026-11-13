# sing-box-rules

每周自动生成 `all.srs` 和条目去重后的 `proxy.srs`。仓库仅包含公开规则、构建脚本和审计信息，不包含节点、账号凭据或个人 sing-box 配置。

## 合并与去重约定

```text
C = media ∪ microsoft ∪ github ∪ ai ∪ telegram
all = 原始 proxy ∪ C
proxy = 原始 proxy 中，按字段删除与 C 完全相同的字符串条目
```

这是**同类型、同文本的条目去重**，不是按域名实际匹配范围做严格差集：

- `domain`、`domain_suffix`、`domain_keyword`、`domain_regex` 分别去重，不相互替换。
- 不修改大小写、前导点、关键词或正则；输出排序固定，便于审查差异。
- 精确域名 `video.example.com` 与后缀 `example.com` 不视为重复。去重后的 proxy 仍可能与其他分类有匹配重叠。
- `all` 严格来自本仓库配置的六份输入，不包含另外手工补充的规则。
- 上游引入逻辑、反向匹配、IP 或其他未支持字段时，构建失败并保留上次成功产物，不会强行展平改变含义。

## 上游来源与许可

| 输入 | 来源 |
| --- | --- |
| media、ai、原始 proxy | [DustinWin/ruleset_geodata](https://github.com/DustinWin/ruleset_geodata/tree/sing-box-ruleset) |
| microsoft、github | [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/tree/sing/geo/geosite) |
| telegram | [原始公开规则](https://github.com/qwer123wd/asd123/blob/main/singbox/telegram.json) |

精确输入 URL 见 [config/sources.json](config/sources.json)。前两项上游采用 GPL-3.0，本仓库保留来源说明并采用 GPL-3.0；上游规则的权利归原作者所有。编译器使用官方 SagerNet/sing-box 发布版。

## 下载与引用

- [all.srs](https://raw.githubusercontent.com/qwer123wd/sing-box-rules/main/all.srs) · [all.json](https://raw.githubusercontent.com/qwer123wd/sing-box-rules/main/all.json)
- [proxy.srs](https://raw.githubusercontent.com/qwer123wd/sing-box-rules/main/proxy.srs) · [proxy.json](https://raw.githubusercontent.com/qwer123wd/sing-box-rules/main/proxy.json)
- [构建记录](build-info.json) · [SHA-256](SHA256SUMS)

SFI 配置示例：

```json
{
  "type": "remote",
  "tag": ["all", "proxy"],
  "format": "binary",
  "url": "https://raw.githubusercontent.com/qwer123wd/sing-box-rules/main/{tag}.srs",
  "update_interval": "1d"
}
```

请先从旧远程规则组的 `tag` 数组中移除 `all` 和 `proxy`，再加入上述规则组，避免同名标签重复。其他分类继续使用原来的地址；原有路由优先级不会因为换下载地址而自动改变。客户端每 1 天检查一次，因此不会因原来的 100 天缓存而错过每周更新。

## 自动更新

- 每周一北京时间 **04:23**（UTC 周日 20:23）运行；GitHub 调度可能延迟，不是精确时钟服务。
- 可在 **Actions → Update rule sets → Run workflow** 手动更新。
- 每次下载六份上游，检查结构和数量后才编译；任一失败不会发布半套文件。
- 每次成功写入 `build-info.json`，记录时间、输入哈希、各字段数量和输出哈希；规则未变化时仅审计记录变化。
- 单个来源条目数量下降超过 40% 时默认停止。确认上游确实做了合理精简后，可手动运行并勾选 `allow_large_drop`。
- 每次只用一次 Git 提交发布全部成功产物。推送遇到分支变动会失败，不强制覆盖。
- 工作流仅需仓库内置的 `GITHUB_TOKEN` 的 `contents: write` 权限，不需个人长期 Token；仓库若有额外分支保护，需要另行适配。
- 公共仓库长期无活动时，GitHub 可能停用定时任务；请保留 Actions 的失败通知，并留意最后成功时间。定期审计提交是正常仓库活动，但不是“永远不停”的保证。

## 本地复现

需要 Python 3.9+ 和 curl，支持 Apple Silicon macOS、Linux x86_64。

```sh
python3 -m unittest discover -s tests -v
python3 scripts/install_compiler.py
python3 scripts/build.py
```

安装脚本只下载到本目录的 `.tools/`，不改系统 PATH。编译器固定为 **1.15.0-alpha.13**，下载后核对发布资产 SHA-256 和版本。输出仅使用基础域名字段，源格式为 v2；两份 SRS 均须成功编译并反编译验证后才能发布。

## 验证范围

单元测试覆盖：精确去重、跨字段区别、字符串保留、集合关系、确定性排序、输入异常、新字段拒绝、异常缩减保护、编译失败时保留旧文件。编译和反编译通过不代表每个域名的实际网络访问一定可达；后者还取决于使用者的 DNS、路由和节点。
