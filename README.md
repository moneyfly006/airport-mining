# Airport-Mining

SSPanel 机场列表采集 + 分类 + 节点获取（一体化）

基于 [lkmvip/sspanel-mining](https://github.com/lkmvip/sspanel-mining)（持续采集 sspanel-uim 站点），
整合多源聚合与自动注册扫描，产出可直接使用的节点。

## 流程（每 12 小时自动运行，见 `.github/workflows/airport-mining.yml`）

```
┌─ Step 1: sspanel-mining 采集器 ─────────────┐
│  Google 搜索扫公网 → collector → classifier │
│  → 产出 classifier/mining_*.csv（尽力而为）  │
└────────────────────────────────────────────┘
        ↓ 最新 CSV
┌─ Step 2: collect_airports.py（本仓库聚合器）─┐
│  1. 多源聚合：最新 CSV + 活跃 GitHub 源       │
│     （lkmvip CSV / hwanz 机场推荐等）         │
│  2. 增量对比：nodes/airport_registry.json     │
│     → 新增机场入队，白名单优先                │
│  3. 扫描：探测 SSPanel → 注册（CF邮箱优先/    │
│     随机163降级）→ 拉节点                    │
│  4. 产出 nodes/scan_*_nodes.txt + registry   │
└────────────────────────────────────────────┘
```

## 目录

- `src/` — sspanel-mining 原版采集器（collector / classifier）
- `src/database/sspanel_hosts/classifier/mining_*.csv` — 采集分类快照（自动更新）
- `scripts/collect_airports.py` — 聚合 + 增量对比 + 并发扫描（核心）
- `scripts/scan_sspanel_airports.py` — 单机场扫描（探测/注册/解析）
- `nodes/airport_registry.json` — 机场状态 registry（白名单/排除/失败，跨运行持久）
- `nodes/scan_*_nodes.txt` — 符合条件的机场节点（base64 订阅）

## 本地运行

```bash
# 1. 采集（可选，需 selenium + Chrome；Google 可能限制）
cd src && python main.py mining --env=production --collector --classifier --source=local

# 2. 聚合 + 扫描（核心）
python scripts/collect_airports.py

# 只探测不注册
SCAN_ONLY_PROBE=1 python scripts/collect_airports.py
```

## 环境变量 / Secrets（可选）

| 变量 | 说明 |
| --- | --- |
| `CF_API_TOKEN` / `CF_GLOBAL_KEY`+`CF_EMAIL` / `CF_EMAIL_DOMAIN` | CF 无限邮箱注册（无则降级随机 163/126 邮箱） |
| `SCAN_CONCURRENCY` | 并发扫描数（默认 8） |
| `SCAN_PER_AIRPORT_TIMEOUT` | 单机场超时秒（默认 45） |

## License

[MPL-2.0](LICENSE)（继承 sspanel-mining）
