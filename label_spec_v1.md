# Vector (SG) 内部标签与血缘隔离规范 v1.0（`label_spec_v1.md`）

> **文档状态**：v1.0 正式内部规范（ACTIVE · Phase 0 退出标准 #1 落地文件）  
> **生效日期**：2026-11-24（北京时间）  
> **主体**：Vector (SG)，新加坡公司  
> **配套文件**：[白皮书 v0.2](whitepaper_v0.2.md) · [路线图 v0.2](roadmap_v0.2.md) · [盲测基准](benchmark.md) · 自动化校验脚本 [validate_labels.py](auto_tracer/validate_labels.py)  
> **核心铁律**：官方权威标签与模型/人工推断**物理及逻辑双隔离**；缺少任一必填证据字段的条目一律拦截进入 `QUARANTINE`（待核区），禁止进入正式风险评分或对外报告。

---

## 一、四级证据等级与物理/逻辑隔离架构

所有实体/地址标签必须先定级、再入对应隔离区，**严禁跨级混存或隐式升级**：

| 证据等级 | 命名 | 合法数据来源 | 允许驱动的系统行为 | 严格禁止的行为 | 存储隔离区（Table / Store） |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Grade-A`** | **官方制裁原文级** | OFAC SDN 官方发布 XML/CSV（如现有 184 条朝鲜相关地址，SDN `2026-10-21` / 检索 `2026-10-27`） | 精确匹配告警、高危风险提示（附官方出处与名单日期） | 严禁混入第三方推测地址、严禁混入 FBI 公告、严禁自动等同司法冻结结论 | `labels_grade_a_official_sanctions` |
| **`Grade-B`** | **官方执法公告级** | FBI / DOJ / 新加坡 SPF / 司法部公开公告（如后续逐条核验的 FBI Bybit 公告） | 独立来源高危风险信号（明确标注 `Source: FBI Advisory` 与公告日） | **绝不混入 `Grade-A` OFAC 库**；未经逐条地址与链核对前不得入正式库 | `labels_grade_b_official_le` |
| **`Grade-C`** | **公开安全复盘与基础设施级** | 知名安全机构公开复盘（PeckShield / SlowMist / CertiK / BlockSec）、官方合约文档、Etherscan/BscScan 公开枢纽标签（CEX 热钱包、DEX 路由、桥、Multicall3） | Frontier 防图爆炸停手（`HUB_CATEGORIES`）、断点识别、辅助背景注释 | 不得仅凭社区抓取标签（如 Etherscan 众包标签）直接定性恶意或犯罪 | `labels_grade_c_reference_hubs` |
| **`Grade-D`** | **分析假设与聚类推断级** | 内部取证推断、图聚类结果、启发式 CEX 充值匹配、外部模型候选归因 | 报告中单列为 **`HYPOTHESIS · REVIEW`**（附置信度与反例），供人工/律师复核 | 严禁直接触发自动阻断；严禁写入 `Grade-A/B`；不得省略反例与不确定性 | `labels_grade_d_hypotheses` |
| **`QUARANTINE`** | **待核隔离区** | 任何缺少 8 项必填字段、链别模糊、格式异常或来源未核验的待入库条目 | **仅限内部数据清洗脚本读取** | **完全隔离于风险评分、Frontier 决策、API 输出与对外报告之外** | `labels_quarantine_pending` |

---

## 二、8 项强制必填证据字段（Schema v1.0）

任何拟进入 `Grade-A`、`Grade-B`、`Grade-C` 或 `Grade-D` 正式库的单条记录，**必须全部齐备以下 8 项必填字段**（由 [validate_labels.py](auto_tracer/validate_labels.py) 强制校验，缺任一项直接分流至 `QUARANTINE`）：

| # | 字段名 | 类型 | 必填规则与格式约束 | 示例 |
| :---: | :--- | :--- | :--- | :--- |
| 1 | `source_url` | `string (URI)` | 可访问的官方原始发布链接、公告 URL 或内部工单/复盘归档编号（`https://...` 或 `internal://case/...`） | `https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists` |
| 2 | `evidence_excerpt` | `string` | 原始出处中对应本地址/实体的精准摘录或关键交易/合约证明（≥ 10 字符，不可为空或泛称 `"公开情报"`） | `"OFAC SDN Entry: LAZARUS GROUP — Digital Currency Address - ETH 0x..."` |
| 3 | `chain` | `enum` | 必须显式指定适用链：`bsc` / `ethereum` / `opbnb` / `polygon` / `arbitrum` / `optimism` / `base` / `tron` / `solana` / `bitcoin`（**禁止用 `"any"` 混填未知链**） | `ethereum` |
| 4 | `retrieved_at_utc` | `ISO-8601 UTC` | 实际抓取/核验时间（`YYYY-MM-DDTHH:MM:SSZ`）；对 `Grade-A/B` 同时建议记录 `effective_date_utc`（名单生效日） | `2026-10-27T00:00:00Z` |
| 5 | `evidence_grade` | `enum` | 严格限定为 `Grade-A` / `Grade-B` / `Grade-C` / `Grade-D` | `Grade-A` |
| 6 | `confidence` | `float [0,1]` | 置信度数值：`Grade-A` 固定 `1.0`（原文存在性，非司法定性）；`Grade-B` `0.90–1.0`；`Grade-C` `0.70–0.95`；`Grade-D` 严禁高于 `0.85` | `1.0` |
| 7 | `reviewer` | `string` | 人工复核人标识（如 `Lucy Li`）或经审定的确定性同步管线版本号（如 `ofac-sync-v1.0`） | `Lucy Li` |
| 8 | `status` | `enum` | 生命周期状态：`active` / `disputed` / `revoked` / `expired` | `active` |

### 附加标识字段（主键与规范化）
- `address`（必填）：EVM 链统一小写校验（`0x` + 40 位十六进制）；TRON（`T...`）/ Solana（Base58）**保持大小写敏感**。
- `entity` / `label` / `category`（必填）：`category` 严格取自 `sanctioned / exploit / mixer / scam / fraud / bridge / cex_hot / cex_deposit / dex_router / victim / benign_contract / other`。

---

## 三、防误伤与实体关系红线（Anti-False-Merge Rules）

1. **成员关系 ≠ 资金边**：官方名单（如 Bitget / OFAC 披露的实体地址集合）仅证明 `Entity Membership`，**严禁据此凭空补齐地址之间的资金转移边**。
2. **收款 ≠ 共同控制**：某地址收到来自 `Grade-A` 或 `exploit` 地址的转账（包括空投、地址投毒、还款、商品收款），**绝对不足以**将其自动标为 `sanctioned` 或 `exploit`。
3. **共享基础设施 ≠ 同伙关系**：多个地址共享同一个 CEX 热钱包、跨链桥、DEX 路由或 `Multicall3` 透传合约，**严禁归并为同一控制主体**。
4. **受害者与中立合约显式豁免**：`victim`、`cex_hot`、`dex_router`、`bridge`、`benign_contract` 永不进入恶意集合（`MALICIOUS_CATEGORIES`）。

---

## 四、名单撤销、异议与历史回放机制（以 Tornado Cash 移出为例）

1. **禁止静默硬删除（No Silent Hard-Delete）**：
   - 当官方名单移出某地址时（例如 **Tornado Cash 相关地址已于 `2025-03-21` 自 OFAC SDN 移出**），不得直接从历史记录物理抹除，而须执行状态迁移：
     - `status: "active"` → `status: "revoked"`
     - 补充 `revoked_at_utc: "2025-03-21T00:00:00Z"` 与 `revocation_source_url`（官方移出公告链接）。
2. **双时间视图**：
   - **实时筛查 / API**：仅匹配 `status == "active"` 条目（因此当前 OFAC `Grade-A` 184 条朝鲜库**不含**已移出的 Tornado Cash）；
   - **历史案件复现**：按案发当时冻结的 `label_snapshot_version` 与 `effective_date_utc` 精确回放，确保历史报告永久可复核。
3. **误报异议通道**：任何对 `Grade-C/D` 标签的申诉，须立即将条目置为 `status: "disputed"`，写入 `dispute_log`，复核后记录改判人、时间戳与理由。

---

## 五、FBI 等新增官方公告入库核验 SOP（独立 `Grade-B`）

面向后续拟核验的 FBI（含 Bybit 等公告）或其他执法披露，强制执行 4 步隔离流程：
1. **原始归档**：保存官方公告 PDF/HTML 原件及 SHA-256，记录 `source_url` 与发布日期；
2. **逐条链别与格式校验**：逐一核对每条地址对应的精确链（ETH / BSC / BTC / SOL / TRON），校验地址校验和与链上真实存在性；
3. **独立建库**：写入 `labels_grade_b_official_le`（`evidence_grade = "Grade-B"`），**严禁合并写入 `Grade-A` OFAC 184 条种子库**；
4. **人工签核**：在 `reviewer` 字段署名并更新快照版本号（如 `FBI-BYBIT-v1`）后方可启用。

---

## 六、现有 `OnchainInvestigator` 标签库首次合规体检结果（2026-11-24）

使用 [validate_labels.py](auto_tracer/validate_labels.py) 对现有两份标签文件执行首次强制校验（完整 JSON 报告归档于 [label_audit_2026-11-24.json](evidence/label_audit_2026-11-24.json)）：

| 标签文件 | 总条数 | 符合 v1.0 直接入库 | 拦入 `QUARANTINE` | 主要缺失 / 违规字段 |
| :--- | :---: | :---: | :---: | :--- |
| `external_labels.json`（OFAC 同步） | `489` | `0` | `489` | 缺 `source_url`、`evidence_excerpt`、`chain`（仅存 `currency`）、`retrieved_at_utc`、`evidence_grade`、`confidence`、`reviewer`、`status` |
| `etherscan_labels.json`（浏览器枢纽） | `44,104` | `0` | `44,104` | 缺 6 项溯源/等级/状态字段；另有 **`1,061` 条** `chain` 字段不在规范链枚举内 |

### 对 `OnchainInvestigator/label_store.py` 的 3 项最小改造清单
1. 在 SQLite `entity_labels` 表增加 `evidence_grade`, `source_url`, `evidence_excerpt`, `retrieved_at_utc`, `effective_date_utc`, `reviewer`, `status`, `revoked_at_utc` 列，或拆分为按 Grade 隔离的物理表；
2. 将 `external_labels.json`（OFAC 同步脚本输出）补齐 `source_url`、`chain` 映射、`retrieved_at_utc`、`effective_date_utc`、`evidence_grade="Grade-A"`、`confidence=1.0`、`reviewer="ofac-sync-v1"`、`status="active"`；
3. 将 `etherscan_labels.json` 明确打标为 `evidence_grade="Grade-C"`（仅作枢纽停手与参考注释，永不参与恶意定性），清洗掉 1,061 条非法 `chain` 记录并补全来源 URL 与抓取时间戳后再移出 `QUARANTINE`。
