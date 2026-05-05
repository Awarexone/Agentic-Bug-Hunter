# Plan: Recon JSON Inventory

實作計畫 — ROADMAP Item 1 的第一個子任務。讓 `/recon target.com` 跑完後，除了現有 `.txt` 檔，**額外**輸出 `recon/<target>/inventory/subdomains.json` 結構化資產清單。

**Status：** 📋 PLANNING（待批准後動工）

**前置文件：**
- [SKILLS_ARCHITECTURE.md](SKILLS_ARCHITECTURE.md) — 9-skill 結構不可動
- [ROADMAP.md](ROADMAP.md) Item 1 — 動機、PR 路線、不移植清單

---

## 1. 目標 (Goal)

每次 `/recon` 結束後產出**機器可讀的資產清單**，達成：

1. **程式化查詢** — 不用 grep 純 text，直接 `jq '.live_subdomains[] | select(.cdn == null)'` 找未上 CDN 的目標
2. **跨 run 比對** — 兩份 JSON 可機械 diff（哪些 subdomain 新出現/消失）
3. **餵 LLM 做攻擊面排序** — `recon-ranker` agent 拿結構化資料比讀亂七八糟的 .txt 強
4. **接 hunt-memory** — 之後可寫進 [memory/audit_log.py](memory/audit_log.py) 做歷史索引

---

## 2. 範圍決策 (Scope)

### In scope（這個 PR 做）

- 一個 schema：`subdomains.json`（仿 communitytools taipower 實際結構）
- 後處理 Python 腳本：解析現有 .txt 輸出 → 產 JSON
- 機械欄位：hostname / ip / cname / cdn / status / title / tech / discovery_method
- Schema 驗證走既有 [memory/schemas.py](memory/schemas.py) 模式
- 維持原 .txt 檔不動（向後相容、上游 PR 接受度高）

### Out of scope（之後另開 PR / 子任務）

- ❌ 其他 5 個 schema（`apis.json`, `web-apps.json`, `network.json`, `cloud.json`, `repositories.json`）— communitytools taipower 也只實作 `subdomains.json`，先 ship 一個再說
- ❌ 每次 hunt 獨立目錄 `recon/$TARGET/<timestamp>/`（ROADMAP Item 1 高 ROI 第 2 項）— 獨立子任務，但**本任務的設計要不阻礙之後做**
- ❌ `analysis/attack-surface.md` 自動產生（ROADMAP Item 1 中 ROI）— 之後改 `recon-ranker` agent 時做
- ❌ Vhost leak / wildcard SSL 戰術 rules（ROADMAP Item 1 高 ROI 第 3 項）— 純內容增補，分開做
- ❌ `notes` 欄位由 LLM 後處理填 — 留空欄位，下個 PR 做
- ❌ `raw/{tool}/` 子目錄重組 — 保留現有 flat 結構
- ❌ Scope checker 整合（`/recon @scope.yaml`）— ROADMAP Item 1 Q1 的另一個獨立議題

---

## 3. 架構決策 (Architecture)

### 選項評估

| 選項 | 描述 | 評估 |
|---|---|---|
| A | 改 [tools/recon_engine.sh](tools/recon_engine.sh) 直接產 JSON | bash 拼 JSON 醜、容易錯、難測；**否決** |
| B | 新增後處理腳本 `tools/recon_to_json.py`，recon_engine.sh 跑完後呼叫 | 邏輯清楚、可單測、不破壞既有 .txt；**選用** |
| C | 純 LLM-driven，SKILL.md 引導 Claude 自己產 JSON | 不確定性高、慢、貴；**否決（核心欄位）** |
| B+C | 機械欄位用 Python，主觀 `notes` 欄位 LLM 後處理 | **採用**（notes 欄位放 out-of-scope） |

→ **本任務只做 B 的機械欄位部分**，notes 欄位留空，之後做。

---

## 4. Schema 定義 (`subdomains.json`)

仿 [taipower 實際 schema](/Users/baihaojun/Documents/communitytools/260429_091549_taipower.com.tw/inventory/subdomains.json)，做幾項微調：

```json
{
  "target": "example.com",
  "scan_date": "2026-05-05T14:23:01Z",
  "scan_duration_seconds": 247,
  "summary": {
    "total_discovered": 265,
    "live_resolved": 49,
    "sources": ["chaos", "subfinder", "assetfinder", "crt.sh"]
  },
  "live_subdomains": [
    {
      "hostname": "api.example.com",
      "ip": "1.2.3.4",
      "cname": null,
      "cdn": null,
      "status": 200,
      "title": "API Gateway",
      "tech": ["nginx", "Express"],
      "discovery_method": ["chaos", "subfinder"],
      "notes": null
    }
  ],
  "all_discovered": ["sub1.example.com", "sub2.example.com"]
}
```

**對比 taipower schema 的調整：**

| 欄位 | taipower | 我們 | 理由 |
|---|---|---|---|
| `tech` | 字串 `"Laravel+Inertia.js+nginx"` | 陣列 `["Laravel", "Inertia.js", "nginx"]` | 程式好處理 |
| `discovery_method` | 沒有 per-asset，只在 summary | 陣列，per-asset | 解 ROADMAP Q2 提到的「無來源歸因」 |
| `scan_date` | 只有 `date: "2026-04-29"` | ISO 8601 timestamp + duration | 為之後 hunt 獨立目錄鋪路 |
| `notes` | 字串（人填） | 預設 null | 本 PR 不做 LLM 後處理 |
| `all_discovered` | 沒有 | 完整 list（含 DNS-only） | 為之後 cross-run diff 必要 |

---

## 5. 實作步驟 (Implementation)

### Step 1: 加 schema 到 [memory/schemas.py](memory/schemas.py)

新增兩個 schema dict（沿用既有的 `validate_schema` pattern）：

- `RECON_ASSET_SCHEMA` — 對應 `live_subdomains[]` 物件
- `RECON_INVENTORY_SCHEMA` — 對應整份 `subdomains.json`

驗證：必填欄位（hostname、status）+ optional 欄位 + 型別檢查。

### Step 2: 新增 [tools/recon_to_json.py](tools/recon_to_json.py)

**輸入：**
```
python3 tools/recon_to_json.py recon/example.com
```

**邏輯：**
1. 讀 `recon/<target>/subdomains.txt` → `all_discovered`
2. 讀 `recon/<target>/live-hosts.txt`（httpx 格式 `https://host [200] [Title] [tech1,tech2]`）→ 大部分欄位
3. 對每個 live host：
   - 解析 status / title / tech（httpx 已標好）
   - 跑 `dig +short <host>` 取 ip + cname（或讀既有 dnsx output 若有）
   - **CDN 偵測**：根據 IP 範圍判斷（CloudFront `54.192.x.x`, Cloudflare `104.16.x.x` 等）— 用 [PD's cdncheck](https://github.com/projectdiscovery/cdncheck) 或內建簡單判斷
   - **Source attribution**：比對 hostname 出現在哪些 source 檔（chaos.txt / subfinder.txt / crtsh.txt 若 recon_engine.sh 保留中間檔）
4. 產出 `recon/<target>/inventory/subdomains.json`，跑 schema 驗證

**估計：** ~200 行 Python，stdlib 為主，可選 cdncheck/dnsx CLI 包裝。

### Step 3: 改 [tools/recon_engine.sh](tools/recon_engine.sh)

末尾加 hook（約 5-10 行）：

```bash
# After all recon steps complete
if [[ "${EMIT_JSON:-1}" == "1" ]]; then
    python3 "$BASE_DIR/tools/recon_to_json.py" "$RECON_DIR" \
        || log_warn "JSON inventory generation failed (non-fatal)"
fi
```

加 `--no-json` flag 解析（opt-out，預設啟用）。

**重要：** recon_engine.sh **保留中間檔**（chaos / subfinder / assetfinder 各自的輸出），讓 source attribution 能跑。目前是 `anew` append 到 `subdomains.txt`，會丟失來源；需在 anew 之前先存各自的 `*-source.txt`。

### Step 4: 改 [commands/recon.md](commands/recon.md)

在 `## Output` 章節加：

```markdown
inventory/subdomains.json   # Structured asset inventory (machine-readable)
```

在 `## What to Do Next` 章節加引導：

```markdown
2. 看 inventory/subdomains.json 找未上 CDN / 跑舊 tech 的 high-value targets
   jq '.live_subdomains[] | select(.cdn == null)' recon/$TARGET/inventory/subdomains.json
```

### Step 5: 改 [skills/web2-recon/SKILL.md](skills/web2-recon/SKILL.md)

加一節說明 JSON inventory 存在 + schema 摘要，引導 Claude 後續分析時優先讀 JSON 而非 .txt。

### Step 6: 單元測試 [tests/test_recon_to_json.py](tests/test_recon_to_json.py)

Fixture：模擬 `recon/example.com/` 目錄，含 fake `subdomains.txt`、`live-hosts.txt`、source files。

測試：
- JSON 產出符合 schema
- `live_subdomains` 數量等於 live-hosts.txt 行數
- `discovery_method` 至少 50% 命中（測試 fixture 設計時控制）
- `summary.total_discovered` 等於 all_discovered 長度
- 缺檔案時 graceful failure（log warn 不 crash）

### Step 7: 更新文件

- [docs/SKILLS_ARCHITECTURE.md](docs/SKILLS_ARCHITECTURE.md)：web2-recon 描述加「produces JSON inventory」
- [docs/ROADMAP.md](docs/ROADMAP.md) Item 1：把「JSON schema 結構化 inventory」標記為 ✅ DONE，附 commit hash

---

## 6. 檔案清單 (File List)

### 新增

| 檔案 | 估計行數 | 用途 |
|---|---|---|
| `tools/recon_to_json.py` | ~200 | 後處理腳本 |
| `tests/test_recon_to_json.py` | ~100 | 單元測試 |

### 修改

| 檔案 | 估計改動 | 用途 |
|---|---|---|
| `memory/schemas.py` | +~50 行 | ReconAsset / ReconInventory schema |
| `tools/recon_engine.sh` | +~10 行 / 改幾行 | 末尾 hook + 保留 source 中間檔 |
| `commands/recon.md` | +~10 行 | 文件 |
| `skills/web2-recon/SKILL.md` | +~20 行 | 引導 Claude 用 JSON |
| `docs/SKILLS_ARCHITECTURE.md` | +1-2 行 | web2-recon 描述微調 |
| `docs/ROADMAP.md` | +幾行 | 標記 done + commit hash |

### 不動

- 所有 SKILL.md（除 web2-recon）
- 所有 agent 檔
- 所有其他 command 檔
- memory/ 其他檔（audit_log.py, pattern_db.py, rotation.py）

---

## 7. 驗證 (Verification)

執行端：

1. `bash tools/recon_engine.sh example.com`
2. 確認 `recon/example.com/inventory/subdomains.json` 存在且是 valid JSON
3. `jq '.summary' recon/example.com/inventory/subdomains.json` 顯示 total / live / sources
4. `jq '.live_subdomains[] | {hostname, ip, status}' ...` 各欄位有值
5. 至少 50% 的 `live_subdomains[].discovery_method` 不是空陣列

測試端：

6. `python3 -m pytest tests/test_recon_to_json.py -v` 全綠
7. 既有測試（[tests/test_scope_checker.py](tests/test_scope_checker.py) 等）不受影響

整合端：

8. 在 Claude session 跑 `/recon example.com` 後問「list high-value targets」，Claude 主動讀 JSON 而非 .txt
9. `bash tools/recon_engine.sh example.com --no-json` 不產 JSON，舊行為完整保留

---

## 8. 上游 PR 拆分建議

對 [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) 拆 3 個 PR，逐個獨立合併：

1. **PR A — Pure tooling**（先合）
   - 新增 `tools/recon_to_json.py` + `tests/test_recon_to_json.py`
   - 加 `memory/schemas.py` 的 schema
   - **不動 recon_engine.sh** — 純粹多一個工具，不改既有行為，最低風險，最易合
   - PR 描述：`Adds a post-processing tool to generate JSON inventory from existing recon output. Design adapted from transilienceai/communitytools (MIT).`

2. **PR B — Wire into pipeline**（A 合後再發）
   - 改 `tools/recon_engine.sh` 加 post-process hook
   - 加 `--no-json` flag opt-out
   - 改 `tools/recon_engine.sh` 保留 source 中間檔（這個改動稍大，需小心）

3. **PR C — Skill & command guidance**（B 合後再發）
   - 改 `commands/recon.md` 加 JSON 輸出說明
   - 改 `skills/web2-recon/SKILL.md` 引導 Claude 用 JSON

---

## 9. 已考量的風險與緩解

| 風險 | 緩解 |
|---|---|
| 上游不喜歡多 Python 依賴 | recon_to_json.py 純 stdlib，無 pip 套件 |
| 現有 .txt 流程被破壞 | hook 失敗只 log warn 不 abort；`--no-json` 完全跳過 |
| Source attribution 不準 | 設 50% 命中為合格門檻，測試強制驗證 |
| 上游 PR 太大被拒 | 拆 3 個獨立 PR，最小破壞面開始 |
| 之後做 per-hunt 獨立目錄時要重做 | recon_to_json.py 接受目錄參數，不假設位置 |
| 上游已有人在做類似 PR | 開工前先去 [PR list](https://github.com/shuvonsec/claude-bug-bounty/pulls) 搜「json」「inventory」「schema」 |

---

## 10. 開放問題 (待確認再開工)

1. **CDN 偵測精度** — 簡單 IP 範圍 vs 整合 PD `cdncheck` CLI。前者零依賴後者準。建議：先做簡單版，留 TODO
2. **Source attribution 實作** — 改 recon_engine.sh 保留中間檔（影響面較大），或讓 recon_to_json.py 重跑 query 比對（慢但乾淨）？建議：前者（一次性改動，之後跑得快）
3. **schema 驗證失敗時行為** — log warn + 寫部分 JSON，還是直接 abort？建議：log warn + 寫不完整 JSON（recon 結果太貴不能丟）
4. **是否包含 `out_of_scope` 欄位** — taipower JSON 沒有 `out_of_scope`，但 ROADMAP Q1 提到 scope 整合是另一個獨立議題。本 PR 不做。
