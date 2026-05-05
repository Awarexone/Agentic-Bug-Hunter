# Optimization Roadmap

想優化的項目清單。多數只記要做什麼；遇到跨 session 必要的設計決定或對比結論，會直接寫在該項目下。

---

## To do

### 1. 優化 Recon 紀錄 — 讓 recon 結果能存下來、之後查得到

#### 🔥 前置：修正 `/recon` 指令呼叫 production 腳本（2026-05-05 發現，✅ 完成 commit `a6a6d42`）

**問題**（從另一個 session 實測 `/recon matters.news` 觀察到）：

1. [commands/recon.md](commands/recon.md) 是 declarative guide — Claude 看完**自己重新詮釋**，**完全沒呼叫** [tools/recon_engine.sh](tools/recon_engine.sh) production 腳本
2. 結果：production 腳本的 trap、timeout、Phase 3-8（port scan / URL crawl / JS 分析 / param 抽取 / config exposure / CI/CD 掃描）**全部沒跑**
3. Claude `cd recon/$TARGET` 後又 `mkdir -p recon/$TARGET`，造成雙層 `recon/matters.news/recon/matters.news/findings.md`
4. 我們的 [tools/recon_to_json.py](tools/recon_to_json.py) 假設 production 腳本的目錄結構（`subdomains/subfinder.txt`），但實際 `/recon` 跑出扁平結構（`subfinder.txt`），**JSON inventory 完全擦肩**

**修法：** ([commit a6a6d42](https://github.com/letztek/claude-bug-bounty/commit/a6a6d42))
- ✅ [commands/recon.md](commands/recon.md) 第一步直接 `bash tools/recon_engine.sh $TARGET`
- ✅ 接著自動 `python3 tools/recon_to_json.py recon/$TARGET` 產 JSON
- ✅ 用絕對路徑（`$(git rev-parse --show-toplevel)`）避免 cwd 切換造成的雙層 bug
- ✅ Output Layout 文件改成 8-phase 子目錄結構（subdomains/ live/ ports/ urls/ js/ dirs/ exposure/ params/ cicd/ inventory/）
- ✅ 加 "Common Mistakes to Avoid" 章節明文警告 — 不要 inline 重寫 pipeline、不要 cd 進子目錄、不要跳過 JSON 步驟
- ✅ "What to Do Next" 提供 3 條 jq 查詢示範（按 CDN / tech / status 過濾 attack surface）

#### Q&A（2026-05-05 已調查）

**Q1：`/recon domain` 怎麼定義 scope？能不能用 `/recon domain @文件` 自訂範疇？**

A：目前 [`/recon`](commands/recon.md) **不做 scope 檢查**，直接對使用者給的 target 跑 pipeline。Scope 機制散在三層：

- 執行層 [tools/scope_checker.py](tools/scope_checker.py) — `ScopeChecker` 類別，但 `/recon` 沒接（只有 `/autopilot` 與 `tools/hunt.py` 用到）
- 資料來源 [mcp/hackerone-mcp/server.py:228](mcp/hackerone-mcp/server.py:228) — `structured_scopes` GraphQL query 從 H1 拉
- 使用者意圖 [commands/scope.md](commands/scope.md) — 純 LLM 引導，無檔案載入

**目前不支援 `/recon domain @file`。** 要加支援需在 `tools/recon_engine.sh` / `commands/recon.md` 加 `--scope-file` flag，YAML 格式（`in_scope` / `out_of_scope` / `excluded_classes`）餵 `ScopeChecker`。基礎設施齊備（已有測試 [tests/test_scope_checker.py](tests/test_scope_checker.py)），實作成本低。

**Q2：`/recon` 產生哪些檔案？**

A：全部 plain text 在 `recon/<target>/`：`subdomains.txt`、`live-hosts.txt`、`urls.txt`、`api-endpoints.txt`、`idor/ssrf/xss/sqli/redirect/lfi-candidates.txt`、`nuclei.txt`。

限制：
- 沒有 JSON / 結構化 metadata
- 沒有 timestamp，重跑直接 `anew` append（同一檔案累積，無法區分哪次跑出來）
- 沒有 tech stack 自動聚合
- 沒有來源歸因（不知道哪個 subdomain 是 Chaos / subfinder / crt.sh 哪個發現的）
- 沒有跨 run diff 能力
- **不寫進 hunt-memory** — 跟 [memory/audit_log.py](memory/audit_log.py) 的 JSONL 系統脫鉤
- Recon 出去的 request **不過 `scope_checker`**

#### 參考設計：communitytools 移植方向（2026-05-05 對比結論）

**來源：** [transilienceai/communitytools](https://github.com/transilienceai/communitytools)（MIT，本地路徑 `/Users/baihaojun/Documents/communitytools`）

**核心差異一句話：** claude-bug-bounty = 扁平 .txt + 每次 overwrite + 純 hunt-memory JSONL；communitytools = 6 層目錄 + JSON schema + 每次 hunt 獨立目錄 + raw/ 保留原始工具輸出。

**真實參考實例：** `/Users/baihaojun/Documents/communitytools/260429_091549_taipower.com.tw/` 是 communitytools 對 taipower.com.tw 真實 recon 的輸出，可作為移植目標的對照樣本。內含 `inventory/subdomains.json`（49 個 live subdomain 含 IP/CDN/tech/notes 完整 metadata）、`analysis/attack-surface.md`（自動產生的網路拓撲表 + high-value targets 排序）、`raw/{subfinder,amass,dns,nmap,ffuf,headers,iis}/`、`artifacts/pentest-report.json`（CVSS/CWE/OWASP/MITRE 完整 finding metadata）。

##### 要移植的（高 ROI）

1. **JSON schema 結構化 inventory** 📋 計畫中
   - 新增 `recon/<target>/inventory/subdomains.json`（與既有 `subdomains.txt` 並存，不破壞向後相容）
   - Schema 參考 communitytools [`formats/reconnaissance.md`](/Users/baihaojun/Documents/communitytools/formats/reconnaissance.md)：每個 asset 含 `{hostname, ip, cdn, status, title, tech, notes, discovery_method}`
   - **直接解決** Q2 列出的「無 JSON、無來源歸因、無 tech 聚合」三大限制
   - 動到的檔案：[tools/recon_engine.sh](tools/recon_engine.sh) 加 `--emit-json` flag、[memory/schemas.py](memory/schemas.py) 加 `ReconAsset` schema
   - **詳細實作計畫：[RECON_JSON_INVENTORY_PLAN.md](RECON_JSON_INVENTORY_PLAN.md)**

2. **每次 hunt 獨立輸出目錄**
   - 改 `recon/$TARGET/` → `recon/$TARGET/<YYYYMMDD_HHMMSS>/`，加 symlink `recon/$TARGET/latest`
   - 這是「跨 run diff」的**前提條件**（沒有獨立目錄就沒法比較兩次跑的差異）
   - 動到的檔案：[tools/recon_engine.sh](tools/recon_engine.sh) `RECON_DIR` 變數計算

3. **Vhost leak / Wildcard SSL / 管理面板偵測戰術 rule**
   - communitytools [`skills/reconnaissance/SKILL.md`](/Users/baihaojun/Documents/communitytools/skills/reconnaissance/SKILL.md) 第 47-50 行有 4 條極具體的戰術：
     - HTTP response header vhost leak（`X-Backend-Server` / `X-Forwarded-Host` 暴露內部 hostname）
     - Wildcard SSL cert (`*.domain.tld` SAN) 觸發 vhost brute-force
     - 無 ffuf 時用 shell loop 跑 vhost 枚舉
     - 管理面板特徵偵測（Nginx UI / Cockpit / Webmin / phpMyAdmin）+ 已知 API endpoint
   - 補進 [skills/web2-recon/SKILL.md](skills/web2-recon/SKILL.md)（不需改架構，純內容增補）

##### 要移植的（中 ROI）

4. **`analysis/attack-surface.md` 自動產生**
   - taipower 範例顯示包含：執行摘要 + 網路拓撲表（CDN/Corporate/eLearning/CCTV/VPN segment）+ 按優先度排序的 high-value targets（含技術細節與 attack angles）
   - 當前 [agents/recon-ranker.md](agents/recon-ranker.md) 邏輯類似但輸出**不固化成檔案**
   - 改規定 recon-ranker 必須寫到 `recon/<target>/<run>/analysis/attack-surface.md`

##### 不移植的（已決策）

- **完整 6-directory engagement 結構**（`findings/` `artifacts/` `reports/` 全套）— 這是 pentest 交付導向（含 PDF 報告生成），bug bounty 平台直接在表單貼字、用不到 PDF。Bug bounty 已有自己的 `report-writing` 流程
- **拆 reconnaissance / osint / techstack-identification 三個 skill** — 違反 [SKILLS_ARCHITECTURE.md](SKILLS_ARCHITECTURE.md) 已確立的「9-skill 結構穩定」原則。改在 `web2-recon` 內加章節即可

##### PR 路線（對 shuvonsec/claude-bug-bounty 上游）

- 雙邊 MIT，license 互相相容
- 上游 [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) 接受外部 PR（近期 merged：[#23 TRIKKSS](https://github.com/shuvonsec/claude-bug-bounty/pull/23)、[#16 venkatas](https://github.com/shuvonsec/claude-bug-bounty/pull/16)）
- **建議拆小 PR，每個 PR 解一件事**，例如：
  - `feat(recon): structured JSON inventory output (domains.json schema)`
  - `feat(recon): per-hunt timestamped output directory + latest symlink`
  - `feat(recon): vhost leak + wildcard SSL tactical rules in SKILL.md`
- PR 描述附 attribution：`Design adapted from transilienceai/communitytools (MIT)`
- 用 opt-in flag（如 `--emit-json`）保留向後相容，避免上游因 breaking change 拒絕

---

### 2. Bypass WAF skills 優化 — 強化 WAF 繞過相關內容

*（細節之後展開）*

---

### 3. 串接取得 CVE 資訊工具 — 整合更多 CVE 來源

**額外想法（2026-05-05）：** communitytools 在 top-level [`CLAUDE.md`](https://github.com/transilienceai/communitytools/blob/main/CLAUDE.md) 有一條規則：「Whenever a CVE ID (pattern `CVE-YYYY-NNNNN`) is mentioned, ALWAYS run `python3 tools/nvd-lookup.py <CVE-ID>`」。在 claude-bug-bounty 可改用 [`.claude/settings.json`](.claude/settings.json) 的 hook 機制，自動偵測 CVE pattern 觸發查詢，比手動規則更可靠。

*（其他細節之後展開）*

---

### 4. `recon_engine.sh` 加 `--passive-only` flag

**動機（2026-05-05 從 matters.news hunt 發現）：** 不少賞金程式明確禁止「自動化探測工具」。例如 Matters 政策：「不使用漏洞掃描軟件或者其他自動化探測工具…我們也有可能會凍結你的帳號並封鎖對應的 IP 地址。」目前 [tools/recon_engine.sh](tools/recon_engine.sh) 沒有 passive-only 模式，全跑會違規：

| Phase | 動作 | passive 安全？ |
|---|---|---|
| 1 | subfinder/amass/crt.sh/wayback | ✅ |
| 2 | httpx 輕量探活 | ✅（單 request/host） |
| **3** | **nmap top 1000 ports** | ❌ |
| 4 | gau | ✅ |
| 5 | JS curl 抓 public JS | ✅ |
| **6** | **ffuf 目錄爆破** | ❌ |
| **6.5** | **配置檔暴露探測** | ❌ |
| 7 | URL 參數抽取 | ✅ |
| 8 | CI/CD GitHub 掃描（external） | ✅ |

**修法：** 加 `--passive-only` flag 跳過 phase 3 / 6 / 6.5。Default 仍 active 全跑。

---

*（陸續補充中）*

---

## Done

- **2026-05-05** — [SKILLS_ARCHITECTURE.md](SKILLS_ARCHITECTURE.md)（commit `213f546`）— plugin 架構說明 + drift 清單
- **2026-05-05** — JSON inventory 工具（commit `e17791f`）— [tools/recon_to_json.py](tools/recon_to_json.py) + [memory/schemas.py](memory/schemas.py) `RECON_INVENTORY_*` schema + [tests/test_recon_to_json.py](tests/test_recon_to_json.py)
- **2026-05-05** — `/recon` 指令修正（commit `a6a6d42`）— [commands/recon.md](commands/recon.md) 改成直接呼叫 production 腳本 `tools/recon_engine.sh`，解決 cwd 切換造成的雙層目錄 bug 與 production 腳本沒被觸發的問題
