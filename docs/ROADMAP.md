# Optimization Roadmap

想優化的項目清單。多數只記要做什麼；遇到跨 session 必要的設計決定或對比結論，會直接寫在該項目下。

---

## 戰略方向（2026-05-06 重新對齊）

探索 recon 優化後，認知到一件事：**recon = commodity，hunt = moat**。

- Recon 本質是包裝社群工具（subfinder / httpx / nuclei / gau / ffuf）— 別人也有，AI 加值有限
- Claude-bug-bounty 的獨特價值在 **hunt 階段**：A→B→C chain 推理、bug class 模式辨識、7-Question Gate 嚴格驗證、跨 hunt pattern learning、bug bounty 平台特化（H1/Bugcrowd/Immunefi 報告風格）— 這些 AI 才能做
- **後續 ROADMAP 重心移到 hunt 側**

Recon 線只保留**已完成的 bug fix（commits `a6a6d42` + `e17791f`）**，不再深挖。

---

## Active items

### 1. WAF bypass skill 強化 🎯 下一個動手做

**為什麼優先：** 實戰 hunt 最常撞牆的就是 403 / WAF block。AI 系統化試 N 種 bypass 比手動 google 高效太多 — 這是 AI 加值最直接的地方。

**現況：** [skills/security-arsenal/SKILL.md:165](../skills/security-arsenal/SKILL.md) 只有 1 節「WAF Bypass」。全 repo 加起來不到 10 處 WAF 提及。

**方向：** 補強 security-arsenal 的 WAF bypass 章節，含：
- WAF fingerprinting（wafw00f / response headers / CSP）
- 各 vendor bypass 表（Cloudflare / Akamai / AWS WAF / Imperva / F5）
- Encoding chain（URL → unicode → HTML entity → mixed case → null byte）
- HTTP-level evasion（verb tampering、parameter pollution、chunked encoding）
- Origin IP 發掘（Censys / Shodan / 歷史 DNS / SSL cert / mail header / dev subdomain）
- Rate-limit bypass（X-Forwarded-For / 分散來源 / slow-rate）

---

### 2. pattern_db → hunt 行為回饋 🥇 高槓桿

**痛點：** [memory/pattern_db.py](../memory/pattern_db.py) 目前**只是被動記錄** — 下次 `/hunt target.com` 時 AI 不會去讀「我之前在這 target 用 PUT method 找到 3 次 IDOR」就**優先測 PUT**。

**做法：** hunt agent 開工前先 query pattern_db、把跨 hunt 高頻成功 technique 排到優先試。**這才是 AI 應該做的個人化 hunting**，不是 commodity recon。

**動到的檔案（粗估）：**
- [agents/recon-ranker.md](../agents/recon-ranker.md) — ranker 開場讀 pattern_db
- [skills/bug-bounty/SKILL.md](../skills/bug-bounty/SKILL.md) 或 [skills/bb-methodology/SKILL.md](../skills/bb-methodology/SKILL.md) — hunt skill 加 memory-aware 開場
- 可能新增 `tools/pattern_query.py` — 給 skill 一個 helper 撈高頻 pattern

---

### 3. Tech-aware vuln playbook 觸發 🥈 中槓桿

**痛點：** 我們的 JSON inventory 已有 `tech: ["Next.js 14.2.3", "Express"]` 欄位，但 hunt skill **沒有 tech-aware 開場** — 不會自動建議「Next.js 14.2.x → 試 CVE-2024-X middleware bypass」。

**做法：** 在 [skills/web2-vuln-classes/SKILL.md](../skills/web2-vuln-classes/SKILL.md) 加 tech-keyed playbook 表（tech name → 對應 bug class + 已知 CVE）。Hunt agent 開場讀 `recon/<target>/inventory/subdomains.json`，把命中的 tech-CVE 列為優先測。

**重用：** 接著 [tools/learn.py](../tools/learn.py) 與 [tools/intel_engine.py](../tools/intel_engine.py) 已有 NVD / GHSA 拉取能力。

---

### 4. Chain verification 自動化 🥈 中槓桿

**痛點：** `bug-bounty` skill 有靜態 chain 表（IDOR→PUT→ATO 等）。但 AI 找到 bug A 後**沒有自動跑 B、C 步驟驗證** — 使用者要手動推進。

**做法：** [agents/chain-builder.md](../agents/chain-builder.md) 找到 A 後**主動執行** B 嘗試（受 scope_checker 與 7-Q Gate 約束），並回報結果。

---

### 5. CVE 資訊工具強化（hunt-adjacent）

**現況：** [tools/learn.py](../tools/learn.py) 已有 NVD + GitHub Advisories；[tools/intel_engine.py](../tools/intel_engine.py) 整合 H1 MCP + hunt memory；[/intel](../commands/intel.md) 命令可用。

**缺口：** 來源單一、無 PoC URL 提取、無 CISA KEV「正在被利用」標記、版本指紋比對是字串比對。

**想法：** communitytools `CLAUDE.md` 有條規則「偵測到 CVE-YYYY-NNNNN 自動跑 nvd-lookup.py」— 我們可改用 [.claude/settings.json](../.claude/settings.json) hook 機制做自動觸發。

---

### 6. Metasploit skill — 用 metasploit 找漏洞

*（細節之後展開）*

---

## Closed / 不再做（戰略捨棄 — 2026-05-06 決定）

| 項目 | 為何不做 |
|---|---|
| ❌ Communitytools 完整 6-directory 結構移植（findings/ artifacts/ reports/） | Pentest 交付導向，bug bounty 平台用不到 PDF |
| ❌ Vhost leak / Wildcard SSL / 管理面板偵測戰術 rule | Commodity recon 知識，nuclei templates 多半已有 |
| ❌ 更多 CDN provider 偵測精度 | Edge case，現有 6 大 CDN 已涵蓋 80% |
| ❌ Per-hunt timestamp 獨立目錄 + cross-run diff | 複雜度高、實際使用頻率低 |
| ❌ `recon_engine.sh --passive-only` flag | 我們不改 `recon_engine.sh`（保持與 upstream 同步），可手動跳過 phase |
| ❌ `/recon @scope.yaml` 自訂 scope 檔 | Recon 階段做 scope 檢查的價值有限，留給 hunt agent 內部處理即可 |

---

## Done

- **2026-05-05** — [SKILLS_ARCHITECTURE.md](SKILLS_ARCHITECTURE.md)（commit `213f546`）— plugin 架構說明 + drift 清單
- **2026-05-05** — JSON inventory 工具（commit `e17791f`）— [tools/recon_to_json.py](../tools/recon_to_json.py) + [memory/schemas.py](../memory/schemas.py) `RECON_INVENTORY_*` schema + [tests/test_recon_to_json.py](../tests/test_recon_to_json.py)
- **2026-05-05** — `/recon` 指令修正（commit `a6a6d42`）— [commands/recon.md](../commands/recon.md) 改成直接呼叫 production 腳本 `tools/recon_engine.sh`，解決 cwd 切換造成的雙層目錄 bug 與 production 腳本沒被觸發的問題

---

## Maintenance note — 與 upstream 同步

跟 upstream `shuvonsec/claude-bug-bounty` 的 recon 差異：

- `tools/recon_engine.sh` — **未修改**，upstream 任何更新可直接 pull
- `tools/recon_to_json.py` / `tests/test_recon_to_json.py` — 新檔，零衝突
- `memory/schemas.py` — 純 additive，低衝突
- `commands/recon.md` — 重寫，**唯一中度衝突風險**（但 upstream 最近 5 commit 都沒碰 recon side）

**建議行動：** [`commands/recon.md`](../commands/recon.md) 的 bug fix 部分（commit `a6a6d42`）值得 PR 到 upstream，讓他們收進去 → 之後 upstream 維護由他們自動處理。

✅ **2026-05-06 已發 PR：[shuvonsec/claude-bug-bounty#32](https://github.com/shuvonsec/claude-bug-bounty/pull/32)** — 待 upstream 審核中（80 行加 / 107 行減）。PR 描述只談 bug fix，不含我們本地的 JSON inventory feature（保持單一目的）。

不 revert — revert 等於把雙層目錄 bug + production 腳本沒被叫起的 bug 拿回來。
