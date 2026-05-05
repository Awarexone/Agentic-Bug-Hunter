# Optimization Roadmap

想優化的項目清單。細節之後再談 — 這裡只記下要做什麼，跨 session 用來提醒「還有這些事」。

---

## To do

1. **優化 Recon 紀錄** — 讓 recon 結果能存下來、之後查得到
   - 開工前先回答的問題：
     - Q1：`/recon domain` 怎麼定義 scope？除了 HackerOne，能不能用 `/recon domain @文件` 自訂範疇？
     - Q2：`/recon` 產生哪些檔案？檔案結構與內容是什麼？
2. **Bypass WAF skills 優化** — 強化 WAF 繞過相關內容
3. **串接取得 CVE 資訊工具** — 整合更多 CVE 來源

*(陸續補充中)*

---

## Done

- **2026-05-05** — [SKILLS_ARCHITECTURE.md](SKILLS_ARCHITECTURE.md)（commit `213f546`）— plugin 架構說明 + drift 清單
