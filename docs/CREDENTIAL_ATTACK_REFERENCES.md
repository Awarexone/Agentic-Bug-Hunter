# Credential Attack — PR 參考資源彙整

> 目標：為 `claude-bug-bounty` plugin 新增「企業專屬密碼字典 + 弱密碼測試」能力。
> 對應 4 個範圍（已確認）：**字典產生器**、**外洩密碼比對**、**登入端點 spray**、**OSINT 員工名單收集**。
> 4 個關鍵字來源（已確認）：**企業官網爬蟲**、**GitHub 公開 repo**、**社群媒體 / 新聞**、**DNS / 子網域命名**。

---

## 0. 為什麼這個攻擊面值得做（紅隊原理）

密碼噴灑（password spraying）和憑證填充（credential stuffing）是真實世界**佔比最高**的初始入侵手法之一（Verizon DBIR 年年都把 Stolen Credentials 列為 Top 3）。Bug Bounty 領域常被忽略，因為：

1. 多數獵人只丟 `rockyou.txt` → 被速率限制擋掉，沒結果就放棄
2. 沒有把「公司專屬字典 + 員工真實 username 格式 + 季節變化」結合起來
3. 不熟 spray 與 brute-force 的差異：**spray 是「少數密碼 × 大量帳號」**，反向操作避開 lockout

**核心原理**：人類懶。員工密碼八成是 `{公司名}{年份}!` 或 `{產品代號}{季節}` 或 `{城市}123`。蒐集越多公司專屬詞彙（產品名、辦公室所在地、CEO 名、企業口號、內部專案代號），猜中率越高。這份 PR 要做的就是**自動化這個蒐集→組合→驗證的流程**。

---

## 1. 字典產生器（核心）

### 1.1 從網站 / 文件爬詞

| 工具 | 語言 | 用法 | 備註 |
|---|---|---|---|
| **[CeWL](https://digi.ninja/projects/cewl.php)** | Ruby | `cewl https://target.com -d 3 -m 5 -w out.txt` | 老牌、Kali 內建；對 JS-heavy 網站抓不到動態內容 |
| **[CeWLeR](https://github.com/roys/cewler)** | Python | `cewler https://target.com --depth 3 -w out.txt` | CeWL 的 Python 重寫版，基於 Scrapy，速度快很多 |
| **[dirtywords](https://tonywest.io/blog/introducing-dirtywords-a-targeted-word-list-generator)** | Python | 針對性 word list 產生器 | 較新，著重 bug bounty 場景 |
| **[getjswords](https://github.com/m4ll0k/getjswords)** | Python | 從 JS bundle 抽詞 | 找隱藏 API 路徑時也好用，可一物兩用 |

> **建議**：CeWLeR 當主力（速度+維護活），CeWL 當備援（網頁簡單時夠用）。

### 1.2 從個人資訊產生（CUPP 系）

| 工具 | 語言 | 用法 | 備註 |
|---|---|---|---|
| **[CUPP](https://github.com/Mebus/cupp)** | Python | `cupp.py -i` 互動式輸入目標生日/寵物名 | 經典；適合**目標明確的高價值帳號** |
| **[cupp-rs](https://github.com/ElNiak/cupp-rs)** | Rust | 同 CUPP，但快 | 較新 |
| **[pydictor](https://github.com/LandGrey/pydictor)** | Python | 模組化、支援社交工程模板、正規式過濾 | **功能最豐富**，建議當核心引擎 |
| **[wister](https://github.com/cycurity/wister)** | Python | Word Mix / Case Alternate / Homograph / Reverser / Saltify 5 種變形 | 變形組合最靈活 |

### 1.3 規則式變形（針對已有字典做擴張）

| 工具 / 規則 | 用法 | 備註 |
|---|---|---|
| **[Mentalist](https://github.com/sc0tfree/mentalist)** | GUI；可輸出 hashcat / John 規則檔 | 適合手動精雕，CI 不好整合 |
| **[hashcat best64.rule](https://hashcat.net/wiki/doku.php?id=rule_based_attack)** | `hashcat -a 0 -r best64.rule wordlist.txt` | hashcat 內建，最常用基本規則 |
| **[OneRuleToRuleThemAll](https://notsosecure.com/one-rule-to-rule-them-all)** | NotSoSecure 整理的「殺手級」綜合規則 | 規則最多但耗時，cracking 領域實證最高破解率 |
| **[rsmangler](https://github.com/digininja/RSMangler)** | `rsmangler --file in.txt --output out.txt` | 簡單變形（前後加數字、l33t、大小寫） |

> **建議組合**：`pydictor` 產生候選字 → `hashcat -r best64.rule` 做變形 → 再用 HIBP 過濾掉早就被洩露的（這些已經沒情報價值，但**反過來在 spray 階段反而高機率打中**）。

---

## 2. OSINT 員工名單收集

### 2.1 員工列舉

| 工具 | 來源 | 備註 |
|---|---|---|
| **[theHarvester](https://github.com/laramies/theHarvester)** | 43 個來源（搜尋引擎、證書透明日誌、HIBP、Dehashed） | 一個指令搞定 email + 子網域 + 員工名 |
| **[LinkedInDumper](https://github.com/l4rm4nd/LinkedInDumper)** | LinkedIn Voyager API（需 LinkedIn 帳號） | `--email-format` 直接產生 email |
| **[CrossLinked](https://github.com/m8sec/CrossLinked)** | Google/Bing 搜尋 LinkedIn | **不需 LinkedIn 帳號**，OPSEC 較好 |
| **[NameSpi](https://github.com/waffl3ss/NameSpi)** | LinkedIn + Hunter.io | 結合多來源 |
| **[Hunter.io](https://hunter.io)** | 商業 API | 員工 email 格式判斷神器（`{first}.{last}@`） |

### 2.2 Username 格式生成

| 工具 | 用法 | 備註 |
|---|---|---|
| **[username-anarchy](https://github.com/urbanadventurer/username-anarchy)** | `username-anarchy -i names.txt` | 把 `John Smith` 展開成 `john.smith`, `jsmith`, `john_smith`, `johns`... 等 32+ 種格式 |
| **[Kerbrute](https://github.com/ropnop/kerbrute)** | `kerbrute userenum --dc dc.target.com -d target.com users.txt` | 透過 Kerberos pre-auth 驗證哪些 username 真的存在（**內網場景**） |

> **流程**：LinkedInDumper / CrossLinked 抓員工真名 → username-anarchy 展開所有格式 → 對目標登入端點驗證哪些存在 → 用 1.x 產的字典 spray。

### 2.3 從 GitHub 蒐集公司專屬關鍵字

| 工具 | 用法 | 備註 |
|---|---|---|
| **[trufflehog](https://github.com/trufflesecurity/trufflehog)** | `trufflehog github --org=target` | 已存在於現有 `tools/secrets_hunter.sh`，可重用 |
| **[gitleaks](https://github.com/gitleaks/gitleaks)** | 同上 | 同上 |
| **[GitDorker](https://github.com/obheda12/GitDorker)** | 自動化 GitHub dork（已在 `REFERENCES.md`） | 找專案代號 / 內部術語 |
| **enumerepo + 自製抽詞** | 把 commit message / README / 變數名抽出 → 餵給 pydictor | 自己寫 50 行 Python 即可 |

> **訣竅**：成功的獵人會找**罕見、公司專屬的關鍵字**配合 dork，例如內部專案代號 `ProjectAurora` 比通用 `password` 命中率高 10 倍。

---

## 3. 外洩密碼 / 字典資料庫

| 來源 | 用法 | 備註 |
|---|---|---|
| **[HaveIBeenPwned Pwned Passwords](https://haveibeenpwned.com/Passwords)** | k-anonymity API（送 SHA-1 前 5 碼），免 API key、無速率限制 | 用來**過濾**自製字典：已經在 HIBP 的密碼可單獨拉一份「高機率密碼集」 |
| **[HIBP Breach API](https://haveibeenpwned.com/api/v3)** | 付費 API key（$3.5/月） | 查特定 email 出現在哪些外洩，做高風險帳號名單 |
| **[DeHashed](https://dehashed.com/)** | 付費，含明文密碼 | Bug Bounty 場景**要看 program scope**，多數禁止使用外洩明文密碼 |
| **[Intelligence Security](https://intelligencesecurity.io/)** | DeHashed 替代，500B+ 紀錄 | 同樣注意法律與 scope |
| **[BreachDirectory](https://breachdirectory.org/)** | 免費查 email 是否外洩（不含明文） | 風險評估用 |
| **[SecLists](https://github.com/danielmiessler/SecLists)** | Passwords/ 目錄含 rockyou、Top-N、年份組合 | **已在 `wordlists/REFERENCES.md`** |
| **[weakpass.com](https://weakpass.com/)** | Weakpass 2.0 = 28GB 多 dump 合集 | 巨量字典，需大磁碟 |
| **rockyou2024.txt** | 99 億筆明文 | 太大，**不建議當 spray 字典**，留給離線 hash cracking |

> **⚠️ Bug Bounty 法律雷區**：使用**外洩的真實明文密碼**對活的帳號嘗試登入，多數 program 視為違反 ToS（即使有 scope）。安全做法是用 HIBP 的**hash prefix** 判斷「這個密碼是否曾外洩」**作為自製字典的優先排序依據**，而不是直接拿外洩明文 spray。

---

## 4. 登入端點 Spray 工具

| 工具 | 適用目標 | 備註 |
|---|---|---|
| **[TREVORspray](https://github.com/blacklanternsecurity/TREVORspray)** | O365 / Okta / OWA / ADFS / Auth0 / JumpCloud / AnyConnect | **目前最完整**，內建 SSH proxy 輪替 IP，支援 `--delay` 控制節奏 |
| **[MSOLSpray](https://github.com/dafthack/MSOLSpray)** | 純 O365 / Azure | 經典 PowerShell；TREVOR 已涵蓋它 |
| **[CredMaster](https://github.com/knavesec/CredMaster)** | 通用 + FireProx | 用 AWS API Gateway 每次請求換 IP，**反 throttling 神器** |
| **[Spray365](https://github.com/MarkoH17/Spray365)** | M365 | 雙步噴灑，繞 Azure Smart Lockout |
| **[SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)** | Lync / S4B / OWA / O365 | byt3bl33d3r 出品 |
| **[awesome-password-spraying](https://github.com/puzzlepeaches/awesome-password-spraying)** | 工具清單 | 隨時擴充參考 |

### Spray vs Brute-force 的關鍵差異

| | Brute-force | Spray |
|---|---|---|
| 模式 | 1 帳號 × N 密碼 | N 帳號 × 1~少數密碼 |
| 觸發 lockout | 容易 | 不易（每帳號錯誤次數低） |
| Bug Bounty 接受度 | **多數禁止** | **多數允許**（需依 program 政策） |
| 命中時間 | 慢 | 快（找弱密碼用戶） |

> **預設參數建議**：`--delay 1800 --jitter 60`（30 分鐘一次 + 隨機抖動），對 O365 安全；對 web 登入若有 CAPTCHA / WAF 還要更慢。

---

## 5. 法律 / 道德 / Bug Bounty Scope 紅線

PR 實作時必須在 tool 跟 skill 裡明確處理：

1. **Scope 強制檢查**：每次跑 spray 前呼叫現有 `tools/scope_checker.py`，目標不在 scope 直接拒絕（這個 plugin 已經有這個守門）
2. **明文外洩密碼禁用**：對活的帳號**不要**直接送 DeHashed 抓到的明文，多數 program 視為違規。改用 HIBP **hash prefix** 做「曾被洩露」的標記，最多排序優先級
3. **lockout 風險告知**：spray 前必須在 console 顯示「將對 N 個帳號嘗試 M 個密碼，預估 X 帳號可能被鎖」並等使用者確認
4. **速率預設保守**：預設 30 分鐘/次，要快速 spray 要顯式 flag（`--aggressive`）
5. **不寫對個人帳號的 brute-force 模式**：只做 spray
6. **遵守 robots.txt + ToS**：CeWL 爬網站時加 `--ua` 標明研究用途、抓取深度設限

這些原則對應到專案 `CLAUDE.md` 的 17 條規則裡「READ FULL SCOPE before touching any asset」與 7-Question Gate。

---

## 6. 建議的 PR 整合架構

對應你選的「完整套件（skill + command + tool）」：

```
claude-bug-bounty/
├── skills/
│   └── credential-attack/                 ← 新 skill
│       ├── SKILL.md                       ← 完整攻擊鏈、原理、流程圖
│       ├── WORDLIST_GENERATION.md         ← 字典產生方法論
│       ├── SPRAY_PLAYBOOK.md              ← spray 步驟 + scope 守則
│       └── LEGAL_GUARDRAILS.md            ← 上面第 5 節
│
├── commands/                              ← 4 個新指令
│   ├── wordlist-gen.md                    ← /wordlist-gen target.com
│   ├── osint-employees.md                 ← /osint-employees target.com
│   ├── breach-check.md                    ← /breach-check <email|domain>
│   └── spray.md                           ← /spray <endpoint> --userlist --passlist
│
├── tools/
│   ├── wordlist_engine.sh                 ← 主腳本：CeWLeR + pydictor + hashcat rules
│   ├── osint_employees.sh                 ← theHarvester + CrossLinked + LinkedInDumper
│   ├── breach_checker.py                  ← HIBP k-anonymity 過濾
│   └── spray_orchestrator.sh              ← TREVORspray wrapper + scope_checker 守門
│
├── agents/
│   └── credential-hunter.md               ← 新 agent：自動跑 OSINT→字典→spray 流程
│
└── wordlists/
    └── company-wordlist-template/          ← 範例輸出
        ├── from-website.txt
        ├── from-github.txt
        ├── from-osint.txt
        └── merged-ranked.txt
```

`tools/external_arsenal.sh` 也要加 entry 讓 `/arsenal` 能列出新增的 ~10 個外部工具。

---

## 7. 立即可動的 next step

依優先序：

1. **先做 `tools/wordlist_engine.sh`** — 串 CeWLeR + pydictor + best64.rule，輸入 domain，輸出 ranked wordlist。**這是 PR 最小可交付單元**。
2. **加 `tools/breach_checker.py`** — 純 HIBP API，過濾 / 排序字典。零外部相依。
3. **`commands/wordlist-gen.md` + 寫 `skills/credential-attack/SKILL.md`** — 把上面整理的原理寫進 skill。
4. **再做 OSINT 部分** — theHarvester + CrossLinked wrapper。
5. **最後做 spray** — 風險最高、要先把 scope_checker 和 lockout 警示寫好才上。

每一步都可以單獨開 PR，不需要一次寫完整套件。

---

## 參考連結

### 字典產生
- [CeWLeR (GitHub)](https://github.com/roys/cewler)
- [CeWL DigiNinja](https://digi.ninja/projects/cewl.php)
- [CUPP (GitHub)](https://github.com/Mebus/cupp)
- [pydictor (GitHub)](https://github.com/LandGrey/pydictor)
- [wister (GitHub)](https://github.com/cycurity/wister)
- [Mentalist (GitHub)](https://github.com/sc0tfree/mentalist)
- [One Rule To Rule Them All (NotSoSecure)](https://notsosecure.com/one-rule-to-rule-them-all)
- [Intigriti — Creating custom wordlists for bug bounty targets](https://www.intigriti.com/researchers/blog/hacking-tools/creating-custom-wordlists-for-bug-bounty-targets-a-complete-guide)

### OSINT 員工
- [theHarvester (GitHub)](https://github.com/laramies/theHarvester)
- [LinkedInDumper (GitHub)](https://github.com/l4rm4nd/LinkedInDumper)
- [CrossLinked (GitHub)](https://github.com/m8sec/CrossLinked)
- [NameSpi (GitHub)](https://github.com/waffl3ss/NameSpi)
- [username-anarchy (GitHub)](https://github.com/urbanadventurer/username-anarchy)
- [Kerbrute (GitHub)](https://github.com/ropnop/kerbrute)

### 外洩密碼
- [HaveIBeenPwned Pwned Passwords](https://haveibeenpwned.com/Passwords)
- [HIBP API v3](https://haveibeenpwned.com/api/v3)
- [SecLists Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
- [weakpass.com](https://weakpass.com/)
- [Packetlabs — rockyou2024 10 billion passwords](https://www.packetlabs.net/posts/wordlists-in-cybersecurity-rockyou-2024-includes-10-billion-stolen-passwords/)

### Spray
- [TREVORspray (GitHub)](https://github.com/blacklanternsecurity/TREVORspray)
- [MSOLSpray (GitHub)](https://github.com/dafthack/MSOLSpray)
- [CredMaster (GitHub)](https://github.com/knavesec/CredMaster)
- [Spray365 (GitHub)](https://github.com/MarkoH17/Spray365)
- [awesome-password-spraying](https://github.com/puzzlepeaches/awesome-password-spraying)
