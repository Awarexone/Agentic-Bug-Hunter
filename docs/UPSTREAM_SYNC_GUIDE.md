# 同步 Upstream 更新教學

> 適用情境：你 fork 了 `shuvonsec/claude-bug-bounty`，想把原作者的最新 commit 合併進自己的 fork。

---

## 一次性設定（只需做一次）

確認 `upstream` remote 是否已設定：

```bash
git remote -v
```

若沒有 `upstream` 這行，執行：

```bash
git remote add upstream https://github.com/shuvonsec/claude-bug-bounty.git
```

---

## 每次同步流程（5 道指令）

```bash
# 1. 確認在 main branch
git checkout main

# 2. 同步本地與你的 fork（origin）
git pull origin main

# 3. 抓取 upstream 的最新內容（不會改動你的程式碼）
git fetch upstream

# 4. 確認 upstream 有沒有新東西
git log --oneline HEAD..upstream/main

# 5. 有更新才執行合併
git merge upstream/main --no-edit

# 6. 推送到你的 fork
git push origin main
```

> 如果 Step 4 的輸出是空的，代表 upstream 沒有新 commit，不需要合併。

---

## 查看 Upstream 有哪些新東西

```bash
# 列出 upstream 比你多的 commit
git log --oneline HEAD..upstream/main

# 查看哪些檔案被改動
git diff --name-only HEAD..upstream/main

# 查看完整 diff（謹慎使用，可能很長）
git diff HEAD..upstream/main
```

---

## 遇到衝突怎麼辦

合併時若出現 `CONFLICT` 訊息：

```bash
# 查看哪些檔案有衝突
git diff --name-only --diff-filter=U
```

用編輯器開啟衝突檔案，找到長這樣的區塊：

```
<<<<<<< HEAD
你這邊的內容
=======
upstream 那邊的內容
>>>>>>> upstream/main
```

**解決方式：**
1. 決定要保留哪一邊，或把兩邊都保留（最常見）
2. 刪除 `<<<<<<<`、`=======`、`>>>>>>>` 這三行標記
3. 存檔後執行：

```bash
git add <衝突的檔案>
git commit -m "merge: sync upstream/main + resolve conflicts in <檔案名>"
git push origin main
```

> **原則：** 如果是你自己加的功能，通常兩邊都保留。如果 upstream 完全重寫了某段，以 upstream 為主並把你的客製化內容補回去。

---

## 常用指令速查

| 指令 | 說明 |
|---|---|
| `git remote -v` | 查看目前的 remote |
| `git fetch upstream` | 抓取 upstream 最新狀態（不改動本地） |
| `git log --oneline HEAD..upstream/main` | upstream 有幾個新 commit |
| `git log --oneline upstream/main..HEAD` | 你領先 upstream 幾個 commit |
| `git diff --name-only HEAD..upstream/main` | upstream 改了哪些檔案 |
| `git merge upstream/main --no-edit` | 合併 upstream（自動產生 commit message） |
| `git merge --abort` | 合併中途後悔，撤銷整個 merge |
| `git diff --name-only --diff-filter=U` | 列出衝突中的檔案 |
| `git status` | 查看目前狀態 |

---

## 讓 Claude 幫你做

下次直接說：

> 幫我檢查 upstream 有沒有更新，有的話幫我合併

Claude 會自動執行 fetch → 比對 → merge → 解衝突 → push，並告訴你這次更新的重點。
