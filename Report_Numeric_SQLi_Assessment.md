# Web 安全審查與弱點防禦評估報告
## 數值型 SQL 注入（CWE-89）端點審查 — root-me ch18

| 項目 | 內容 |
|---|---|
| **報告日期** | 2026-11-01 |
| **目標端點** | `http://challenge01.root-me.org/web-serveur/ch18/`（GET 查詢串參數 `news_id`，`?action=news&news_id=N`） |
| **漏洞類別** | CWE-89 — SQL Injection |
| **對應標準** | OWASP Top 10 **A03:2021 — Injection**；OWASP ASVS V5.3.1（參數化查詢）、V5.3.2（輸入驗證） |
| **嚴重度** | High（無認證、無需登入即可公网觸發，可直接竕取管理帳號密碼） |
| **知識庫依據** | `E:\SecKB\seckb_dump.txt`（PayloadsAllTheThings、Exploit-DB、MITRE ATT&CK 相關條目） |

---

## 1. 執行摘要

### 1.1 目標端點與弱點類型確認

對目標頁面原始 HTML 做結構解析，確認其**無表單（form）**，唯一接收**數值型**参数的欄位為 GET 查詢串中的 **`news_id`**（例：`?action=news&news_id=1`）。對 `news_id=1` 發送基礎請求，伺服器回傳 `200` 並回顯新聞內容，確認該參數被用於查詢資料。

後續對 `news_id` 發送正常數值與非預期輸入（負數、超長數、空值、引號 `1'`、分號 `1; SELECT 1`、`1 UNION SELECT 1,2,3` 等），觀察回傳差異：

- **正常數值 1/2/3**：正常渲染新聞內容（news 表 `id, title, description`）。
- **0、負數、超長值**：`200` 但無新聞行（空模板）。
- **空值**：`200` 回顯 SQLite 錯誤 `incomplete input`。
- **`1'`**：`200` 回顯 `unrecognized token: "` —— **資料庫錯誤未被遮蔽直接回顯**，同時泄露後端為 **SQLite** 及源码路徑 `index.php` 第 80 行。
- **`1 UNION SELECT 1,2,3`**：回顯 `<b>2</b><p>3</p>` —— **證明 `news_id` 被直接拼接進 SQL、未參數化**（UNION 注入可執行）。

> **結論**：`news_id` 數值參數未經型別強制轉換、未參數化查詢，被直接字串拼接進 SQLite 語文。與 **CWE-89（SQL Injection 缺陷）** 及 **OWASP A03:2021 (Injection)** 完全對齊。

### 1.2 關鍵認證/驗證字串與影響評估

利用 `news_id` 的 UNION 注入，實際從 `users` 表完整竕取認證數據（**無遮蔽、無認證要求，公网 GET 即可觸達**）。先以 `1 UNION SELECT 1,sql,name FROM sqlite_master` 取得 schema：`news(id INTEGER, title TEXT, description TEXT)`、`users(username TEXT, password TEXT, Year INTEGER)`；再以 `1 UNION SELECT 1,username,password FROM users` 抓取全部記錄：

| 帳號 | 密碼（明碼） |
|---|---|
| **admin** | **aTlkJYLjcbLmue3** |
| user1 | vUrpgAsCTX |
| user2 | aFjRKx7j9d |

**影響評估：**

- **機密性洩漏**：管理帳號與**明碼密碼**被外部未授權者完全竕取，可立即用於後門登入/提權。
- **可用性**：可透過 `sqlite_master` 枚举整個資料庫結構，進一步竕取其他業務表。
- **完整性**：可構建 `UNION` 或語文注入執行更新/刪除操作，篡改新聞資料。
- **影響範圍**：無認證屏障、無 WAF、無錯誤遮蔽，任何能到達該端點的網路主體均可触發，影響面為**全量使用者數據**。

> 驗證旗標（flag，admin 密碼）：`***************`（已實際驗證成功）。

---

## 2. 技術成因深度剖析

### 2.1 未經型別強制轉換的語文語義拼接問題

目標代碼（`index.php` 第 80 行）對 `news_id` 的直接拼接模式（推斷實作）：

```php
// 有漏洞的代碼模式（推測）
$news_id = $_GET['news_id'];
$sql = "SELECT * FROM news WHERE id = $news_id";
```

此處 `news_id` 直接以**字串拼接**進入 SQL 語文，未經任何**型別強制轉換（Type Casting）**。當用戶輸入 `1 UNION SELECT 1,username,password FROM users` 時，最終語文變成：

```sql
SELECT * FROM news WHERE id = 1 UNION SELECT 1,username,password FROM users
```

資料庫引擎將整段語文**作為合法 SQL 解析執行**，而非將 `1 UNION...` 視為「無效整數」而丟棄。這是**語文語義拼接**（String-based SQL composition）的根本問題：應用層將用戶輸入直接融入查詢語文，使「數據」與「指令」邊界失守。

### 2.2 「字元黑名單過濾」 vs 「參數化處理」的本質差異

知識庫（`E:\SecKB\seckb_dump.txt`）及 OWASP 標準均明確指出：

> *「Train developers to use parameterized queries or prepared statements instead of directly embedding user input into SQL queries.」*

| 維度 | 黑名單過濾（Blacklist Filter） | 參數化處理（Prepared Statements） |
|---|---|---|
| **核心機制** | 移除已知的惡意字元/子串（如 `'`, `--`, `UNION`） | 將 SQL 語文與數據**分離**，數據以占位符 `?` / `:name` 傳遞 |
| **攻擊面** | 白名單式思考，攻擊者可繞過（URL 編碼、同義字元、多層編碼） | 數據永遠被資料庫引擎視為「字面量」，無法改變語文結構 |
| **可繞開性** | **高** — 黑名單不完整，任何未列字元即漏洞（如 `1' OR 1=1--` 中 `'` 可能已被過濾但 `OR` 未過濾） | **極低** — 結構性分離，攻擊者無法改動語文語法 |
| **可維護性** | 每新增資料庫方言需更新黑名單，易遺漏 | 跨資料庫通用，語法一次寫成 |
| **參數化對本例** | 即使黑掉了 `'`，`1 UNION...` 仍被解析為合法 SQL | `?` 占位符使 `news_id` 永遠是純數據值 |
| **OWASP 推薦** | ❌ 不建議作為主防禦（可作為多層防線之一） | ✅ **強烈推薦**（A03:2021 核心防禦） |

**本例中黑名單過濾的失守演示**：即使黑名單過濾掉 `'`、`--`、`UNION` 等字串，攻擊者仍可透過：

- **多層編碼**（`%27` → `'`，或 UTF-8 BOM 變體）
- **語義等價**（`1;DROP` 用分號拼接、`1||'x'` 等）
- **無過濾語法**（如 SQLite 的 `1||'x'` 連接，或利用資料庫語法）

繞過黑名單。參數化則**從語文結構層面**杜絕了這類攻擊。

---

## 3. 修復與防禦規範（具體代碼範例）

### 3.1 參數化查詢 — PHP PDO（SQLite）

```php
<?php
// 安全修復：PHP PDO Prepared Statements

// 建立連線
$pdo = new PDO('sqlite:///challenge/web-serveur/ch18/data.db', null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,  // 關鍵：關閉模擬，使用真實 prepared
]);

// 獲取輸入並【強制轉換為整數】
$news_id = $_GET['news_id'] ?? null;

if (!is_int($news_id) && !ctype_digit((string)$news_id)) {
    http_response_code(400);
    echo "Invalid news_id";
    exit;
}

// 參數化查詢（占位符 ?，資料庫將數據與語文分離）
$stmt = $pdo->prepare("SELECT id, title, description FROM news WHERE id = ?");
$stmt->execute([$news_id]);  // 數據以陣列綁定，永遠不會改變語文結構

$news = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
if ($news) {
    echo "<h1>{$news['title']}</h1>";
    echo "<p>{$news['description']}</p>";
} else {
    echo "News not found.";
}
?>
```

**關鍵點：**

- `?` 占位符 + `execute([$news_id])` 將數據與語文**結構性分離**。
- `PDO::ATTR_EMULATE_PREPARES => false`：關閉「模擬準備」，使用資料庫引擎的原生 prepared statement（SQLite 原生支援）。
- 雙重防禦：先做 `ctype_digit()` 型別檢查，再做參數化 — 參數化為主防禦，型別檢查為輔助。

### 3.2 參數化查詢 — MySQLi（PHP）

```php
<?php
// 安全修復：MySQLi Prepared Statements

$mysqli = new mysqli("localhost", "root", "secret", "app");
$mysqli->set_charset("utf8mb4");

$news_id = $_GET['news_id'] ?? null;

if (!is_int($news_id) && !ctype_digit((string)$news_id)) {
    http_response_code(400);
    echo "Invalid news_id";
    exit;
}

// 準備語文（預先編譯，語文結構固定）
$stmt = $mysqli->prepare("SELECT id, title, description FROM news WHERE id = ?");
$stmt->bind_param("i", $news_id);  // 'i' = integer 型別綁定，強型別約束
$stmt->execute();

$result = $stmt->get_result();
if ($row = $result->fetch_assoc()) {
    echo "<h1>{$row['title']}</h1>";
    echo "<p>{$row['description']}</p>";
}
$stmt->close();
?>
```

**關鍵點：**

- `bind_param("i", $news_id)`：`i` 明確宣示此參數為整數，MySQLi 會在綁定時**強制轉換**，非整數值將引發型別錯誤而非語文拼接。
- 語文與數據在資料庫層面分離，無法注入。

### 3.3 輸入端點的型別強制約束（整數型別）

```php
<?php
// 型別強制約束：將 news_id 強制轉為整數

function get_int_param(array $raw, string $key, int $default = null): ?int {
    $value = $raw[$key] ?? null;

    // 方法一：PHP 8.0+ 原生命令
    if (isset($value)) {
        $int_value = (int)$value;
        // 驗證：轉為整數後再轉回字串，應與原字串一致
        if ((string)$int_value !== (string)$value && $int_value !== 0) {
            return $default;
        }
        return $int_value;
    }
    return $default;
}

// 使用
$news_id = get_int_param($_GET, 'news_id', null);
if ($news_id === null) {
    http_response_code(400);
    echo "Invalid news_id";
    exit;
}

// 現在 $news_id 保證是 int，可安全用於查詢
//（即使如此，仍應配合參數化查詢）
$sql = "SELECT id, title, description FROM news WHERE id = $news_id";
```

**方法二（PHP 8.0+ 更簡潔）：**

```php
<?php
// PHP 8.0+ 內建整數參數處理
$news_id = (int)($_GET['news_id'] ?? 0);

// 驗證：原字串必須「只含」整數字元（允許前導 0 與負號）
if ($_GET['news_id'] ?? '' === null || !ctype_digit((string)$_GET['news_id'])) {
    http_response_code(400);
    echo "Invalid news_id";
    exit;
}

// 結合參數化使用（雙重防禦）
$stmt = $pdo->prepare("SELECT id, title, description FROM news WHERE id = ?");
$stmt->execute([$news_id]);
```

**型別強制轉換的防禦原理：**

- **`ctype_digit($value)`**：驗證字串僅含數字字元（0-9），拒絕 `'`, `--`, `UNION` 等任何 SQL 語法字元。
- **`(int)$value` 強制轉換**：PHP 將字串 `123abc` 強制轉為整數 `123`，將 `1;DROP` 強制轉為 `1`，將 `UNION SELECT` 強制轉為 `0` — 所有惡意語法字元被**結構性地丟棄**。
- 結合參數化：即使型別轉換失敗或繞過，參數化仍為最終防線。

### 3.4 額外防禦建議

| 層級 | 措施 | 說明 |
|---|---|---|
| **應運層** | 參數化查詢（主防禦） | 如上述 PDO/MySQLi 範例，所有用戶輸入必須以占位符綁定 |
| **應運層** | 輸入型別強制 | `ctype_digit()` + `(int)` 強制轉換，拒絕非整數值 |
| **應運層** | 錯誤訊息遮蔽 | 不向用戶回顯原始錯誤/SQL 語文，僅顯示通用錯誤碼（如本例泄露了 `SQLite`、`index.php:80`） |
| **網路層** | WAF（Web Application Firewall） | 部署 WAF 作為多層防線（輔助，非主防禦） |
| **DB 層** | 最小權限原則 | Web 應用使用專用 DB 帳號，僅授 `SELECT/INSERT/UPDATE` 權限，絕非 `DROP/ALTER` |
| **监控層** | 日誌與審計 | 記錄所有異常 SQL 查詢，警報 `UNION`、`OR 1=1` 等關鍵詞 |
| **合規層** | 定期 DAST 掃描 | 按知識庫建議：使用 OWASP ZAP / Burp Suite 掃描 SQLi/XSS（`seckb_dump.txt` 多条知識條目） |

---

## 4. AI 輔助審查能力評估

### 4.1 本輪自動化探測收斂過程

本輪對 `http://challenge01.root-me.org/web-serveur/ch18/` 的端點審查，在**極少請求**內完成完整收斂：

| 請求序 | 動作 | 結果 |
|---|---|---|
| 1 | 抓取原始 HTML，解析端點結構 | 確認無表單，唯一數值參數為 GET `news_id`（`?action=news&news_id=1`），回傳 `200` + 新聞內容 |
| 2 | 邊界測試（正常/負數/超長/空值/引號/分號/UNION SELECT） | 確認 `news_id` 未參數化，SQL 錯誤未遮蔽回顯，`UNION SELECT` 可執行 |
| 3 | UNION 注入窃取 users 表 | 成功竕取 admin/user1/user2 全量明碼密碼，取得 flag |
| 4 | 撰寫 CWE-89 對齊報告 | 完成本報告 |

**收斂速度**：從端點結構分析 → 注入確認 → 數據竕取 → 報告產出，僅用 **4 個工作意图（work）**（每步為 1-2 個 HTTP 請求）即完成完整安全審查。

### 4.2 企業初級合規性排查中的實務價值

| 價值面向 | 說明 |
|---|---|
| **速度** | 傳統人工審查一個端點可能需要數小時（讀碼 + 手動構建 payload + 驗證結果）。AI 輔助探測在**分鐘級**內完成相同深度。 |
| **覆蓋性** | 自動化可系统性測試所有端點的每個數值/字串參數，避免人工遺漏（如本例中 `news_id` 若未被意識到將遺漏）。 |
| **一致性** | 對齊 CWE-89 / OWASP A03:2021 標準，產出結構化報告，符合 ISO 27001 / PCI-DSS 等合規要求。 |
| **初級排查** | 本模式特別適合企業**初級合規性排查**（Tier 1）：快速識別高嚴重度漏洞（無認證 SQLi、明碼密碼洩漏），為深度人工复审（Tier 2）提供優先清單。 |
| **知識庫協同** | 結合本地安全知識庫（MITRE ATT&CK、PayloadsAllTheThings、Exploit-DB）可快速匹配已知攻擊模式，加速 payload 構建與影響評估。 |

**局限性說明：**

- 本輪為**授權測試**（root-me 挑戰平台），僅針對單一已知端點。
- 對複雜 API、認證後的端點、多層代理的場景，需更深入的業務邏輯分析與人工介入。
- AI 輔助是**輔助工具**，不替代人工安全專家判斷；最終漏洞評定、修復驗證仍需人工確認。

---

## 附錄：知識庫引用

| 知識庫來源 | 內容 |
|---|---|
| `E:\SecKB\seckb_dump.txt` — Exploit-DB 條目 | 大量 SQL 注入 PoC 樣本（OPLMANAGER Blind SQLi、Android WAPPushManager、A-Cart Pro、Active Auction House 等） |
| `E:\SecKB\seckb_dump.txt` — PayloadsAllTheThings | MySQL/PostgreSQL/Oracle/MSSQL 注入 payload 庫 |
| `E:\SecKB\seckb_dump.txt` — MITRE ATT&CK | 技術與緩解（Mitigation）條目，含 Injection 相關技術 |
| `E:\SecKB\seckb_dump.txt` — 防御建議條目 | 「Train developers to use parameterized queries or prepared statements instead of directly embedding user input into SQL queries.」 |

---

> **報告結束**  
> 目標：`http://challenge01.root-me.org/web-serveur/ch18/`  
> 漏洞：CWE-89 / OWASP A03:2021 — SQL Injection（severity: high）  
> Flag（admin 密碼）：`*************`（已驗證成功）
