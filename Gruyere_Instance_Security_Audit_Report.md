



# Google Gruyere 沙盒實例安全審計報告

**測試目標：** Google Gruyere 隔離實例 (`https://google-gruyere.appspot.com/<instance-id>/`)
**報告日期：** 2026-10-31
**審計範疇：** 非破壞性 Web 架構審計、攻擊面盤點、OWASP 安全回應標頭與認證邊界檢查

---

## 審計環境與技術規格 (Audit Environment & Specs)

本報告由自建之本地端安全審計管線自動探測與彙整產出，全程於本地隔離環境執行：

- **執行架構**：Windows 11 / Local LLM Agent 架構
- **探測限制**：非破壞性探測，請求間隔固定 0.8s，單一端點重試上限 2 次
- **核心模組**：
  - `crawler.py`：遞迴解析端點與 HTML 表單欄位（提取 method、action、hidden inputs）
  - `header_auditor.py`：比對 OWASP 推薦回應標頭與 Cookie 安全屬性
- **審計基線**：OWASP Top 10 (2021) / OWASP Secure Headers Project

---

## 1. 執行摘要 (Executive Summary)

- **部署形態：** Google App Engine 代管服務（Server: Google Frontend），HTTPS 端點。
- **TLS 安全：** HTTPS 已啟用，但**未設定 HSTS（Strict-Transport-Security）**，存在協定降級風險。
- **安全回應標頭：** 受測端點上 **5 項 OWASP 推薦安全標頭全數缺失**：
  - Content-Security-Policy (CSP) — 未設定
  - Strict-Transport-Security (HSTS) — 未設定
  - X-Frame-Options — 未設定（無 Clickjacking 防護）
  - X-Content-Type-Options — 未設定（無 MIME Sniffing 防護）
  - Referrer-Policy — 未設定（無 Referrer 洩漏防護）
- **X-XSS-Protection：** 伺服器顯式設為 `0`（禁用），完全未啟用瀏覽器內建 XSS 防護機制。
- **Cookie 配置：** 所有回應**均未設定 Set-Cookie**，欠缺狀態保持機制。
- **認證設計缺陷：** 登入表單以 **GET 方法**提交 `uid`/`pw`，導致憑證直接暴露於 URL Query String、瀏覽器歷史紀錄、伺服器存取日誌及 Referer 標頭中。
- **CSRF 防護：** 兩個表單（`/login`、`/newaccount.gtl`）均**未配置 Anti-CSRF Token**。
- **IDOR 缺陷疑慮：** `snippets.gtl?uid=<id>` 接受任意 uid 參數查詢他人資料片段，若伺服器端無權限校驗則存在越權存取與資訊洩漏風險。
- **錯誤處理：** 404 與異常參數探測均返回統一的「Gruyere: Error」頁面；經腳本複核，**未發現**框架版本號、Stack Trace 或環境變數外洩。

---

## 2. 攻擊面盤點 (Attack Surface Inventory)

### 2.1 端點清單

| # | 端點 URL | Method | 分類 | 狀態碼 |
|---|----------|--------|------|--------|
| 1 | `.../login` | GET | auth_endpoint | 200 |
| 2 | `.../newaccount.gtl` | GET | auth_endpoint | 200 |
| 3 | `.../snippets.gtl?uid=brie` | GET | data_submission_endpoint | 200 |
| 4 | `.../snippets.gtl?uid=cheddar` | GET | data_submission_endpoint | 200 |
| 5 | `.../` | GET | public_functional_page | 200 |
| 6 | `.../saveprofile` | GET | public_functional_page | N/A |

### 2.2 表單清單

| 表單 | 來源頁面 | Method | Action | 輸入欄位 | CSRF Token |
|------|---------|--------|--------|----------|------------|
| 1 | `.../login` | GET | `/login` | `uid`, `pw` | ✗ 缺失 |
| 2 | `.../newaccount.gtl` | GET | `/saveprofile` | `action`, `uid`, `pw`, `is_author` | ✗ 缺失 |

---

## 3. 發現與差距分析 (Findings & Gap Analysis)

### 3.1 缺失 OWASP 安全標頭（5 項）
- **嚴重度：** Medium
- **受影響端點：** 所有探測端點
- **證據：** 回應標頭均缺乏 `Content-Security-Policy`、`Strict-Transport-Security`、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`。
- **根本成因：** Google App Engine 預設不附加 OWASP 推薦標頭，需於 `app.yaml` 或反向代理層顯式設定。

### 3.2 X-XSS-Protection 被顯式禁用
- **嚴重度：** Medium
- **受影響端點：** 所有端點
- **證據：** 回應標頭包含 `x-xss-protection: 0`。
- **根本成因：** 伺服器端顯式關閉了瀏覽器 XSS 防護，在缺乏 CSP 的情況下放大了跨站腳本攻擊風險。

### 3.3 缺乏 CSRF 防護機制
- **嚴重度：** High
- **受影響端點：** `/login`、`/saveprofile`
- **證據：** 登入與帳號建立表單均無包含任何隨機 Token，且 `/saveprofile` 同時接受 GET 與 POST 請求且無 Token 校驗。
- **根本成因：** 系統未實作 Anti-CSRF Token 機制，第三方站點可藉由惡意標籤誘騙瀏覽器發送敏感操作。

### 3.4 登入憑證經由 GET 傳輸
- **嚴重度：** High
- **受影響端點：** `/login`
- **證據：** 表單使用 `method="GET"`，提交後帳號密碼以明文包含在 URL Query String 中。
- **根本成因：** 表單方法設計錯誤，認證流程應使用 POST 傳遞請求主體。

### 3.5 Cookie 機制完全缺失
- **嚴重度：** Low（架構缺陷）
- **受影響端點：** 所有端點
- **證據：** 回應中無任何 `Set-Cookie` 標頭。
- **根本成因：** 應用未採用標準 Cookie-Session 機制，未來若啟用需確保附加 `HttpOnly`、`Secure` 與 `SameSite` 屬性。

### 3.6 `snippets.gtl` 疑似 IDOR 越權缺陷
- **嚴重度：** High
- **受影響端點：** `/snippets.gtl`
- **證據：** 帶入任意 `uid`（如 `brie`、`cheddar`）皆能成功取回資料，無權限判定。
- **根本成因：** 伺服器端未驗證當前連線使用者是否有權限存取該特定 `uid` 之資源。

### 3.7 `is_author` 參數存在角色權限繞過疑慮
- **嚴重度：** High
- **受影響端點：** `/saveprofile`
- **證據：** 帳號建立表單接受客戶端可控的 `is_author` 參數，提交 `is_author=1` 回應 200。
- **根本成因：** 角色與權限未在伺服器端控制，直接信任客戶端傳入之身分參數。

### 3.8 錯誤處理與敏感資訊洩漏（複核：未發現漏洞）
- **嚴重度：** Informational
- **探測結果：** 針對多組 404 路徑與異常參數進行邊界探測，伺服器均回應統一的「Gruyere: Error」頁面，未洩漏 Stack Trace 或環境資訊。

---

## 4. 修復加固指南 (Remediation Guide)

### 4.1 安全回應標頭設定 (App Engine `app.yaml`)
```yaml
handlers:
  - url: /.*
    script: auto
    headers:
      Content-Security-Policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
      Strict-Transport-Security: "max-age=31536000; includeSubDomains; preload"
      X-Frame-Options: "DENY"
      X-Content-Type-Options: "nosniff"
      Referrer-Policy: "strict-origin-when-cross-origin"
      X-XSS-Protection: "1; mode=block"

```

### 4.2 認證表單與 CSRF 防護改進

```html
<form method="POST" action="/login">
    <input name="uid" type="text" required>
    <input name="pw" type="password" required>
    <input name="csrf_token" type="hidden" value="{{ csrf_token() }}">
    <button type="submit">登入</button>
</form>

```

### 4.3 伺服器端存取控制 (IDOR 修復)

```python
@app.route('/snippets.gtl', methods=['GET'])
def get_snippets():
    target_uid = request.args.get('uid')
    current_user = get_session_user()
    
    # 校驗存取者是否為資源擁有者或管理員
    if current_user.uid != target_uid and not current_user.is_admin:
        return ("權限不足，禁止存取他人片段", 403)
        
    return render_snippets(target_uid)

```

---

*報告結束*

