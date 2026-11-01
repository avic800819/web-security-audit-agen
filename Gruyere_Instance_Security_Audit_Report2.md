# Gruyere 實例安全審計報告

**目標：** https://google-gruyere.appspot.com/558732479247968011871453863040124306826/

**報告日期：** 2026-10-31

---

## 1. Executive Summary（執行摘要）

- **部署形態：** Google App Engine 托管服務（Server: Google Frontend），HTTPS 端點。
- **TLS 安全：** HTTPS 已啟用，但**未設定 HSTS（Strict-Transport-Security）**，存在協議降级風險。
- **安全標头：** 7 個端點上 **5 項 OWASP 推薦安全標头缺失**：
  - Content-Security-Policy (CSP) — 未設定
  - Strict-Transport-Security (HSTS) — 未設定
  - X-Frame-Options — 未設定（無 clickjacking 防護）
  - X-Content-Type-Options — 未設定（無 MIME  sniffing 防護）
  - Referrer-Policy — 未設定（無 referrer 泄露防護）
- **X-XSS-Protection：** 顯式設為 `0`（禁用），未啟用瀏覽器 XSS 防護。
- **Cookie：** 所有響應**未設定任何 Set-Cookie**，無 session cookie。
- **認證設計：** 登入表單以 **GET 方法**提交 `uid`/`pw`，凭據暴露在 URL query string、瀏覽器歷史、服务器日誌及 Referer 頭中。
- **CSRF：** 兩個表單（login、saveprofile/newaccount）均**無 CSRF token**。
- **IDOR 嫌疑：** `snippets.gtl?uid=<id>` 接受任意 uid 參數查詢他人片段，若無服务端權限校驗則存在 IDOR / 信息泄漏風險。
- **錯誤處理：** 404 / 異常參數探測均返回統一「Gruyere: Error」頁面；經 verify.py 複核，**未发现**框架版本、Stack Trace、環境變量等敏感信息洩露。

---

## 2. Attack Surface Inventory（攻擊面盤點）

### 2.1 端點總覽（6 個端點）

| # | 端點 URL | Method | 分類 | 狀態 |
|---|----------|--------|------|------|
| 1 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/login | GET | auth_endpoint | 200 |
| 2 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/newaccount.gtl | GET | auth_endpoint | 200 |
| 3 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/snippets.gtl?uid=brie | GET | data_submission_endpoint | 200 |
| 4 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/snippets.gtl?uid=cheddar | GET | data_submission_endpoint | 200 |
| 5 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/ | GET | public_functional_page | 200 |
| 6 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/saveprofile | GET | public_functional_page | N/A |

### 2.2 表單盤點（2 個表單）

| 表單 | 來源頁面 | Method | Action | 欄位 | CSRF Token |
|------|---------|--------|--------|------|------------|
| 1 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/login | GET | /558732479247968011871453863040124306826/login | uid, pw | ✗ 缺失 |
| 2 | https://google-gruyere.appspot.com/558732479247968011871453863040124306826/newaccount.gtl | GET | /558732479247968011871453863040124306826/saveprofile | action, uid, pw, is_author | ✗ 缺失 |

### 2.3 功能分類

| 分類 | 端點數 |
|------|-------|
| public_functional_page | 2 |
| auth_endpoint | 2 |
| data_submission_endpoint | 2 |

---

## 3. Findings & Gap Analysis（發現與差距分析）

### 3.1 缺失 OWASP 安全標头（5 項）

**CVSS 概念評級：** Medium

**受影响端點：** 所有 7 個已探測端點

**證據：** stage2 標头審計顯示 7 個端點響應均缺乏以下標头：
- `Content-Security-Policy` — 未設定
- `Strict-Transport-Security` — 未設定
- `X-Frame-Options` — 未設定
- `X-Content-Type-Options` — 未設定
- `Referrer-Policy` — 未設定

**根因：** 應用未配置安全標头。App Engine 預設不添加 OWASP 推薦頭；需通過 app.yaml / 反代層補充。

### 3.2 X-XSS-Protection 被顯式禁用

**CVSS 概念評級：** Medium

**受影响端點：** 所有 7 個端點

**證據：** 所有 7 個端點響應包含 `x-xss-protection: 0`。

**根因：** 開發者顯式禁用了瀏覽器 XSS 过滤器。若 CSP 已正確設定則無妨，但當前 CSP 缺失，此設定使 XSS 防護完全失效。

### 3.3 無 CSRF 防護

**CVSS 概念評級：** High

**受影响端點：** /login、/saveprofile（POST 亦被接受）

**證據：**
- login 表單 Method=GET, 無 CSRF token
- newaccount.gtl → saveprofile 表單 Method=GET, 無 CSRF token
- POST /saveprofile (form-data / plaintext) 均返回 200, 無 token 驗證

**根因：** 應用未實現 CSRF token 機制。任何惡意頁面可通過 `<img src=...>` 或 `<form>` 強迫受害者浏览器提交敏感請求。

### 3.4 登入憑據通過 GET 傳輸

**CVSS 概念評級：** High

**受影响端點：** /login

**證據：** login 表單 method=GET, action=/login, fields=[uid, pw]. 提交後 URL 形如 `?uid=xxx&pw=yyy`.

**風險：** 凭據洩露至 URL、瀏覽器歷史、HTTP Referer 頭、代理/CDN 日誌、服务器日誌。

**根因：** 表單設計錯誤，認證請求應使用 POST。

### 3.5 Cookie 完全缺失（無 session 機制）

**CVSS 概念評級：** Low（當前無 session 時風險較低，但架構缺陷）

**受影响端點：** 所有端點

**證據：** 7 個端點響應均未包含 `Set-Cookie` 頭。

**根因：** 應用未使用傳統 cookie-session 架構，可能採用品名/令牌方式認證。若未來啟用 cookie，需確保 HttpOnly / Secure / SameSite 屬性。

### 3.6 snippets.gtl uid 參數 — 疑似 IDOR / 信息泄漏

**CVSS 概念評級：** High

**受影响端點：** /snippets.gtl

**證據：**
- `snippets.gtl?uid=brie` → 200, 顯示 brie 的片段
- `snippets.gtl?uid=cheddar` → 200, 顯示 cheddar 的片段
- 任意 uid 值均可被接受，無端點授權校驗

**風險：** 若無伺服器端權限校驗（即用戶只能看自己的 uid 的片段），則存在 IDOR 漏洞，可任意查看/修改他人片段。

**根因：** 端點以 uid 直接查詢，未驗證當前會話用戶與 uid 的對應關係。

### 3.7 is_author 參數 — 疑似權限繞過

**CVSS 概念評級：** High

**受影响端點：** /saveprofile（via /newaccount.gtl）

**證據：** saveprofile 接受 `is_author` 參數，該參數由客户端控制。探測 `?uid=brie&pw=&is_author=1` 返回 200。

**風險：** 若 is_author 用於控制權限角色，則攻擊者可通過直接修改該參數繞過權限校驗。

**根因：** 權限屬性從客户端輸入讀取，未在伺服器端驗證。

### 3.8 錯誤處理與信息洩露（已核實：未發現洩露）

**CVSS 概念評級：** —（無漏洞）

**探測結果：**
- 6 個 404 路徑探測（/nonexistent-*, /secretadmin, /config, /.env）
- 10 個異常參數探測（空 uid / 數字 uid / URL-encoded uid 等）
- 所有響應均為統一「Gruyere: Error」頁面 (200, ~2250 bytes)

**verify.py 複核：** 響應中未發現框架版本號、Stack Trace、環境變量、源碼路徑等敏感信息。

**結論：** 錯誤處理符合「最小信息洩露」原則，**未发现**錯誤信息洩露漏洞。

---

## 4. Remediation Guide（補救指南）

### 4.1 安全標头配置（App Engine / Nginx）

#### app.yaml 示例
```yaml
handlers:
  - url: /.*
    script: auto
    headers:
      Content-Security-Policy: "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
      Strict-Transport-Security: "max-age=31536000; includeSubDomains; preload"
      X-Frame-Options: DENY
      X-Content-Type-Options: nosniff
      Referrer-Policy: strict-origin-when-cross-origin
      X-XSS-Protection: "1; mode=block"
```

#### Nginx 反代層示例
```nginx
server {
    listen 443 ssl http2;
    server_name google-gruyere.appspot.com;
    location / {
        add_header Content-Security-Policy "default-src 'self'" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header X-XSS-Protection "1; mode=block" always;
        proxy_pass http://upstream;
    }
}
```

### 4.2 CSRF 防護

```python
# 例: Flask + Flask-WTF CSRF
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# 模板:
# <form method="POST" action="/saveprofile">
#   {{ form.hidden_tag() }}  <!-- 包含 <input name="csrf_token" ...> -->
#   ...
</form>
```

### 4.3 登入改用 POST

```html
<form method="POST" action="/login">
    <input name="uid" type="text" required>
    <input name="pw" type="password" required>
    {{ form.csrf_token }}
    <button type="submit">登入</button>
</form>
```

### 4.4 Cookie 安全屬性

```python
response.set_cookie("session", token,
    secure=True,          # 僅 HTTPS
    httponly=True,        # JS 不可讀
    samesite="Strict"     # 跨站請求不帶 cookie
)
```

### 4.5 端點權限校驗（IDOR 修復）

```python
@app.route('/snippets.gtl', methods=['GET'])
def snippets(uid):
    current_user = get_current_user()  # 從 session / token 取得
    if uid != current_user.uid and not is_admin():
        raise PermissionDenied()
    return render_snippets(uid)
```

---

*報告結束*
