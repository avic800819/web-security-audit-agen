# Web 架構合規與威脅建模報告

**審計對象**：`http://testaspnet.vulnweb.com/default.aspx`（含主要可見功能連結）  
**審計日期**：2026-11-01  
**審計人/執行**：自動化 Web 架構安全稽核管線（Local Agent Pipeline / 非破壞性探測）  
**授權範圍與執行方法**：僅限對入口首頁及主要可見功能連結（about.aspx、login.aspx、Signup.aspx、rssFeed.aspx）的**被動分析**與**標頭探測**；僅 HTTP 協議分析、靜態架構推演與輸入邊界驗證（Negative Testing）。**未**執行任何自動化滲透、漏洞利用、目錄爆破或破壞性操作，保持低頻探測（請求間約 4s）。

---

## 一、審計基本信息

### 1.1 目標端點與審計範圍

| 項目 | 內容 |
|---|---|
| 根 URL | `http://testaspnet.vulnweb.com/default.aspx` |
| 主要可見功能連結 | `about.aspx`、`login.aspx`、`Signup.aspx`、`rssFeed.aspx` |
| 靜態資源 | `/styles.css`、`/images/logo_acunetix.gif`、`/images/rss.gif` 等 |
| 審計維度 | ① 傳輸安全與標頭加固 ② 技術指紋與資訊暴露 ③ 狀態管理與認證架構 |

### 1.2 技術棤指紋

| 項目 | 觀察到的值 | 來源 |
|---|---|---|
| **Server** | `Microsoft-IIS/8.5` | 回應標頭（各 aspx/靜態資源一致） |
| **X-Powered-By** | `ASP.NET` | 回應標頭 |
| **X-AspNet-Version** | `2.0.50727` | 回應標頭 |
| **.NET Framework** | `2.0.50727.8974` | 404 詳細錯誤頁「Version Information」 |
| **meta GENERATOR** | `Microsoft Visual Studio .NET 7.1` | HTML 產生器 meta |
| **meta CODE_LANGUAGE** | `C#` | HTML meta |
| **頁面模型** | ASP.NET Web Forms（Server-side，含 `__VIEWSTATE`/`__VIEWSTATEGENERATOR`/`__EVENTVALIDATION`） | HTML 隱藏欄位 |
| **靜態資源時間** | `Last-Modified: Thu, 29 May 2008` | 靜態資源標頭 |

**結論**：系統為 **IIS 8.5 + ASP.NET 2.0（.NET 2.0.50727.8974）**。ASP.NET 2.0 為 2005 年發布、已**徹底停止微軟安全支援（EOL）**的過時執行環境；Server / X-Powered-By / X-AspNet-Version 三標頭直接暴露精確版本，便於攻擊者比對 CVE。

### 1.3 審計範圍摘要表

| 審計維度 | 關鍵結論 | 風險等級 |
|---|---|---|
| 傳輸安全 | 無 HTTPS、無 HTTP→HTTPS 跳轉、HSTS 等 5 項防護標頭全缺失 | **高 (High)** |
| 技術指紋 | IIS 8.5 + ASP.NET 2.0 過時執行環境全暴露；404 堆疊外泄（CWE-209） | **高/中** |
| 狀態管理 | Session Cookie 缺 Secure/SameSite；無專門 CSRF Anti-Forgery Token；無抗自動化 | **中/高** |

---

## 二、架構攻擊面與威脅建模

> 本節依循 **OWASP Top 10 (2021)** 與 **CWE** 對前述事實進行分類。所有結論均基於意圖 131（傳輸安全）/132（技術指紋）/133（狀態管理）與 finding 136（CWE-209）的真實被動探測與只讀邊界測試得出，**未**進行任何主動利用。

### 2.1 傳輸安全與標頭加固

#### 2.1.1 HTTPS / TLS 未強制（CWE-290 使用不當加密；OWASP A03:2021 Cryptographic Failures）
- 443 端口**不可達**（`curl -k --connect-timeout 5` 報 `Connection timed out`，HTTP code 000）。
- 無 HTTP→HTTPS 301/302 跳轉（最終 URL 仍為 `http://.../default.aspx`）。
- 登入憑證（login.aspx）、註冊資訊（Signup.aspx）、會話 Cookie（`ASP.NET_SessionId`）全程**明文中間碼 HTTP** 傳輸。
- **危害**：攻擊者可實施 MITM / 網絡嗅探，直接竊取會話 Cookie 與表單憑證；無法保證傳輸機密性、完整性。

#### 2.1.2 HSTS 缺失（CWE-324 / CWE-912；OWASP A03）
- 無 `Strict-Transport-Security` 標頭。即使後續啟用 HTTPS，也**無法阻止瀏覽器降級為 HTTP**，無法防 SSL stripping。

#### 2.1.3 防護標頭全缺失
| 標頭 | 狀態 | 風險 | 對應 |
|---|---|---|---|
| `Content-Security-Policy` (CSP) | ❌ 缺失 | 無 XSS 縱深防禦，允許任意來源/內聯 JS/樣式 | OWASP A07 XSS 相關；CWE-79 |
| `X-Frame-Options` | ❌ 缺失 | 頁面可被第三方 iframe 嵌入 → 點擊劫持 Clickjacking | CWE-925 |
| `X-Content-Type-Options` | ✅/❌ 缺失 | 瀏覽器不做 MIME 強校驗 → MIME sniffing（如假 .jpg 內嵌 <script> 可執行） | CWE-137 |
| `Referrer-Policy` | ❌ 缺失 | 預設 Referer 外泄完整 URL（含 token/參數） | CWE-238 / 資訊外泄 |
| `Cache-Control: private` | ✅ 已設置 | 基本 OK（防 CDN 緩存個人會話內容） | — |

### 2.2 技術指紋與資訊暴露（CWE-209 資訊暴露；OWASP A05）

- **版本過度暴露**：Server/IIS 8.5 + X-AspNet-Version 2.0.50727/.NET 2.0.50727.8974 全暴露。ASP.NET 2.0 已 EOL，精確版本可被直接用於 CVE 匹配、漏洞掃描與針對性攻擊（CWE-204 可識別版本資訊）。
- **CWE-209：404 詳細錯誤頁/堆疊外泄（已確认可重現，finding 136）**
  - `GET /does_not_exist_xyz789.aspx` → **404**，返回 ASP.NET 詳細錯誤頁（約 3369 B），含：
    - `<H1>Server Error in '/' Application.</H1>`
    - **完整堆疊追蹤**：`at System.Web.UI.Util.CheckVirtualFileExists(...)`、`BuildManager.GetVPathBuildResultInternal`、`PageHandlerFactory.GetHandlerHelper` 等內部方法呼叫鏈
    - `Version Information: Microsoft .NET Framework Version:2.0.50727.8974; ASP.NET Version:2.0.50727.8974`
    - HTML 註解自曝：`This error page might contain sensitive information because ASP.NET is configured to show verbose error messages using <customErrors mode="Off"/>`
  - 對比：非 `.aspx` 的 `GET /xyz_nonexist_sub` 返回 IIS 預設靜態 404（無堆疊）→ 說明 `.aspx` 路由處於 `customErrors mode="Off"`，**向未登入訪問者外泄內部執行環境架構**。
  - **危害**：攻擊者可獲知內部類/方法呼叫鏈、執行環境版本與部署結構，降低其它攻擊（如注入、越權、RCE 偵測）的成本，構成資訊暴露與攻擊面放大。
  - 註：`/default.aspx?id=...` 的常規參數邊界 Negative Testing（空/空格/超長/特殊字元）均返回 200 正常頁，**未**觸發 Verbose Error——說明該特定入口不洩露錯誤頁，但 `.aspx` 非正常路徑仍洩露。

### 2.3 狀態管理與認證架構（CWE-321/617/352/862；OWASP A07）

#### 2.3.1 Session Cookie 安全標籤缺失
| 頁面 | Cookie | path | HttpOnly | Secure | SameSite |
|---|---|---|---|---|---|
| default.aspx | ASP.NET_SessionId | / | ✅ | ❌ | ❌ |
| login.aspx | ASP.NET_SessionId | / | ✅ | ❌ | ❌ |
| Signup.aspx | ASP.NET_SessionId | / | ✅ | ❌ | ❌ |

- 僅 `HttpOnly` 正確（防 JS 讀取），**缺 Secure 與 SameSite**。
- **Secure 缺失**：Cookie 在明文中間碼 HTTP 下可被嗅探竊取 → 會話劫持。
- **SameSite 缺失**：跨站請求會自動附帶 Cookie → 增大 CSRF 成功率。注意 ASP.NET 2.0 **不原生支援 SameSite**（該屬性於 .NET Framework 4.5+ 引入）。
- **危害**：結合無 HTTPS，攻擊者可 MITM 竊 Cookie 實現會話劫持，或跨站 CSRF 重用會話（CWE-617、CWE-321、CWE-798 相關；OWASP A03/A07）。

#### 2.3.2 CSRF 防護不足（CWE-352 跨站請求偽造；OWASP A07）
各表單均有 `__VIEWSTATE` + `__VIEWSTATEGENERATOR` + `__EVENTVALIDATION`，但**無 per-user 專門 Anti-Forgery Token（無 `__REQUESTVERIFICATION`）**：
- `__VIEWSTATE`：Base64 加密的頁面狀態，攻擊者可**從受害者瀏覽器取得**該值，非 per-user 隨機值。
- `__VIEWSTATEGENERATOR`（如 `CA0B0334`/`C2EE9ABB`/`36F90C25`）：僅做 View State 完整性校驗，**非 CSRF token**。
- 結合 Cookie 跨域發送（缺 SameSite），攻擊者可構造有效跨站 POST 執行敏感操作（改密碼、註冊等）。

#### 2.3.3 抗自動化設計缺陷
- login.aspx / Signup.aspx / default.aspx **無 CAPTCHA、無 Rate Limiting、無 Bot Detection/UA 檢查**。
- 登入/註冊表單可被腳本**批量化自動化**：暴力破解、批量註冊、自動化登入（CWE-862 認證會話管理缺失等）。

### 2.4 同一會話風險鏈（合併）

```
明文中間碼 HTTP（無 TLS / 無 HSTS）
        │  Session Cookie 明文中間碼傳輸（缺 Secure）
        ▼
  攻擊者 MITM 竊取 ASP.NET_SessionId ──▶ 會話劫持（無需密碼）
        │  Cookie 跨域附帶（缺 SameSite）
        ▼
  構造跨站 POST（攜帶受害者 __VIEWSTATE + 會話 Cookie）──▶ CSRF 篡改狀態
        │  無 CSRF Token / 無抗自動化
        ▼
  批量自動化攻擊登入/註冊 ──▶ 帳號濫用 / 憑證爆破
        │  404 堆疊外泄（CWE-209）提供內部結構 + 精確版本
        ▼
  降低後續注入/越權/RCE 偵測成本 ──▶ 攻擊面放大
```

**整體評估：高 (High)** — 無 TLS + 全防護標頭缺失 + Session 缺 Secure/SameSite + 無 CSRF Token + 過時 EOL 執行環境 + 錯誤資訊外泄，形成多條可疊加的攻擊鏈。

---

## 三、防禦加固指南（針對 IIS 8.5 / ASP.NET 2.0）

> ⚠️ **根本建議優先**：ASP.NET 2.0 / IIS 8.5 已超出微軟安全支援且存在已知 CVE，**長期正確做法是遷移升級**（ASP.NET 4.x/8、IIS 10）與部署 TLS 1.2+。以下為在受控測試環境下按當前技術棤可落地的步進加固，**不得**替代升級。

### 3.1 傳輸與標頭層（IIS / 反向代理 ARR）

1. **部署 TLS 1.2+ 並開啟 443 聽取**（IIS 30 安全更新 / 證書綁定）。
2. **HTTP→HTTPS 301 強制跳轉**（URL Rewrite 或 `httpDefaultRedirect`）：
   ```xml
   <!-- IIS 8.5 web.config (站位點根) —— 回應標頭可在此自定義添加 -->
   <system.webServer>
     <httpProtocol>
       <customHeaders>
         <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
         <add name="X-Frame-Options" value="SAMEORIGIN" />
         <add name="X-Content-Type-Options" value="nosniff" />
         <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
       </customHeaders>
     </httpProtocol>
   </system.webServer>
   <!-- 註：Cache-Control 目前已由應用返回 "private"，無需重複；如需覆蓋可在此追加 -->
   ```
3. **CSP**（按實際內聯/外部腳本細化；Web Forms 常需 `unsafe-inline` 過渡）：
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'
   ```
4. **代理層（ARR/反向代理）**：統一注入上述標頭並剝離 `Server`/`X-Powered-By`/`X-AspNet-Version`，避免底層版本外泄（CWE-204）。

### 3.2 抑制詳細錯誤（關閉 customErrors=Off）

```xml
<!-- web.config (應用根) -->
<configuration>
  <system.web>
    <!-- 生產環境關閉詳細錯誤，僅顯示通用錯誤頁 -->
    <customErrors mode="RemoteOn" defaultRedirect="/Error.aspx" />
    <compilation debug="false" />
  </system.web>
</configuration>
```
- 將 `customErrors` 從 `Off` 改為 `RemoteOn`（遠端訪問時顯示自定義通用頁），或部署專用友好 404 頁，**不再**向未登入訪問者回顯堆疊（消滅 finding 136 的 CWE-209）。

### 3.3 Session Cookie 安全標籤

```xml
<configuration>
  <system.web>
    <httpCookies secure="Always" />
    <!-- ASP.NET 2.0 無 SameSite 屬性；需借助 ARR 代理層改寫 Set-Cookie 追加 ; SameSite=Strict/Lax -->
  </system.web>
</configuration>
```
- `secure="Always"`：強制 Cookie 僅經 TLS 下發（需配合 HTTPS）。
- **SameSite**：因 2.0 不支援，推薦在 ARR/反向代理層改寫回應標頭為 `ASP.NET_SessionId=...; HttpOnly; Secure; SameSite=Lax`（對 Web Forms 登入態建議 `Lax` 以相容正常跳轉）。

### 3.4 CSRF 防護（Web Forms）

- **首選**：升級至 ASP.NET 4.5+ 使用 `@Html.AntiForgeryToken()` / `[ValidateAntiForgeryToken]`（生成 `__REQUESTVERIFICATION` per-user 隨機 token）。
- **2.0 過渡**：手動實現 per-user 會話 token（存入 `Session`，表單隱藏欄位輸出，POST 校驗 `Session[token]==posted value`），並強制 `SameSite=Lax/Strict`。
- 示例（Global.asax / 頁面 Code-Behind）：
  ```csharp
  // 頁面載入
  ViewState["csrf"] = Guid.NewGuid().ToString();
  // 表單渲染時輸出 <input type="hidden" name="csrf" value="..." />
  // POST 處理
  if (Request.Form["csrf"] != ViewState["csrf"]) { /* 拒絕 */ }
  ```

### 3.5 抗自動化（登入/註冊）

- 引入 **CAPTCHA**（如 reCAPTCHA v2/v3）。
- 實施 **Rate Limiting**（按 IP+User）：如 IIS ARR / 應用層限制每秒登入/註冊次數。
- 記錄並告警失敗登入（IP/UA/時間序列），配置 IP 黑名单。
- 增加最小密碼策略、登入失敗鎖定。

### 3.6 指紋與版本管理

- 代理層剝離 `Server`、`X-Powered-By`、`X-AspNet-Version`。
- 移除開發環境 `meta GENERATOR` 等除錯資訊（可選）。
- **關鍵**：將 IIS 8.5/ASP.NET 2.0 納入**升級遷移計畫**（EOL 執行環境是上述所有風險的根本源頭）。

---

## 四、結論

| 維度 | 狀態 | 總體 |
|---|---|---|
| 傳輸安全（HTTPS/HSTS/標頭） | **FAIL**（0/6 關鍵項通過） | 高 |
| 技術指紋（版本暴露 + CWE-209） | **FAIL**（全暴露 + 堆疊外泄已確認） | 高/中 |
| 狀態管理（Cookie/CSRF/抗自動化） | **FAIL**（缺 Secure/SameSite、無 CSRF Token、無抗自動化） | 中/高 |

**綜合威脅等級：High**。系統處於明文中間碼傳輸、過時 EOL 執行環境、錯誤資訊外泄與狀態管理薄弱四重疊加狀態，需優先部署 TLS+HSTS、關閉詳細錯誤、補 Cookie 安全標籤與 CSRF 防護，並**將執行環境升級列為根本整改目標**。

> **報告產出說明**：本報告僅基於已有審計檔案（`audit_transport.md`、`audit_fingerprint.md`、`audit_state_auth.md`）及探索事實（134/135/137）與 finding（136，CWE-209）的**匯總重寫**，**未**執行任何主動探測、注入、爆破或破壞性操作。
