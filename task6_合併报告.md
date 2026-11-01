# 任務 #6 漏洞審計報告總和
## http://testasp.vulnweb.com/

> 任務類型：進階 Web 應用架構與威脅建模審計（**非破壞性**）
> 執行限制：請求間隔 0.5~1.0 秒；嚴禁自動化滲透、目錄爆破或破壞性攻擊；漏洞分析採靜態推演、響應比對與輸入邊界驗證（Negative Testing）
> 後端技術棧：IIS 8.5 + 經典 ASP / ASP.NET，Dreamweaver 模板生成，ASPSESSIONID 會話機制
> **確認漏洞：2 項**（均未見 high/critical）

| # | 漏洞名 | 類別 | 等級 | 探索節點 | 獨立記錄 ID | 流量綁定 |
|---|--------|------|------|----------|-------------|----------|
| 1 | 登錄/註冊憑据明文 HTTP 傳輸 | 明文傳輸敏感憑据（缺 TLS，CWE-319） | **medium** | 52 | 6 | 0 |
| 2 | Server / X-Powered-By 標頭與模板路徑技術棧信息洩漏 | Information Disclosure | **low** | 50 | 5 | 0 |

---

# 一、登錄/註冊憑据明文 HTTP 傳輸（node 52 / finding 6，medium）

## 概述
`testasp.vulnweb.com` 僅以 HTTP/80 提供服务，HTTPS/443 端點探測超時不可用。`/Login.asp` 與 `/Register.asp` 的表單以 `POST` 方式將用戶名、密碼等敏感憑据明文提交，全程無 TLS 加密保護。

## 影響與危害
- **憑据嗅探 / MITM**：用戶名、密碼（及註冊頁的姓名、郵箱）明文經網絡傳輸。網絡旁路（交換機、惡意熱點、中間人）可完整竕取憑据，直接導致賬號接管。
- **會話風險疊加**：登錄成功後 `Set-Cookie` 下發 `ASPSESSIONID` 會話 Cookie，且亦經明文体下發；明文凭據問題與會話固定/偽造問題疊加，抬高整體認證鏈攻擊面。
- **嚴重等級 medium 判斷理由**：憑据可被任意網絡竕聽方获取，屬明確且高現實概率的泄露；但目標為 Acunetix 官方公開演示/測試站（頁面頁腳自述「deliberately vulnerable」，數據每日清除），無真實用戶與真實賬號，故不評 high/critical。

## 受影響範圍
- 主機：`testasp.vulnweb.com`（資產 ID 109、112）
- 端點：`/Login.asp`、`/Register.asp`
- 傳輸：`HTTP/1.1` 明文；響應標頭 `Server: Microsoft-IIS/8.5`、`X-Powered-By: ASP.NET`
- 受影響字段：`tfUName`（用戶名）、`tfUPass`（密碼）；註冊頁另含 `tfRName`（姓名）、`tfEmail`（郵箱）

## 復現步驟
1. 用瀏覽器或 HTTP 工具訪問 `http://testasp.vulnweb.com/Login.asp`，確認響應為 `HTTP/1.1 200`，響應頭含 `Server: Microsoft-IIS/8.5`、`X-Powered-By: ASP.NET`；頁面頁腳自述「built using ASP」。
2. 查看返回的登錄頁 HTML：第 27 行 `<form action="" method="POST">`，包含 `<input name="tfUName" type="text">` 與 `<input name="tfUPass" type="password">` — 表單未指向 `https://` 地址。
3. 訪問 `http://testasp.vulnweb.com/Register.asp`：第 27 行 `<form action="" method="post" enctype="application/x-www-form-urlencoded" name="frmRegister">`，含 `tfUName`、`tfUPass` 等字段，同為明文 POST。
4. 對 `https://testasp.vulnweb.com/` 與 `https://testasp.vulnweb.com/Login.asp` 發起 TLS 握手提探測（socket 443 端口 GET，5 秒超時）：均返回 `URLError: timed out`，確認 443/TLS 不可用。
5. 結論：憑据提交必經過明文体。可用任何抓包工具（Wireshark/代理）在兩機之間抓包，提交登錄表單即可觀察 `tfUName`/`tfUPass` 明文出現在 POST body。

## 證據
- **Login.asp 響應頭**（urllib 抓取）：`HTTP/1.1 200`、`Server: Microsoft-IIS/8.5`、`X-Powered-By: ASP.NET`
- **HTTPS 探測超時**（work#1, intent_id=48, 步驟 2812/2818）：
```text
HTTPS FAIL https://testasp.vulnweb.com/          -> URLError <urlopen error timed out>
HTTPS FAIL https://testasp.vulnweb.com/Login.asp  -> URLError <urlopen error timed out>
```
- **Login 頁源碼**（第 27 行起，work#1 抓取）：
```html
<form action="" method="POST">
  <input name="tfUName" type="text" class="Login" id="tfUName">
  <input name="tfUPass" type="password" class="Login" id="tfUPass">
  <input type="submit" value="Login">
</form>
```
- **Register 頁源碼**（第 27 行起，work#1 抓取）：
```html
<form action="" method="post" enctype="application/x-www-form-urlencoded" name="frmRegister">
  <input name="tfUName" type="text" id="tfUName" class="Login">
  <input name="tfRName" type="text" id="tfRName" class="Login">
  <input name="tfEmail" type="text" id="tfEmail" class="Login">
  <input name="tfUPass" type="password" id="tfUPass" class="Login">
  <input type="submit" value="Register me">
</form>
```
- **會話行為佐證**（work#1, intent_id=48）：訪問各頁後 `Set-Cookie: ASPSESSIONID=...`，確認會話亦經明文 HTTP 下發（事實記錄 fact_id=54）。

## PoC
復現步驟即為 PoC；如需自動化驗證，可用以下最小腳本（僅讀取、零破壞）：

```python
import urllib.request
import socket

BASE = "testasp.vulnweb.com"

# 1) 驗證 Login.asp 響應頭僅 HTTP、標頭特徵
r = urllib.request.urlopen(f"http://{BASE}/Login.asp")
print(r.status, dict(r.headers))   # 預期: Server: Microsoft-IIS/8.5, X-Powered-By: ASP.NET

# 2) 驗證 443/TLS 不可達（5s 超時）
try:
    s = socket.create_connection(BASE, 443, timeout=5)
    print("443 OPEN")
except Exception as e:
    print("443 UNREACHABLE:", e)  # 預期: URLError timed out
```

運行預期：返回 IIS/ASP.NET 頭，且 443 超時；結合源碼中的 `method="POST"` + `tfUPass`，即可證明敏感憑据明文傳輸。

## 根因分析
- **架構層面**：Web 伺服器僅暴露 HTTP/80，未部署或不可用 TLS 終結（443 端口超時），IIS 8.5 配置未啟用 HTTPS 站點綁定。
- **應用層面**：Login.asp / Register.asp 前端表單未使用 `https://` 絕對地址，也未設置 `HSTS`/`X-Forwarded-Proto` 等策略，導致客戶端無法感知「必須 HTTPS」。
- 結果：任何涉及身份認證（登錄）與身份註冊（註冊）的表單提交均依賴明文体，屬典型的「缺少 TLS 傳輸加密」（CWE-319）。

## 修復建議
1. **立即啟用 TLS**：IIS 8.5 上為站點綁定 HTTPS（443），部署 CA 證書，配置 HTTP→HTTPS 301/307 跳轉（保留 `X-Forwarded-Proto: https` 以便應用層識別協議）。
2. **HSTS 強制**：添加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`，使瀏覽器永遠優先 TLS。
3. **表單強制 HTTPS 地址**：Login.asp / Register.asp 的 `<form action="...">` 改為絕對 `https://...`，並在前端/後端對非 TLS 請求返回 403。
4. **Cookie 安全屬性**：Set-Cookie 增加 `Secure`、`HttpOnly`，並考慮 `SameSite=Strict`。
5. **升級 IIS**：IIS 8.5 已較舊，建議遷移至 Windows Server 2016/2019/2022 + IIS 10，獲得默認 TLS 1.2/1.3、更嚴格的默認安全配置。
6. **長期建議**：將「傳輸加密」作為威脅建模檢查項納入 CI/CD（自動驗證 HSTS、443 可達性、表單 HTTPS 地址），並在滲透測試報告中作為 P0 項。

> 流量綁定說明：本漏洞流量綁定清單當前為空（version=0，未綁定）。上述證據來自 work#1 實際抓取的響應頭、登錄/註冊 HTML 及 HTTPS 探測命令輸出（probe_tls.py, 步驟 2812），均已存檔。後續若人工關聯原始流量可補充 request/response 原文片段。

---

# 二、Server / X-Powered-By 標頭與模板路徑技術棗信息洩漏（node 50 / finding 5，low）

## 概述
`http://testasp.vulnweb.com/` 的 HTTP 響應標頭明文披露 `Server: Microsoft-IIS/8.5` 與 `X-Powered-By: ASP.NET`，且首頁正文 HTML 註解中暴露 Dreamweaver 模板的實體路徑 `/Templates/MainTemplate.dwt.asp`（另見 `Templatize.asp?item=html/about.html` 等動態端點引用），使攻擊者可無偵測即可鎖定完整技術棗，為後續針對性利用（版本特定的利用、目錄結構猜測）提供情報。

## 影響與危害
- **技術棗指認**：攻擊者可確認後端為 IIS 8.5 + ASP.NET + 經典 ASP，進而鎖定該版本組合成已知歷史漏洞（IIS 8.5 / .NET Framework 4.x 版本對應的 CVE 面），無須自行探測即可構造針對性攻擊。
- **文件結構洩漏**：`/Templates/`、`.dwt.asp` 模板路徑及 `Templatize.asp?item=...` 動態端點暴露了應用內部目錄與模板引擎結構，可輔助攻擊者預測其他模板、腳本位置，降低後續偵查成本。
- **會話機制暴露**：`ASPSESSIONID...` cookie 前綴披露了 ASP 經典會話機制，有助於攻擊者理解會話綁定方式與攻擊面。
- **危害定位**：本漏洞本身不直接導致數據洩漏或系統接管，屬**信息洩漏**，作為前置情報為後續漏洞的發現與利用提供條件，故評定為 **low（低風險）**。

## 受影響範圍
- **資產**：`http://testasp.vulnweb.com/`（探索圖關聯資產 IDs 109、112）
- **受影響標頭**：`Server: Microsoft-IIS/8.5`、`X-Powered-By: ASP.NET`
- **受影響內容**：首頁 `GET /` 響應正文的 HTML 註解：
  - `<!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->`
  - 正文中还引用了 `Templatize.asp?item=html/about.html`
- 從首頁觀測來看為整站通用響應特徵。

## 復現步驟
1. 對目標發起普通 GET 請求（非破壞性）：
```powershell
Invoke-WebRequest -Uri http://testasp.vulnweb.com/ -UseBasicParsing
# 或
curl -s -D headers.txt "http://testasp.vulnweb.com/" -o index.html
```
2. 檢查響應標頭，可見 `Server : Microsoft-IIS/8.5` 與 `X-Powered-By : ASP.NET`。
3. 查看響應正文 HTML，搜索 `InstanceBegin` / `Templates/`，可定位 Dreamweaver 模板路徑註解。
4. 驗證結論：信息存在、非隨機、且無須任何認證即暴露。

## 證據
響應標頭（來自任務 #6 意圖 #47 的 `fetch_headers.ps1` 執行輸出）：
```
STATUS: 200
=== HEADERS ===
Content-Length : 3538
Cache-Control : private
Content-Type : text/html
Date : Sat, 31 Oct 2026 03:24:58 GMT
Set-Cookie : ASPSESSIONIDCACQTDTB=BCHICKOBJDEKEAANCMNEICIF; path=/
Server : Microsoft-IIS/8.5
X-Powered-By : ASP.NET
```
首頁正文片段（`head -c 2000 index.html` 輸出節選）：
```html
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->
<head>
...
    <a href="Templatize.asp?item=html/about.html" class="menu">about</a> -
    <a href="Default.asp" class="menu">forums</a> -
    <a href="Search.asp" class="menu">search</a>
    - <a href="./Login.asp?RetURL=%2FDefault%2Easp%3F" class="menu">login</a> -
    <a href="./Register.asp?RetURL=%2FDefault%2Easp%3F" class="menu">register</a>
```
**流量綁定說明**：本漏洞已保存於獨立記錄 `finding_id=5`，流量綁定清單當前為空（version=0），未綁定到具體 HTTP 流量。以上證據直接來自探索過程保存的原始命令輸出；後續若人工關聯原始請求/響應可補充綁定。

## PoC
復現步驟即為 PoC：一次普通 `GET http://testasp.vulnweb.com/` 即可觀測到 `Server`、`X-Powered-By` 標頭及正文模板路徑註解。可運行的最小腳本：
```powershell
# 非破壞性信息洩漏驗證
$r = Invoke-WebRequest -Uri "http://testasp.vulnweb.com/" -UseBasicParsing
Write-Host $r.Headers.Server
Write-Host $r.Headers."X-Powered-By"
if ($r.Content -match "InstanceBegin\s+template=\"([^\"]+)\"") {
    Write-Host "Exposed template path: $($Matches[1])"
}
```
預期輸出：
```
Microsoft-IIS/8.5
ASP.NET
Exposed template path: /Templates/MainTemplate.dwt.asp
```

## 根因分析
- **Server / X-Powered-By 標頭未關閉**：IIS 默認會返回 `Server` 標頭，且該站未配置 ASP.NET 的 `X-Powered-By` 抑制（默認開啟），導致運行時直接暴露。
- **靜態/動態模板註解未剝離**：頁面由 Dreamweaver 模板生成，生成器將 `<!-- InstanceBegin template="..." -->` 註解隨正文一同下發，未在生產發布流程中做註解剝離。
- 本質上是**響應清理與發布規範缺陷**：既未做標頭定制，也未在發布前做模板註解/敏感路徑清理。

## 修復建議
1. **關閉/改寫 Server 與 X-Powered-By**：IIS 將 `Server` 改為固定字串；在 `web.config` 中設置：
```xml
<system.web>
  <customErrors mode="On">
    <add pattern="*" redirect="~/error.aspx" />
  </customErrors>
</system.web>
```
並在 ASP.NET 層面移除/統一 `X-Powered-By`；或在反向代理層（Nginx/Apache）用 `header always X-Powered-By "";` 與 `add_header Server "www.example.com";` 統一收斂。
2. **發布前剝離模板註解**：在 CMS/模板生成流程中增加「生產環境不輸出 `InstanceBegin` 等編輯器註解」的發布檢查項。
3. **收斂目錄與端點信息**：對 `/Templates/` 目錄做訪問拒絕（返回 403/404，不枚舉文件）；審查 `Templatize.asp?item=...` 類動態文件加載端點，增加參數白名單與類型校驗，防止路徑穿越。
4. **會話 cookie 加堅（關聯建議）**：為 `ASPSESSIONID` 增加 `HttpOnly`、`Secure`（需 HTTPS）與更嚴格的 `path` 約束。
5. **持續監控**：將 `Server`、`X-Powered-By`、模板註解作為 WAF/日誌掃描項定期查核，防止發布流程回退。

---

# 三、總評與觀察

- **架構畫像**：IIS 8.5 + 經典 ASP / ASP.NET，Dreamweaver 模板生成，`ASPSESSIONID` 會話機制；整站 HTTP-only，無 TLS。
- **主要風險組合**：信息洩漏（low，第②項）為前置情報，與明文凭据傳輸（medium，第①項）形成「偵查 → 竕取」鏈；兩者修復動作部分重疊（會話 cookie 加堅、響應清理），可協同落實。
- **未发现**：SQL 注入、路徑穿越、未授權訪問等更高嚴重漏洞（頁腳自述為「deliberately vulnerable」，但本任務為**非破壞性靜態推演**，未實際觸發利用，故不作確認）。
- **流量狀態**：兩項漏洞均未綁定原始 HTTP 流量（bindings 空，version=0），報告均依據探索過程的命令輸出與抓取的響應頭/源碼撰寫。

**文件位置**：本合併報告存於 `data/sessions/conv-11/task6_合併漏洞報告.md`。各項漏洞的獨立詳細報告已分别保存回探索記錄（node 52 / finding 6；node 50 / finding 5）。
