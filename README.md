# web-security-audit-agen
Local LLM-powered automated Web security architecture audit and OWASP compliance pipeline.  （基於本地推論架構之自動化 Web 安全架構審計與 OWASP 合規管線）

---

# Local Web Security Audit Pipeline

基於本地推論架構（Local LLM / Agent Orchestration）構建之非破壞性 Web 應用安全審計自動化管線。系統能在完全保障日誌與資料隱私（無雲端 API 外傳）的前提下，自主完成目標站點的端點爬取、表單邊界解析、OWASP 安全標頭合規比對，並輸出結構化審計報告。

---

## 核心架構與技術棧

- **推論核心**：Local LLM / Agent Orchestration
- **自動化探測**：Python 3 (Requests, BeautifulSoup)
- **分析規範**：OWASP Top 10 (2021)、OWASP Secure Headers Project
- **成果交付**：[查看 Google Gruyere 實例審計報告範例](docs/reports/Gruyere_Security_Audit_Report.md)

---

## 工程挑戰與除錯紀錄 (Engineering Notes)

在實作與調試本地 Agent 自動化管線期間，針對環境、路徑解析及模型推論等瓶頸完成以下工程優化：

### 1. Windows 與 Shell 路徑字元跳脫衝突
- **問題現象**：
  Agent 在初期任務規劃（Planner）調用 Bash 進行中介 JSON 與報告寫檔時，因 Windows 反斜線路徑（如 `E:\Artex\...`）觸發 Shell 跳脫字元解析錯誤，導致管線中斷並引發 500 API 結構異常。
- **修復策略**：
  移除外部 Shell 轉義依賴，將檔案 I/O 全面收斂至 Python 標準庫處理，規範跨平台檔案路徑傳遞機制，確保 Windows 環境下資料落盤穩定性。

### 2. 模型上下文截斷與空轉迴圈治理
- **問題現象**：
  在單一 Prompt 要求過大範圍（同時執行全站爬取、標頭檢驗與長篇 Markdown 渲染）時，模型容易遭遇上下文視窗飽和，引發未調用工具或無文字回包（空轉輸出）的狀態。
- **修復策略**：
  重構為三階段狀態機（State Machine）架構：
  - `Stage 1`：端點枚舉與表單結構化盤點（Recon）
  - `Stage 2`：HTTP 回應標頭比對與輸入邊界驗證（Audit）
  - `Stage 3`：資料彙整與 Markdown 報告組裝（Reporting）
  透過分階段狀態隔離，大幅降低單輪推論負擔，徹底消除模型死迴圈。

### 3. 動態沙盒實例之邊界隔離保證
- **問題現象**：
  針對具備臨時動態路徑之沙盒目標（如 Google Gruyere 的 `/5587.../` 路徑），爬蟲容易因相對路徑解析偏移跳出目標範圍，誤爬全站靜態說明頁。
- **修復策略**：
  實作 Base URL 動態綁定機制，嚴格校驗每次跳轉與請求之 URL 前綴，限制探測動作僅在授權之動態實例邊界內執行，保證資料採集精確度。
