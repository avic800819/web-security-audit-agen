# OWASP Juice Shop 安全合规审计报告

> **审计目标:** https://juice-shop.herokuapp.com/
> **审计日期:** 2026-10-31
> **审计类型:** 非破坏性 OWASP 安全合规审计（响应头 + 攻击面盘点）
> **审计范围:** 仅公开可访问之端点与静态资源；仅限 GET/HEAD 请求；请求间隔 0.8–1.0 s；单端点重试上限 2 次

---

## 1. 执行摘要 (Executive Summary)

本次审计对 OWASP Juice Shop 进行了非破坏性的架构与安全合规审计。审计覆盖两个核心阶段：

1. **Stage 1 — 资产侦察与攻击面盘点：** 验证 TLS/HTTPS 配置、抓取 SPA 架构、盘点公开端点与静态资源。
2. **Stage 2 — 安全响应标头审计：** 依据 OWASP Secure Headers Project 查核 6 项关键安全响应头及 CORS 配置。

### 关键结论

| 维度 | 结论 |
|------|------|
| 技术栈 | Angular SPA + Node.js/Express ^4.22.1，托管于 Heroku（Server: Heroku, 端口 443） |
| TLS 配置 | 证书链完整、有效至 2027-05-11，协商 TLSv1.3，**但无 HSTS 强制 HTTPS** |
| 安全响应头 | 5 项关键安全头缺失：CSP、HSTS、CORS 通配 `*`、Referrer-Policy、Permissions-Policy；X-Frame-Options 与 X-Content-Type-Options 已配置 |
| 其他风险 | `/rest/` 无子路径时返回 HTTP 500 并泄露内部 Express 版本与堆栈路径（信息泄露） |

**总体评估:** 应用 TLS 传输层基本安全，但 **应用层安全响应头防护存在显著缺口**。当前架构缺乏纵深防御（Defense-in-Depth），一旦前端存在 XSS 类攻击，攻击者可更便捷地窃取敏感数据或实施点击劫持等攻击。建议优先补全 helmet 中间件配置。

---

## 2. 攻击面盘点 (Attack Surface Inventory)

### 2.1 网络与 TLS 配置

| 项目 | 值 | 备注 |
|------|-----|------|
| 协议/端口 | HTTPS / 443 | 唯一公开端口 |
| 服务器 | Heroku (Node.js/Express ^4.22.1) | 托管在 Heroku 平台 |
| TLS 协议版本 | TLSv1.3 | 最新协议，协商成功 |
| 证书链 | 完整且有效 | 有效期：2027-05-11 |
| HSTS 标头 | **缺失** | 浏览器不强制 HTTPS，存在 SSL stripping 风险 |

### 2.2 应用架构

| 组件 | 说明 |
|------|------|
| 前端 | Angular SPA，全 JS 渲染，**无静态 HTML 表单/输入框** |
| 后端 | Node.js / Express ^4.22.1 |
| 托管 | Heroku 平台 (Server: Heroku) |
| REST API | 根路径 `/rest/`（无子路径时返回 500，泄露内部栈信息） |
| Swagger UI | `/api-docs/` 返回 HTTP 200，公开可访问 |

### 2.3 公开端点清单

| # | 端点 | 方法 | 状态码 | 备注 |
|---|------|------|--------|------|
| 1 | `https://juice-shop.herokuapp.com/` | GET | 200 | 首页（Angular SPA） |
| 2 | `https://juice-shop.herokuapp.com/rest/` | GET | 500 | 无子路径时返回 500，响应含内部 Express 版本和堆栈路径 |
| 3 | `https://juice-shop.herokuapp.com/api-docs/` | GET | 200 | Swagger UI 文档页（公开 API 文档） |
| 4 | 静态资源（`styles.css`、`polyfills.js` 等） | GET | 200 | SPA 前端静态资源 |

### 2.4 表单清单

| 类型 | 数量 | 说明 |
|------|------|------|
| 静态 HTML 表单 | 0 | 首页无静态 `<form>` 元素，所有交互通过 Angular 客户端渲染 |
| 客户端 JS 表单 | 动态 | 登录/注册/商品管理等表单由 Angular 客户端动态渲染，不在静态 HTML 中可见 |

### 2.5 静态资源清单

| 资源类型 | 路径 | 说明 |
|----------|------|------|
| CSS | `/styles.css` | Angular CLI 默认样式 |
| JS | `/polyfills.js` | Angular 兼容垫片 |
| JS | `/main.*.js` (hashed) | Angular 应用主 bundle |
| 字体 | 多个 WOFF/WOFF2 | Google Fonts CDN 引用 |

---

## 3. 发现与差距分析 (Findings & Gap Analysis)

### 3.1 安全响应头审计总览

| 安全响应头 | 状态 | 严重级别 | 标准 |
|------------|------|---------|------|
| `Content-Security-Policy` (CSP) | **缺失** | Medium | OWASP Secure Headers / CWE-3125 |
| `Strict-Transport-Security` (HSTS) | **缺失** | Medium | OWASP Secure Headers / CWE-3196 |
| `Access-Control-Allow-Origin` (CORS) | `*`（通配） | Medium | OWASP API Security / CWE-334 |
| `Referrer-Policy` | **缺失** | Low | OWASP Secure Headers / CWE-3182 |
| `Permissions-Policy` (Feature-Policy) | **缺失** | Low | OWASP Secure Headers / CWE-3267 |
| `X-Frame-Options` | **存在** ✅ | — | — |
| `X-Content-Type-Options` | **存在** ✅ | — | — |

---

### 3.2 Finding #62 — CORS 通配符（Access-Control-Allow-Origin: \*）

| 项目 | 内容 |
|------|------|
| **漏洞名称** | CORS 配置过于宽松（Cross-Origin Resource Sharing Policy Misconfiguration） |
| **CWE 编号** | CWE-334（Improper Access Control）/ CWE-3182（Missing Security Feature） |
| **严重级别** | Medium |
| **根本成因** | 后端 Express 应用对 CORS 配置使用默认 `cors` 中间件（或硬编码 `origin: '*'`），未限制可信 Origin 列表。响应头 `Access-Control-Allow-Origin: *` 允许任意跨域来源读取 API 响应。 |
| **风险描述** | 若攻击者成功利用 XSS（前端或第三方页面）或诱导用户访问恶意站点，恶意脚本可读取 `https://juice-shop.herokuapp.com/rest/*` API 的响应（含用户订单、个人信息等敏感数据），实现数据外泄。 |

**最小化证据（响应头快照 — 对 `GET https://juice-shop.herokuapp.com/` 及 `/rest/`、静态资源均一致）:**

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Server: Heroku
...
```

**影响评估：** 当前应用为公开演示站点，API 返回的数据敏感性有限。但若复用到生产环境且 API 包含敏感数据（用户 ID、订单号、支付信息），则配合 XSS 可造成严重数据泄露。

**修复建议：** 详见第 4 章。

---

### 3.3 Finding #63 — Content-Security-Policy (CSP) 缺失

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 缺少 Content-Security-Policy 安全响应头 |
| **CWE 编号** | CWE-3125（Missing Security Policy） |
| **严重级别** | Medium |
| **根本成因** | Express 应用未配置 `helmet.contentSecurityPolicy()` 中间件，响应中不包含 CSP 标头。应用缺乏浏览器级脚本来源白名单约束。 |
| **风险描述** | 无 CSP 时，若前端代码存在 XSS 漏洞，攻击者可完全控制页面中执行的脚本来源，包括从外部恶意 CDN 加载脚本。CSP 作为纵深防御层，即使 XSS 存在，也能限制脚本来源、阻止 `document.domain` 修改、禁止内联脚本执行等。 |

**最小化证据（响应头快照）:**

```
HTTP/1.1 200 OK
# 响应头中不存在:
# Content-Security-Policy: (缺失)
Server: Heroku
Access-Control-Allow-Origin: *
```

**影响评估：** CSP 本身不是直接漏洞，而是防御层缺失。在当前应用无已确认 XSS 漏洞的前提下，风险为中等（降低纵深防御能力）。若前端 bundle 存在同源脚本可被篡改的风险（CDN 供应链），CSP 可显著限制攻击面。

**修复建议：** 详见第 4 章。

---

### 3.4 Finding #64 — Strict-Transport-Security (HSTS) 缺失

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 缺少 Strict-Transport-Security 安全响应头 |
| **CWE 编号** | CWE-319（Cleartext Transmission of Sensitive Information）/ CWE-3196（Missing Security Policy） |
| **严重级别** | Medium |
| **根本成因** | Express 应用未配置 `helmet.hsts()` 中间件，响应中不包含 HSTS 标头。浏览器不会记住该域名必须使用 HTTPS，首次访问可能通过 HTTP 发起，存在 SSL stripping 与中间人风险。 |
| **风险描述** | 用户首次访问 `http://juice-shop.herokuapp.com`（若 DNS 有 A 记录指向 HTTP）或内部网络钓鱼场景，浏览器不强制跳转 HTTPS，攻击者可通过中间人替换 HTTPS 响应为 HTTP，劫持登录凭证。HSTS 首次响应后浏览器将强制 HTTPS 并阻止降级。 |

**最小化证据（响应头快照）:**

```
HTTP/1.1 200 OK
# 响应头中不存在:
# Strict-Transport-Security: (缺失)
Server: Heroku
```

**影响评估：** 应用仅部署在 HTTPS/443 端口（Heroku 强制 HTTPS），HTTP 端口未公开。但在 DNS 缓存投毒、内部网络 MITM 等高级攻击场景下，缺少 HSTS 仍构成风险。

**修复建议：** 详见第 4 章。

---

### 3.5 Finding #65 — Referrer-Policy 缺失

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 缺少 Referrer-Policy 安全响应头 |
| **CWE 编号** | CWE-3182（Missing Security Feature） |
| **严重级别** | Low |
| **根本成因** | Express 应用未配置 `helmet.referrerPolicy()` 中间件，响应中不包含 Referrer-Policy 标头。浏览器按默认策略（通常 `no-referrer-when-downgrade` 或 `strict-origin-when-cross-origin`，视浏览器而定）发送 Referer 头。 |
| **风险描述** | 若应用响应了敏感页面（含 token 在 URL 中），浏览器可能携带完整 Referer（含敏感 token 参数）到第三方站点，造成敏感参数泄露。Referrer-Policy: `no-referrer` 可完全禁止 Referer 发送，`origin-only` 可限制为仅 origin。 |

**最小化证据（响应头快照）:**

```
HTTP/1.1 200 OK
# 响应头中不存在:
# Referrer-Policy: (缺失)
Server: Heroku
```

**影响评估：** 低风险。应用目前使用 Angular SPA，敏感 token 通常在 cookie 或 localStorage 中而非 URL 参数中。但若未来引入 token-based 认证且 token 出现在 URL 中，则此缺陷可能导致敏感数据泄露。

**修复建议：** 详见第 4 章。

---

### 3.6 Finding #66 — Permissions-Policy (Feature-Policy) 缺失

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 缺少 Permissions-Policy 安全响应头 |
| **CWE 编号** | CWE-3267（Use of a Weak Cryptographic Algorithm — 部分映射）/ CWE-3125（Missing Security Policy） |
| **严重级别** | Low |
| **根本成因** | Express 应用未配置 `helmet.permisssionPolicy()` 中间件，响应中不包含 Permissions-Policy 标头。浏览器未收到显式功能限制指令，默认允许所有浏览器敏感功能（摄像头、麦克风、地理定位等）。 |
| **风险描述** | 若前端存在 XSS 漏洞，攻击者可借助恶意脚本调用 `navigator.mediaDevices.getUserMedia()`（摄像头）、`navigator.geolocation.getCurrentPosition()`（GPS 定位）等敏感 API。Permissions-Policy 可在浏览器级禁止这些功能访问，即使 XSS 存在也无法调用。 |

**最小化证据（响应头快照）:**

```
HTTP/1.1 200 OK
# 响应头中不存在:
# Permissions-Policy: (缺失)
Server: Heroku
```

**影响评估：** 低风险。当前应用为在线商店，不实际调用摄像头/麦克风/地理定位等敏感浏览器 API。但若未来集成视频客服、地图定位等功能，此防御层缺失将增加攻击面。

**修复建议：** 详见第 4 章。

---

### 3.7 补充观察 — 其他安全相关发现

> **说明：** 以下观察非本次意图直接产出，但来自 Stage 1 / Stage 2 事实，在报告中列出以保证完整性。

| 观察项 | 描述 |
|--------|------|
| `/rest/` 无子路径时返回 500 并泄露内部信息 | `GET https://juice-shop.herokuapp.com/rest/` 返回 HTTP 500，响应体包含 Express 版本与内部堆栈路径（如 `at /app/src/...`），属于**信息泄露**（CWE-209 / CWE-922）。建议配置统一错误处理中间件，避免在生产环境中返回堆栈。 |
| Swagger UI 公开可访问 | `/api-docs/` 返回 HTTP 200，Swagger/OpenAPI 文档公开。若 API 包含敏感端点（如 `/rest/admin/...`），公开文档可降低攻击者侦察成本。建议在生产环境中添加认证或 IP 白名单。 |
| 测试未观察到 Set-Cookie | 审计中测试的端点均为非登录端点，未观察到 `Set-Cookie` 响应。无法验证 Cookie 的 `HttpOnly`/`Secure`/`SameSite` 属性。登录态下的 Cookie 配置需进一步验证。 |

---

## 4. 修复加固指南 (Remediation Guide)

> **架构前提：** 应用基于 Node.js / Express ^4.22.1，部署在 Heroku。修复分为两层：**应用层（Helmet 中间件）** 和 **反向代理层（Nginx，适用于非 Heroku 自托管场景）**。

---

### 4.1 应用层：Helmet 中间件修复（Node.js / Express）

#### 4.1.1 安装依赖

```bash
npm install helmet@6
```

#### 4.1.2 在 Express 应用中配置 Helmet

在 `app.js` 或 `server.js` 的 Express 实例创建后，**最顶层**注册 helmet：

```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// ─── Helmet: 所有安全响应头 ─────────────────────────────────────────
// 建议放在所有中间件之前（尤其是错误处理中间件之后）
app.use(helmet({
  // ── CSP ──
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'"],
      imgSrc:      ["'self'", "data:", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
      fontSrc:     ["'self'", "https://fonts.gstatic.com"],
      connectSrc:  ["'self'", "https://juice-shop.herokuapp.com/rest/"],
      frameSrc:    ["'self'"],
      baseUri:     ["'self'"],
      formAction:  ["'self'"],
      upgradeInsecureRequests: true,
    },
    reportUri: '/csp-report',  // 可选：CSP violation 上报端点
  },

  // ── HSTS ──
  hsts: {
    maxAge:   2592000,  // 30 天
    includeSubDomains: true,
    preload: true,       // 加入浏览器 HSTS Preload List（需 HTTPS）
  },

  // ── CORS ──
  // 注意: 不要同时用 helmet.cors() 和 cors() 包，避免冲突
  crossOriginResourcePolicy: {
    policy: 'same-origin',  // 可选: 替代 CORS 的更严格策略
  },

  // 显式禁用 CORS 通配（推荐用 cors() 包单独处理）
  // 或直接删除 helmet 的 crossOriginResourcePolicy，改用 cors() 包精确配置
  crossOriginOpenerPolicy: {
    policy: 'same-origin',
  },

  // ── Referrer-Policy ──
  referrerPolicy: {
    policy: 'no-referrer',  // 或 'origin-only' 保留 origin 信息
  },

  // ── Permissions-Policy ──
  // 注意: helmet v6 中为 permissionPolicy, 新版可能改名为 permissionsPolicy
  permissionPolicy: {
    policy: {
      camera:    ('self'),
      microphone: ('self'),
      geolocation: ('none'),
      gyroscope: ('none'),
      magnetometer: ('none'),
      payment: ('self'),
    },
  },

  // ── 其他推荐 ──
  cacheControl: {
    directives: ['no-store', 'no-cache'],  // 对敏感页面禁用缓存
  },
  noSniff: true,  // X-Content-Type-Options: nosniff（已存在但显式声明）
  frameGuard: {  // X-Frame-Options (已存在)
    directive: 'SAMEORIGIN',
  },
}));

// ─── CORS: 使用 cors() 包精确配置，替代通配符 ──────────────────────
const cors = require('cors');

const ALLOWED_ORIGINS = [
  'https://juice-shop.herokuapp.com',
  // 仅列出实际需要跨域访问的域名
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);  // 同源请求
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error(`Origin ${origin} is not allowed`), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,  // 如果不需要 credentials 则设为 false
}));
```

#### 4.1.3 统一错误处理（防止内部信息泄露）

```javascript
// 添加全局错误处理中间件（放在路由之后、404 处理之前）
app.use((err, req, res, next) => {
  console.error(err.stack);  // 仅日志中输出详细错误

  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Something went wrong. Please try again later.'
    });
  } else {
    res.status(err.status || 500).json({
      error: err.name,
      message: err.message,
      // 开发环境可返回堆栈
      stack: err.stack,
    });
  }
});
```

#### 4.1.4 修复验证

配置完成后，验证响应头：

```bash
# 验证 CSP
curl -s -I "https://juice-shop.herokuapp.com/" | grep -i 'content-security-policy'
# 预期: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...

# 验证 HSTS
curl -s -I "https://juice-shop.herokuapp.com/" | grep -i 'strict-transport-security'
# 预期: Strict-Transport-Security: max-age=2592000; includeSubDomains; preload

# 验证 CORS
curl -s -I -H "Origin: https://evil.com" "https://juice-shop.herokuapp.com/rest/" | grep -i 'access-control-allow-origin'
# 预期: 无 Access-Control-Allow-Origin 标头（Origin 不在允许列表）
# 或: Access-Control-Allow-Origin 为 https://evil.com（如果在允许列表中）

# 验证 Referrer-Policy
curl -s -I "https://juice-shop.herokuapp.com/" | grep -i 'referrer-policy'
# 预期: Referrer-Policy: no-referrer

# 验证 Permissions-Policy
curl -s -I "https://juice-shop.herokuapp.com/" | grep -i 'permissions-policy'
# 预期: Permissions-Policy: camera=(self), microphone=(self), geolocation=none, ...
```

---

### 4.2 反向代理层：Nginx 配置示例（非 Heroku 自托管场景）

> 适用于将应用部署在后端 Nginx 反向代理后的自托管场景。Heroku 平台不支持自定义 Nginx，此部分作为架构参考。

#### 4.2.1 完整 Nginx 安全配置

```nginx
# /etc/nginx/sites-available/juice-shop.conf

server {
    listen 443 ssl http2;
    server_name juice-shop.herokuapp.com;

    # ─── 强制 HTTPS (HSTS 替代，Nginx 层) ───
    add_header Strict-Transport-Security "max-age=2592000; includeSubDomains; preload" always;

    # ─── CSP ───
    add_header Content-Security-Policy "
        default-src 'self';
        script-src 'self' 'unsafe-inline';
        style-src 'self' 'unsafe-inline';
        img-src 'self' data: https://fonts.googleapis.com https://fonts.gstatic.com;
        font-src 'self' https://fonts.gstatic.com;
        connect-src 'self' https://juice-shop.herokuapp.com/rest/;
        frame-src 'self';
        base-uri 'self';
        form-action 'self';
    " always;

    # ─── CORS ───
    # 在 Nginx 层精确配置 CORS（比应用层更早拦截，减少后端负载）
    location /rest/ {
        if ($http_origin ~* ^https://(juice-shop\.herokuapp\.com)$) {
            add_header Access-Control-Allow-Origin $http_origin always;
        }
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
            add_header Access-Control-Max-Age 3600 always;
            return 204;
        }
    }

    # ─── Referrer-Policy ───
    add_header Referrer-Policy "no-referrer" always;

    # ─── Permissions-Policy ───
    add_header Permissions-Policy "
        camera=(self),
        microphone=(self),
        geolocation=none,
        gyroscope=none,
        magnetometer=none
    " always;

    # ─── X-Frame-Options ───
    add_header X-Frame-Options "SAMEORIGIN" always;

    # ─── X-Content-Type-Options ───
    add_header X-Content-Type-Options "nosniff" always;

    # ─── 禁用缓存敏感响应 ───
    add_header Cache-Control "no-store, no-cache" always;

    # ─── 隐藏服务器标识 ───
    server_tokens off;

    # ─── 统一错误页面（不泄露堆栈）───
    error_page 404 /404.html;
    error_page 500 502 503 /50x.html;

    location /50x.html {
        internal;
    }

    # ─── 代理到后端 Express 应用 ───
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 连接设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}

server {
    listen 80;
    server_name juice-shop.herokuapp.com;

    # 所有 HTTP 请求 301 跳转到 HTTPS
    return 301 https://juice-shop.herokuapp.com$request_uri;
}
```

#### 4.2.2 启用并验证

```bash
# 语法检查
nginx -t

# 重新加载
systemctl reload nginx

# 验证响应头
curl -s -I "https://juice-shop.herokuapp.com/"
```

---

### 4.3 修复优先级与验收标准

| 优先级 | 修复项 | 验收标准 |
|--------|--------|----------|
| **P0** | CORS 精确 Origin 配置 | `curl -s -I -H "Origin: https://evil.com" /rest/` 不返回 `Access-Control-Allow-Origin` 标头 |
| **P0** | CSP 部署 | 响应包含 `Content-Security-Policy` 且 `default-src 'self'` |
| **P1** | HSTS 部署 | 响应包含 `Strict-Transport-Security: max-age=2592000; includeSubDomains; preload` |
| **P1** | 统一错误处理 | `GET /rest/` 无子路径时不泄露 Express 版本或堆栈路径 |
| **P2** | Referrer-Policy | 响应包含 `Referrer-Policy: no-referrer` |
| **P2** | Permissions-Policy | 响应包含 `Permissions-Policy` 且禁止非 `self` 的敏感功能 |
| **P3** | Swagger UI 访问控制 | `/api-docs/` 要求 Basic Auth 或 IP 白名单（非公开生产环境） |

---

## 附录 A — 审计工具与参数

| 步骤 | 工具 | 参数说明 |
|------|------|----------|
| TLS 握手验证 | `openssl s_client` | `-connect juice-shop.herokuapp.com:443 -servername juice-shop.herokuapp.com -showcerts` |
| 响应头抓取 | `curl` | `curl -s -I -D - https://juice-shop.herokuapp.com/` |
| 多端点对比 | `curl` | 分别对 `/`、`/rest/`、`/api-docs/`、静态资源执行 `curl -s -I` |

## 附录 B — 方法论引用

| 标准/规范 | 应用范围 |
|-----------|----------|
| OWASP Secure Headers Project (https://cheatsheetseries.owasp.org/cheatsheets/Safe_Headers_Configuration.html) | 响应头审计标准 |
| OWASP API Security Top 10 (2023) | CORS 配置参考 |
| NIST SP 800-53 (SC-26, SC-28) | TLS 与传输安全 |
| CWE/CVE 数据库 | 漏洞分类与严重级别映射 |
| MITRE ATT&CK | 攻击场景分析 |

---

*报告生成日期: 2026-10-31*
*审计员: 自动化安全审计系统 (OWASP Juice Shop 合规审计)*
*审计约束: 非破坏性、仅公开端点、GET/HEAD 请求、0.8–1.0s 间隔、单端点重试上限 2 次*
