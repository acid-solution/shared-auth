# shared-auth

`shared-auth` 是 JobPilot 与 StudyFlow 共用的账号认证微服务。它只负责账号、登录身份、访问令牌和刷新会话，不读取两个产品的业务数据库，也不提供单点登录。

当前版本支持邮箱注册和登录、邮箱验证码重置密码、密码确认后的账号注销、RS256 Access Token、可撤销并轮换的 Refresh Token、应用受众隔离，以及 Resend 邮件投递。

## 快速启动

前置条件：Docker Desktop 已启动，并已根据 `.env.example` 创建 `.env`。Docker Compose 会自动读取 `.env`，但不会把它打进镜像。

```bash
docker compose up --build -d
docker compose ps
```

服务地址为 `http://127.0.0.1:18082`，PostgreSQL 映射到本机 `5434`。Compose 会在持久化卷中生成 RSA 私钥、等待数据库就绪并自动执行 Goose Migration。
镜像构建使用仓库内的 `vendor` 依赖，因此启动时不需要临时访问 Go Module 代理。

检查状态：

```bash
curl http://127.0.0.1:18082/health/live
curl http://127.0.0.1:18082/health/ready
curl http://127.0.0.1:18082/.well-known/jwks.json
```

停止服务不会删除账号和会话：

```bash
docker compose down
```

只有明确需要清空本地数据时才执行 `docker compose down -v`。

## 邮件发送模式

本地调试业务流程时可以使用开发收件箱：

```env
EMAIL_PROVIDER=dev
DEV_OUTBOX_ENABLED=true
```

测试真实邮件或部署时使用 Resend：

```env
EMAIL_PROVIDER=resend
DEV_OUTBOX_ENABLED=false
RESEND_API_KEY=re_替换为真实密钥
RESEND_FROM=账号中心 <verify@mail.example.com>
```

`RESEND_FROM` 必须使用 Resend 已验证的域名。真实 API Key 只放在未提交的 `.env` 或部署平台 Secret 中；`.env.example` 保持为空。Resend 模式不会开放 `/dev/outbox`。

## 验证码流程

申请 JobPilot 邮箱注册验证码：

```bash
curl -X POST http://127.0.0.1:18082/auth/v1/verifications \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:5173" \
  -d '{"client_id":"jobpilot","email":"person@example.com","purpose":"register"}'
```

响应中的 `challenge_id` 标识一次验证。使用开发发送器时可以读取验证码：

```bash
curl "http://127.0.0.1:18082/dev/outbox?identifier=person@example.com"
```

再使用 `challenge_id` 和六位验证码注册。`-c cookies.txt` 保存 HttpOnly Refresh Cookie：

```bash
curl -c cookies.txt -X POST http://127.0.0.1:18082/auth/v1/register \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:5173" \
  -d '{"client_id":"jobpilot","challenge_id":"替换为 UUID","code":"替换为验证码","password":"change-this-password"}'
```

刷新 Access Token 时不在 JSON 中传 Refresh Token：

```bash
curl -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:18082/auth/v1/token/refresh \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:5173" \
  -d '{"client_id":"jobpilot"}'
```

注销账号需要同时提交当前 Access Token 和当前密码。成功后账号、邮箱身份以及 JobPilot 和 StudyFlow 的全部刷新会话都会永久删除：

```bash
curl -X DELETE http://127.0.0.1:18082/auth/v1/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer 替换为AccessToken" \
  -H "Origin: http://localhost:5173" \
  -d '{"current_password":"替换为当前密码"}'
```

完整接口和请求结构见 [OpenAPI 文档](docs/openapi.yaml)。

## 本机运行与测试

先启动 PostgreSQL，并生成开发密钥：

```bash
docker compose up -d postgres
go run ./cmd/keygen -out .local/private.pem
```

根据 `.env.example` 把环境变量注入当前终端后运行；直接执行 `go run` 不会自动读取 `.env`。也可以使用前面的 Docker Compose 启动方式：

```bash
go run ./cmd/server
```

纯 Go 测试不依赖数据库：

```bash
go test ./...
```

PostgreSQL 生命周期集成测试会重建目标数据库中的表，只能连接专用测试数据库：

```bash
TEST_DATABASE_URL='postgres://shared_auth:shared_auth@127.0.0.1:5434/shared_auth?sslmode=disable' go test ./internal/auth -run TestCompleteAccountLifecycle -v
```

该测试覆盖邮箱注册与登录、验证码复用拒绝、发送限流、应用会话隔离、刷新令牌轮换、密码重置、账号注销、关联数据清理和安全审计保留。

## 安全边界

- 密码使用 bcrypt；默认 cost 为 12。
- Access Token 有效期 15 分钟，包含 `iss`、`sub`、`aud`、`sid`、`jti`、`iat` 和 `exp`。
- Refresh Token 有效期 7 天，只通过应用专属 HttpOnly Cookie 传输，数据库仅保存 SHA-256 摘要。
- 邮箱验证码有效期 10 分钟、最多尝试 5 次，数据库只保存带服务端密钥的 HMAC。
- 同一目标 60 秒内不能重发，每小时最多申请 5 次；同一来源地址每小时最多申请 20 次。
- `jobpilot` 与 `studyflow` 使用不同 Cookie 和 JWT `aud`，登录状态相互独立。
- 退出会立即撤销 Refresh Session；已经签发的 Access Token 最长仍可使用 15 分钟，这是业务服务本地验签的明确取舍。
- 注销账号会删除邮箱身份和全部 Refresh Session，并保留不含密码、验证码或令牌原文的安全审计事件。同一邮箱之后可以重新注册，但会得到新的用户 UUID。
- 下游业务服务如果只在本地验证 JWT，注销前签发的 Access Token 最长仍可能通过验签 15 分钟；业务服务需要把敏感写操作与账号状态查询结合，或等待令牌自然过期。
- `EMAIL_PROVIDER=resend` 时必须提供 API Key 和有效发件地址，同时必须关闭开发收件箱；生产环境拒绝使用开发发送器。
- Resend 调用失败会返回 `503 email_delivery_failed`，并立即作废对应验证码记录。
- RSA 私钥和验证码 HMAC 密钥必须通过部署环境注入，不能提交到仓库。

## 后续接入

下一阶段由 JobPilot 的 `identity.Resolver` 验证 JWKS、签发方和 `aud=jobpilot`，并把 JWT `sub` 转为现有 UUID `user_id`。本仓库当前不会修改 JobPilot 或 StudyFlow。
