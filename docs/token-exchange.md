# 学习路线代办令牌

JobPilot 确认一份固定学习路线后，可使用服务端配置的 `JOBPILOT_EXCHANGE_SECRET` 作为 HTTP Basic 密码、`jobpilot` 作为用户名，向 `POST /auth/v1/token/exchange` 提交表单。

必填表单字段：`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`、`subject_token_type=urn:ietf:params:oauth:token-type:access_token`、JobPilot 用户的 `subject_token`、`resource`、`scope=learning_route:import learning_route:read`、`import_key`、`content_digest`。

`resource` 必须等于服务端 `STUDYFLOW_MCP_RESOURCE`。生产使用 HTTPS，本地仅允许回环 HTTP。两项配置都为空时不启用交换，不影响原登录。

交换会核验来源令牌、账号和会话有效性。返回令牌与来源使用同一用户身份，但仅用于 StudyFlow MCP 学习路线导入和对应回执查询，绑定导入键和 SHA-256 内容摘要。有效期不超过两分钟或来源令牌剩余期限，不提供刷新令牌。普通页面 API 不接受代办令牌。

密钥和令牌不得写入日志、浏览器、模型上下文或学习路线记录。本接口为固定业务代办，不提供浏览器单点登录，也不开放任意受众或权限的通用交换。
