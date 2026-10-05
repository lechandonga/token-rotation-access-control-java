# 本地自包含接口鉴权与令牌生命周期管理

基于 Spring Boot 3.4 / Java 21 实现的**纯本地**鉴权演示：主体、密钥、令牌族全部保存在内存中，
不依赖数据库、Redis、第三方鉴权服务或真实凭据。令牌使用 JDK 自带的 HMAC-SHA256 自行签名，
格式为 `base64url(claims).base64url(hmacSha256(claims))`，无任何外部令牌库依赖。

## 快速开始

```bash
mvn test          # 运行全部测试，日志按“业务模块 -> 用例 -> 结果”输出
mvn spring-boot:run
```

模拟登录（subjectId 即本地主体标识，无需密码）：

```bash
curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' -d '{"subjectId":"alice"}'
```

内置主体与权限范围（scope）：

| 主体 | 权限范围 |
| --- | --- |
| `alice` | `profile:read` `doc:read` `doc:write` |
| `bob` | `profile:read` `doc:read` |
| `service-report` | `profile:read` |

## HTTP 接口

| 方法 路径 | 说明 | 所需 scope |
| --- | --- | --- |
| `POST /auth/login` | 模拟登录，签发首个访问/刷新凭证对并建立令牌族 | 无 |
| `POST /auth/refresh` | 刷新凭证轮换：旧刷新凭证立即失效，签发新凭证对 | 无（凭刷新凭证） |
| `POST /auth/revoke` | 显式吊销当前访问凭证所属的整个令牌族 | `profile:read` |
| `GET /api/profile` | 读取个人信息 | `profile:read` |
| `GET /api/docs` | 读取文档 | `doc:read` |
| `POST /api/docs` | 更新文档 | `doc:write` |
| `POST /admin/keys/rotate` | 轮换签名密钥（旧密钥进入宽限期） | 本地管理接口 |
| `POST /admin/keys/{kid}/revoke` | 立即吊销指定密钥 | 本地管理接口 |
| `GET /admin/keys` | 查看全部密钥版本与状态 | 本地管理接口 |

受保护接口需携带 `Authorization: Bearer <accessToken>`。

## 令牌生命周期

- **签发（login）**：为主体创建一个**令牌族（family）**，同时签发访问凭证（access token）与
  刷新凭证（refresh token），二者载荷均带 `familyId` 与签名用的 `keyId`。
- **访问（access token）**：短期凭证（默认 10 分钟）。每次请求先验结构、验签、判过期，
  再检查令牌族状态，最后按方法上的 `@RequireScope` 校验权限范围。
- **刷新（refresh token）**：长期凭证（默认 12 小时）。成功使用一次后立即作废，
  由服务端签发一对新凭证，族内“当前刷新凭证 jti”整体前进一步。
- **吊销**：
  - 显式吊销 `/auth/revoke`：令牌族置为 `REVOKED`，族内访问/刷新凭证立即全部失效；
  - 检测到刷新凭证重用：令牌族置为 `COMPROMISED`，族内**所有**凭证（包括尚未到期的最新凭证）
    全部失效，之后该族任何请求都返回 `refresh_token_reused` / `token_family_revoked`。

## 刷新轮换与重用判定规则

1. 每次刷新都在**该令牌族独占的锁**内完成「验签 → 读族状态 → 比对当前 jti → 写新族状态」，
   读改写是一个不可分割的临界区。
2. 提交的刷新凭证 jti 必须等于族内记录的“当前刷新凭证”：
   - 相等且未过期 → 轮换成功，旧 jti 立即被覆盖失效；
   - 不相等 → 说明它是**已被使用过的旧凭证（重用/重放）**，整族标记 `COMPROMISED` 并拒绝。
3. 并发刷新同一凭证时，临界区保证**恰好一个请求成功**，其余请求看到的都不是当前 jti，
   全部失败并触发整族吊销；不存在两个请求同时成功，也不存在状态互相覆盖。
4. 凭证自身过期只返回 `expired_token`，不会把令牌族推进到异常状态；过期后的重放仍按重用语义处理。

## 签名密钥轮换与宽限期

- 每个密钥有独立 `keyId` 与状态机：`ACTIVE → RETIRED → EXPIRED`，任意时刻可被 `REVOKED`
  （`REVOKED`/`EXPIRED` 为终态）。
- 轮换（`/admin/keys/rotate`）：新密钥成为唯一 `ACTIVE`，所有新凭证用它签发；旧 `ACTIVE` 密钥
  变为 `RETIRED`，并记录 `graceDeadline = 轮换时刻 + key-grace-period`。
- **宽限期语义**：`RETIRED` 密钥在宽限期内仍可校验此前签发的旧凭证（访问/刷新均可），
  实现轮换与新旧密钥并存；宽限期一旦结束，旧密钥进入 `EXPIRED`，用它签名的凭证稳定返回
  `invalid_signature`。边界语义为 `now >= graceDeadline` 即失效，判定结果不会在通过/拒绝间抖动。
- 立即吊销（`/admin/keys/{kid}/revoke`）：不等宽限期，旧密钥即刻 `REVOKED`，其凭证立刻失效。
- 密钥库所有读写均受读写锁保护，轮换/吊销与并发校验之间不会出现同一凭证“时好时坏”。
- 密钥标识不存在时返回 `unknown_key`，与签名错误 `invalid_signature` 区分。

## 可区分的拒绝原因

错误响应统一为 `{"code":..., "status":..., "message":...}`：

| code | HTTP | 触发条件 |
| --- | --- | --- |
| `missing_credential` | 401 | 缺少 `Authorization` 头 |
| `malformed_credential` | 401 | 非 Bearer 结构、段数/Base64URL/载荷无法解析、缺少 keyId |
| `invalid_signature` | 401 | 签名不匹配、密钥已吊销或宽限期已过 |
| `unknown_key` | 401 | 凭证指向的密钥标识在密钥库中不存在 |
| `expired_token` | 401 | 访问/刷新凭证自身超过有效期 |
| `revoked_token` | 401 | 令牌族被显式吊销 |
| `token_family_revoked` | 401 | 令牌族因刷新凭证重用被整体吊销（访问凭证侧） |
| `refresh_token_reused` | 401 | 使用了已用过的刷新凭证（含并发落败方） |
| `insufficient_scope` | 403 | 凭证有效但权限范围不足 |
| `invalid_subject` | 401 | 模拟登录的主体不存在 |

任何失败都不会静默放行。

## 可配置项

前缀 `token-rotation.security`（`src/main/resources/application.properties`）：

| 配置项 | 默认值 | 含义 |
| --- | --- | --- |
| `access-ttl` | `10m` | 访问凭证有效期 |
| `refresh-ttl` | `12h` | 刷新凭证有效期 |
| `key-grace-period` | `7d` | 旧签名密钥轮换后的验签宽限期 |

时长使用 Spring Boot 的 Duration 写法（如 `30s`、`2m`、`12h`、`7d`）。

## 测试

全部时间相关用例使用可拨快的 `MutableClock`（测试中覆盖系统 `Clock` Bean），
**过期与密钥宽限期用例零真实等待**。

- `AccessControlIntegrationTests`：放行、缺凭证、格式错误、篡改签名、权限不足、吊销、未知主体；
- `RefreshRotationTests`：单次轮换与重用整族吊销、20 线程并发恰好一个成功、连续轮换后重放；
- `TokenExpiryTests`：访问/刷新凭证越过过期点的稳定判定（拨快时钟）；
- `KeyRotationTests`：宽限期内并存、宽限期结束稳定拒绝且新凭证不受影响、立即吊销；
- `ApplicationTests`：原有上下文冒烟测试保持通过。

`BusinessLoggingExtension`（JUnit 自动注册，见
`src/test/resources/junit-platform.properties`）在测试日志中输出每个业务模块包含的用例与逐个结果，
并在类结束时给出通过/失败汇总。
