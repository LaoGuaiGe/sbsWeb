# 测试

## 合同测试（不需要板子）

```sh
python3 tests/contract_test.py
```

在本机 127.0.0.1:8080 起一个真实的 sbsweb 服务进程，硬件与系统命令全部替换成
假数据，只验证 HTTP 行为合同：

- `GET /login` → 200，页面带一次性 CSRF token；
- 登录缺 CSRF / CSRF 错误 → 400；
- 正确登录 → 302 并下发 HttpOnly + SameSite=Strict 会话 Cookie；
- 登录后 `GET /` → 200（中文界面），`/api/status` → 200 JSON；
- 未登录 `/api/status` → 401；
- 操作 POST 带 `X-Requested-With: fetch` → 返回 JSON 结果，不带 → 302 回跳（无 JS 回退）；
- 没有录音时 `/audio/rec.wav` → 404。

全部通过时输出 `ALL PASS`，退出码 0。CI（`.github/workflows/ci.yml`）在每次
push / PR 时用 Python 3.11 跑 `py_compile` + 本测试。
