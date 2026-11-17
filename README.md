# pairwise-saml-assertion

SAML 单点登录一接入多租户，断言校验就出问题：签名只验证了 Assertion 外层，签名包裹后可以把未签名断言塞进去；Audience 和 Recipient 只做字符串包含，跨 SP 的断言能复用；NotOnOrAfter 用本地时间，时钟漂移导致提前失效；InResponseTo 没有和请求 ID 对应，重放请求能过；XML 规范化前后命名空间不一致，签名校验偶发失败。security/saml_assertion.py 是核心，tests/test_saml_assertion.py 15个红。要修的是：防签名包裹；Audience/Recipient 精确；UTC 时间窗口；InResponseTo 绑定；规范化与命名空间。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
