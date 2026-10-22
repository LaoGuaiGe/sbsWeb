# sbsWeb

面向 Linux 开发板的本地配置网页：USB 或网线连上即可在浏览器里完成屏幕、风扇、
WiFi、音频、存储与系统诊断。板卡适配可插拔，不绑定具体开发板。

## 特性

- 板端自带，不依赖云端和外部网络
- 只用 Python 3 标准库 + 系统已有的 NetworkManager / systemd / ALSA
- 登录 + CSRF + HttpOnly 会话；默认只监听 USB 网卡，WiFi/网口侧访问不到
- 操作结果统一右下角 toast，表单 fetch 提交，不整页刷新
- 暗色 / 亮色主题，中文界面，手机和电脑浏览器都能用
- 屏幕、风扇、WiFi、4G、音频、SD 卡、系统诊断集中在一个页面

## 支持的板卡

| 板卡 | 状态 | 说明 |
| --- | --- | --- |
| 泰山派 1M（RK3566 / Debian） | 已验证 | 屏幕切换、风扇、RK809 音频、EC20 4G |
| 通用 Debian | 基础 | nmcli / amixer / sysfs / systemctl |

新增板卡只需要在 `boards/` 下加一个适配文件，不需要改 `core`（重构计划见 docs/board-porting.md）。

## 快速开始

```sh
sudo ./packaging/install.sh
# 用 USB 线连电脑，浏览器打开
http://192.168.7.1
```

默认账号为板子的系统用户，首次登录密码见所用镜像的出厂说明，登录后请立即修改。

## 安全

- 仅绑定 USB 网卡地址，其他网络接口访问不到
- 会话 Cookie：HttpOnly + SameSite=Strict，8 小时过期
- 登录失败 5 次锁定 5 分钟
- CSP 限制脚本/样式/媒体来源，页面不加载外部资源

## 开发与测试

```sh
python3 -m py_compile sbsweb.py
python3 tests/contract_test.py   # 本机 127.0.0.1:8080，不需要板子
```

## License

Apache-2.0
