# 板卡适配设计（第 2 步）

> 说明：**当前版本尚未拆分**——所有板卡相关调用仍在 `sbsweb.py` 里直接执行
> （nmcli / amixer / tspi-config / sysfs / AT 口）。本文只描述下一轮重构的
> 适配层设计，不含实现代码。

## 目标

把「读状态 / 执行动作」的系统调用从 Web 逻辑中拆出来，形成可插拔的板卡适配层：
新增一块板子只需要在 `boards/` 下加一个适配文件，不需要改 `core`。

## Board 接口

`core/board.py` 定义 `Board` 协议（`typing.Protocol`），按职责分三类成员：

- 标识：`id`（如 `tspi-1m`）、`name`、`match(compatible) -> bool`；
- 信息类方法（读状态，返回 dict，字段与现在 `collect_status()` 完全一致，
  Web 层照旧渲染）：`screens()`、`fan()`、`wifi()`、`ethernet()`、`modem()`、
  `audio()`、`sd()`、`usb()`、`system()`、`ssh()`；
- 动作类方法（执行，返回 `(ok, message[, data])`，与现在 HTTP 层的返回一致）：
  `switch_screen(fid)`、`fan_set(on)`、`wifi_scan()`、`wifi_connect(ssid, pw)`、
  `volume_set(pct)`、`play_test_tone()`、`record(seconds)`、`play_recording()`、
  `sd_mount()`、`sd_test()`、`ping(iface)`、`emmc_test()`、`ddr_test()`。

方法边界按现有函数 1:1 划分，是为了保证拆分不改变任何已验证行为。

## GenericDebian 兜底

`boards/generic.py` 实现通用 Debian 板卡，只用所有 Debian 都有的工具：
`nmcli`（WiFi / 网口）、`amixer` / ALSA（音频）、sysfs（存储 / USB）、
`systemctl`（SSH）。板卡特有职能（屏幕切换、风扇、4G、音量寄存器曲线）在
兜底实现里返回「不支持」，界面隐藏对应卡片或灰显。

## boards/<id>.py 注册

每块板一个文件（如 `boards/tspi_1m.py`）：继承 `GenericDebian`，只覆盖有专属
实现的方法（屏幕走 `tspi-config`、风扇走 PWM hwmon、4G 走 EC20 AT 口、音量走
RK809 寄存器曲线），文件末尾把实例类放进模块级 `BOARD` 变量即完成注册，
不需要修改任何其他代码。

## 按 compatible 自动识别

服务启动时读 `/proc/device-tree/compatible`（NUL 分隔的兼容标识列表，例如
`rockchip,rk3566-taishanpi-1m`），按注册顺序逐个调用各板卡的 `match()`，
第一个命中的生效；全部未命中或读不到设备树（非 ARM 环境、容器）时落到
`GenericDebian`。

## 明确不做的事

- 不改变任何已验证行为（方法边界、返回字段 1:1）；
- 不引入第三方依赖，仍然只用 Python 3 标准库；
- 入口保留单文件 `sbsweb.py`，适配层落地时再拆包结构。
