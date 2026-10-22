#!/bin/bash
# sbsWeb 安装脚本：把板载配置网页安装到正在运行的 Debian 系统上。
# 默认安装路径与泰山派 1M 定制 Debian 镜像（v0.4.2 起）完全一致：
#   程序 /usr/local/sbin/tspi-web.py，logo /usr/local/share/tspi-web/logo-small.png，
#   服务 tspi-web.service。代码里 logo 路径写死，默认名不要改；
#   --name 仅为未来重命名预留，行为与默认安装一致。
set -e

NAME="tspi-web"
while [ $# -gt 0 ]; do
  case "$1" in
    --name)
      [ $# -ge 2 ] || { echo "错误：--name 需要一个参数" >&2; exit 1; }
      NAME="$2"; shift 2 ;;
    --name=*)
      NAME="${1#--name=}"; shift ;;
    *)
      echo "用法：sudo ./packaging/install.sh [--name sbsweb]" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：请用 sudo 运行（需要写 /usr/local 与 systemd）" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG_SRC="$SRC_DIR/sbsweb.py"
LOGO_SRC="$SRC_DIR/assets/logo-small.png"
UNIT_SRC="$SRC_DIR/packaging/tspi-web.service"

# logo 路径在代码里写死为 /usr/local/share/tspi-web/logo-small.png，任何服务名下都装到这里
LOGO_DST="/usr/local/share/tspi-web/logo-small.png"
PROG_DST="/usr/local/sbin/${NAME}.py"

echo "安装 sbsWeb（服务名：${NAME}）..."
install -m 0755 "$PROG_SRC" "$PROG_DST"
mkdir -p "$(dirname "$LOGO_DST")"
install -m 0644 "$LOGO_SRC" "$LOGO_DST"

UNIT_DST="/etc/systemd/system/${NAME}.service"
if [ "$NAME" = "tspi-web" ]; then
  install -m 0644 "$UNIT_SRC" "$UNIT_DST"
else
  # 预留命名：仅程序路径与 unit 文件名跟随 NAME，其余与默认一致
  sed "s#^ExecStart=.*#ExecStart=/usr/bin/python3 -u ${PROG_DST}#" "$UNIT_SRC" > "$UNIT_DST"
  chmod 0644 "$UNIT_DST"
fi

systemctl daemon-reload
systemctl enable --now "${NAME}.service"
# 重装/升级时服务已在运行：重启以加载新程序
systemctl restart "${NAME}.service"
echo "完成。用 USB 线连电脑后，浏览器打开 http://192.168.7.1"
