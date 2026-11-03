#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if (( EUID != 0 )); then
    printf '\nЗапустите установщик через sudo: sudo bash %q\n\n' "$0" >&2
    exit 1
fi
if [[ ! -r /etc/os-release ]]; then
    printf 'Не удалось определить ОС. Нужен Debian 13.\n' >&2
    exit 1
fi
. /etc/os-release
if [[ ${ID:-} != debian || ${VERSION_ID%%.*} != 13 ]]; then
    printf 'Этот установщик предназначен для Debian 13.\n' >&2
    exit 1
fi
here=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ -f "$here/server/admin.py" ]]; then
    source_root=$here
else
    source_root=$(CDPATH= cd -- "$here/.." && pwd -P)
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf '\nУстановка штатного Python из репозиториев Debian…\n'
    log=/var/log/myownvpn-install.log
    if [[ -L "$log" || -e "$log" && ! -f "$log" ]]; then
        printf 'Небезопасный путь журнала: %s\n' "$log" >&2
        exit 1
    fi
    if [[ -e "$log" && $(stat -c %u -- "$log") != 0 ]]; then
        printf 'Журнал установки должен принадлежать root.\n' >&2
        exit 1
    fi
    touch -- "$log"
    chmod 600 -- "$log"
    if ! DEBIAN_FRONTEND=noninteractive apt-get update >> "$log" 2>&1 ||
       ! DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y python3 ca-certificates >> "$log" 2>&1; then
        printf 'Не удалось подготовить Python. Подробности: %s\n' "$log" >&2
        exit 1
    fi
fi
exec /usr/bin/python3 -I "$source_root/server/admin.py" "$@"
