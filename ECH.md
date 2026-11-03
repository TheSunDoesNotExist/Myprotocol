# ECH: скрытие внутреннего SNI

Режим включается явно: `--ech-config` на клиенте и `--ech-keys` на сервере.
Без этих параметров остаётся прежний прямой TLS/QUIC, где SNI виден.
В режиме ECH оба пути требуют настоящего принятого ECH; автоматического перехода
к открытому SNI, GREASE вместо шифрования или отключения проверки сертификата нет.

## Имена и VPS

Достаточно одного принадлежащего вам домена и одного VPS:

- `relay.example.com` — внутреннее имя сервера, проверяемое клиентом и скрываемое ECH.
- `www.example.com` — публичное имя в наружном ClientHello; оно остаётся видимым.
- `VPS_IP` — фактический IP выбранного VPS, который тоже остаётся видимым.

Это два поддомена вашего домена. Публичное имя не означает использование чужого
сайта/CDN. Сертификат сервера должен содержать оба имени в SAN. Одинаковые публичный
и внутренний SNI отклоняются. Клиент проверяет цепочку CA и внутреннее имя;
при отказе ECH стандартная библиотека также проверяет
сертификат публичного имени, но всё равно завершает попытку без передачи ключа.

Начать можно с VPS в Нидерландах или Хельсинки. Второй VPS сам по себе не переносит
удерживаемые исходящие TCP-сокеты: смена узла выхода требует отдельной архитектуры.
Никакие VPS/DNS-настройки автоматически не изменяются.

## Что находится на проводе

`приложение → внутренний TLS/HTTP CONNECT → ECH TLS/HTTP CONNECT или ECH HTTP/3 → сервер`

Внешний слой — Go `crypto/tls` с ECH и `quic-go` для HTTP/3. Внутри сохраняется
прежний проверенный TLS 1.3 и протокол сессий v5. Между Python и native backend
по loopback передаются TLS-записи: полезная нагрузка зашифрована, но внутренний
ClientHello с именем может быть виден локальной ОС. ОС входит в доверенную модель;
во внешнюю сеть этот ClientHello передаётся внутри ECH-защищённого канала.
Проверки CA/имени и PSK внутреннего
слоя не заменяются утверждениями backend о безопасности канала.

Перед отправкой даже внутреннего ClientHello backend проверяет внешний сертификат,
принятие ECH и ответ аутентифицированного CONNECT. ECH rejection, неправильный ключ,
устаревший/неправильный ECHConfig или остановка backend прекращают канал.
Старое рабочее соединение может продолжить работу; открытого запасного пути нет.

Два слоя TLS добавляют handshake и некоторый расход CPU/байтов. Наружный ClientHello
имеет fingerprint Go, а не браузера; ECH не гарантирует неотличимость от Chrome.
Публичный SNI, IP, факт использования ECH/QUIC, размеры и время пакетов наблюдаемы.
SRTL можно включить отдельно в Python; это не меняет fingerprint внешнего Go backend.
Изменение рисунка проб/heartbeat здесь не добавлено.

## Сборка

Проверено с Go 1.27.3; версии зависимостей и контрольные суммы закреплены
в `native/go.mod` и `native/go.sum`. В этом workspace Windows-бинарник уже собран
в `.local/ech-gateway.exe`, Go установлен только локально в `.local/toolchains/go`.

```powershell
$env:GOPATH = Join-Path (Get-Location) '.local/go-path'
$env:GOCACHE = Join-Path (Get-Location) '.local/go-cache'
.\.local\toolchains\go\bin\go.exe -C native mod download
.\.local\toolchains\go\bin\go.exe -C native test -v ./...
.\.local\toolchains\go\bin\go.exe -C native build -trimpath -o ../.local/ech-gateway.exe .
```

На Linux VPS с установленным Go 1.27.3 или совместимой обновлённой версией:

```bash
mkdir -p .local
go -C native mod download
go -C native test -v ./...
go -C native build -trimpath -o ../.local/ech-gateway .
```

Сборка/регрессии выполнены на Windows; Linux-вариант требует собственного прогона
на выбранном VPS. Бинарник можно задать через `--ech-binary /absolute/path`.
Не включайте ECH с отсутствующим backend: запуск завершится ошибкой.

## Ключи и запуск

Сначала создайте ECH-материал **на сервере** или в другом доверенном месте:

```bash
python ech_gateway.py --public-name www.example.com --out .local/ech
```

`ech-keys.json` содержит **закрытый ECH-ключ**, остаётся только на сервере.
`ech-config.bin` содержит публичный ECHConfigList: передайте клиенту через SSH или
другой доверенный канал, как CA. Генератор отказывается перезаписывать файлы.
Права приватных файлов на Windows зависят от ACL каталога; ограничьте их владельцем.
Закрытые ключи и PSK не передаются аргументами CLI и не пишутся в логи.

С тем же `MYVPN_KEY` в окружении клиента/сервера и сертификатом обоих имён:

```bash
python tunnel.py server --listen 0.0.0.0:443 --target 127.0.0.1:9000 --cert /path/fullchain.pem --cert-key /path/privkey.pem --ech-keys .local/ech/ech-keys.json --log-file .local/server.jsonl
python tunnel.py client --server VPS_IP:443 --server-name relay.example.com --ca /path/trusted-ca.pem --ech-config .local/ech/ech-config.bin --log-file .local/client.jsonl
```

Замените `VPS_IP` реальным IPv4 или `[IPv6]`. В ECH-режиме адреса `--server` и
`--udp-server` обязаны быть IP-литералами: это исключает утечку внутреннего имени
через обычный DNS bootstrap. `--server-name` остаётся DNS-именем сертификата.
Автоматического получения ECHConfig через DNS/DoH и автоматического retry по
конфигу, предложенному сервером, нет: неправильный pinned config завершает попытку.

По умолчанию открываются TCP и UDP на одном номере порта. Они должны быть разрешены
на VPS. Внешний listener принадлежит native backend; Python TLS-listeners привязаны
только к случайным loopback-портам. Эти внутренние порты не надо публиковать.
`--transport tcp`/`udp` клиента и `auto` сохраняются; сервер поддерживает `tcp`/`auto`.
Использование 443 не требует ослабления TLS. Нужные права привязки порта выдаются ОС.

При ротации сервер принимает до четырёх ECH-ключей из JSON-массива. Период перекрытия
со старым ключом нужен до обновления pinned config клиентов. Не удаляйте рабочий
ключ до их обновления. Автоматическое распространение/ротация не реализованы.

## Ресурсы и проверка

Native backend имеет отдельные бюджеты TCP/QUIC: 64 канала, 32 до авторизации,
8 до авторизации с одного IP и абсолютный deadline 5 секунд. QUIC использует Retry,
не принимает 0-RTT и не выдаёт session tickets; qlog/экспорт TLS secrets не включены.
Допускается один CONNECT stream, три служебных stream, заголовки до 8 КиБ.
QUIC receive window фиксирован: 96 КиБ на stream и 256 КиБ суммарно на соединение;
он охватывает reassembly. Это другой backend и другой бюджет, чем прямой aioquic.
Копирование использует ограниченные буферы и блокирующую запись QUIC.
Слоты освобождаются при ошибке handshake, отказе авторизации и закрытии.

EOF управляющего stdin завершает дочерний backend. Python также следит за его
завершением: падение процесса останавливает обслуживаемую работу, не меняя режим.

```bash
go -C native test -v ./...
python -m unittest -v
go -C native run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -show verbose ./...
```

Go-тесты проверяют TCP/HTTP3, захваченный TCP ClientHello, отсутствие передачи
HTTP/ключа при отказе ECH, неправильные ECHConfig/сертификат/PSK.
Python-тесты проверяют полный CLI, сохранение сокета при TCP → UDP → TCP,
остановку backend и UDP ClientHello после снятия публичной QUIC Initial-защиты.
Без собранного native backend ECH-тесты Python явно пропускаются, а не подменяются
проверками обычного TLS. Go-тесты нужно запускать отдельно.

События `ech_backend_started`, `ech_accepted`, `ech_connection_failed`,
`ech_backend_failed` дополняют прежние JSONL-логи. `verified` означает принятое ECH,
проверенный внешний TLS и успешный CONNECT, а не доказательство неразличимости DPI.
В логи не попадают внутреннее имя, заголовки, PSK, ECH private key или payload.

Стандарт: [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html).
API и политика отказа ECH: [Go crypto/tls](https://pkg.go.dev/crypto/tls#Config).
HTTP/3 backend: [quic-go](https://quic-go.net/docs/http3/).
