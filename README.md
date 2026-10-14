# Port Scanner

Многопоточный TCP-сканер портов на Go с баннер-граббингом, OS fingerprinting (Linux) и экспортом в JSON, CSV, TEXT.

## Возможности

- **Сканирование портов** — одиночные (`80`), списки (`22,80,443`), диапазоны (`1-1000`), смешанные (`22,80-82`), все порты (`-p -`)
- **Параллельность** — горутина на порт + семафор, лимит через `--threads` (по умолчанию = число CPU)
- **Баннер-граббинг** — чтение с 500ms deadline, HEAD-запрос как fallback
- **OS Fingerprinting** — через `TCP_INFO` (только Linux)
- **Экспорт** — JSON (pretty), CSV (RFC 4180), TEXT
- **Docker** — multi-stage сборка, fingerprinting работает на Windows/macOS через Linux-контейнер

## Сборка

### Локально

	go build -o portscanner .

> **Внимание:** OS fingerprinting работает только на Linux. На Windows/macOS соберётся без него (используется stub).

### Docker (рекомендуется для fingerprinting)

	docker build -t portscanner .
	docker run --rm portscanner -t scanme.nmap.org -p 22,80

## Использование

	# базовый скан
	portscanner -t scanme.nmap.org -p 22,80,443

	# диапазон + JSON в файл
	portscanner -t 192.168.1.1 -p 1-1000 -f json -o result.json

	# все порты, больше потоков
	portscanner -t 10.0.0.1 -p - --threads 100

	# CSV в stdout
	portscanner -t scanme.nmap.org -p 22,80 -f csv

### Флаги

| Флаг | Алиас | По умолчанию | Описание |
|---|---|---|---|
| `-t` | `--target` | `127.0.0.1` | целевой хост |
| `-p` | `--ports` | `22,80,443,8000` | порты: `80`, `22,80`, `1-1000`, `-` (все) |
| `--timeout` | — | `2` | таймаут подключения в секундах |
| `--threads` | — | `0` (auto = NumCPU) | максимальная параллельность |
| `-o` | `--output` | `""` (stdout) | файл для записи результата |
| `-f` | `--format` | `text` | формат: `text`, `json`, `csv` |

> **Отличие от C++-версии:** флаги `-to` и `-th` удалены. Стандартный пакет `flag` не поддерживает двухбуквенные короткие флаги. Используйте `--timeout` и `--threads`.

### Форматы вывода

- **text** — человекочитаемый формат с секциями
- **json** — pretty-printed с отступом в 2 пробела, валидный
- **csv** — RFC 4180, поля с запятыми экранируются кавычками

## Ограничения

- **OS fingerprinting** — только Linux. На Windows/macOS поле `os` будет пустым.
- **Баннеры** — могут не читаться на медленных сетях (deadline 500ms). Это не баг, а природа TCP.
- **IPv4 only** — как в C++-версии.
- **UDP не поддерживается** — только TCP connect scan.
- **TTL не определяется** — `TCP_INFO` не даёт TTL входящего пакета (в C++ был баг: использовался исходящий TTL).

## Структура проекта

	main.go                          # entrypoint
	internal/cli/                    # парсинг аргументов, оркестрация
	internal/scan/                   # модель (Options, Result)
	internal/scan/engine/            # параллельное сканирование
	internal/scan/fingerprint/       # TCP_INFO (Linux) + stub
	internal/scan/classify/          # OS по сигнатурам
	internal/export/                 # json, csv, text

## Разработка

	# тесты
	go test ./...

	# vet + форматирование
	go vet ./...
	gofmt -l .

	# сборка Docker
	docker build -t portscanner .
	docker run --rm portscanner -t scanme.nmap.org -p 22,80 -f json
