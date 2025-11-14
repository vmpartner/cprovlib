# cprovlib

Go-библиотека для работы с КриптоПро CSP через CLI утилиты (cryptcp, certmgr).

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Возможности

- Подпись документов с поддержкой CAdES-BES и CAdES-T
- Присоединенная (attached) и отсоединенная (detached) подпись
- Управление сертификатами (установка, удаление, проверка)
- Автоматический retry при ошибках TSP сервера
- Поддержка нескольких TSP серверов с балансировкой нагрузки
- Thread-safe операции с изолированными временными директориями
- Встроенная поддержка OpenTelemetry трассировки
- Гибкое логирование (поддержка zerolog и других библиотек)

## Требования

- Go 1.25 или выше
- КриптоПро CSP 5.0+
- Установленные утилиты:
  - `/opt/cprocsp/bin/amd64/cryptcp`
  - `/opt/cprocsp/bin/amd64/certmgr`
- Linux (amd64)

## Установка

```bash
go get github.com/vmpartner/cprovlib
```

## Быстрый старт

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/vmpartner/cprovlib"
)

func main() {
    // Создаем клиент КриптоПро
    client := cprovlib.New(
        "uMy",                          // Хранилище сертификатов
        cprovlib.DefaultTSPServers,     // TSP серверы
        1,                              // Тип подписи: 1 = CAdES-T
        nil,                            // Logger (nil = default logger)
        false,                          // skipChainValidation
    )

    ctx := context.Background()

    // Получаем список сертификатов
    certs, err := client.ListCertificates(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(certs)
}
```

## Примеры использования

### Подпись документа (CAdES-BES)

```go
package main

import (
    "context"
    "encoding/base64"
    "fmt"

    "github.com/vmpartner/cprovlib"
)

func main() {
    client := cprovlib.New("uMy", nil, 0, nil, false)

    // Данные для подписи в base64
    data := base64.StdEncoding.EncodeToString([]byte("Hello, World!"))

    // Параметры подписи
    thumbprint := "1234567890abcdef"
    pin := "12345678"

    // CAdES-BES (базовая подпись без временной метки)
    signType := uint(0)
    detached := false // присоединенная подпись

    signature, err := client.SignDocument(
        context.Background(),
        thumbprint,
        pin,
        data,
        &detached,
        &signType,
    )

    if err != nil {
        panic(err)
    }

    fmt.Println("Signature:", signature)
}
```

### Подпись с временной меткой (CAdES-T)

```go
// CAdES-T (подпись с временной меткой)
signType := uint(1)
detached := true // отсоединенная подпись

signature, err := client.SignDocument(
    context.Background(),
    thumbprint,
    pin,
    data,
    &detached,
    &signType,
)
```

### Установка сертификата

```go
// Сертификат в формате PKCS#12 (base64)
certBase64 := "MIIK..." // ваш сертификат
pin := "12345678"

err := client.InstallCertificate(context.Background(), certBase64, pin)
if err != nil {
    panic(err)
}
```

### Проверка наличия сертификата

```go
thumbprint := "1234567890abcdef"

if client.IsCertificateInstalled(context.Background(), thumbprint) {
    fmt.Println("Сертификат установлен")
} else {
    fmt.Println("Сертификат не найден")
}
```

### Удаление сертификата

```go
thumbprint := "1234567890abcdef"

err := client.DeleteCertificate(context.Background(), thumbprint)
if err != nil {
    panic(err)
}
```

### Использование с кастомным логгером (zerolog)

```go
import (
    "github.com/rs/zerolog"
    "github.com/vmpartner/cprovlib"
)

logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
zerologAdapter := cprovlib.NewZerologAdapter(&logger)

client := cprovlib.New("uMy", nil, 1, zerologAdapter, false)
```

## API

### Конструктор

```go
func New(
    store string,              // Хранилище: "uMy", "uCa", "MY", "CA"
    tspServers []string,       // TSP серверы (nil = использовать DefaultTSPServers)
    signType uint,             // Тип подписи по умолчанию: 0 = CAdES-BES, 1 = CAdES-T
    logger Logger,             // Логгер (nil = DefaultLogger)
    skipChainValidation bool,  // Отключить проверку цепочки сертификатов
) *CryptoCLI
```

### Методы

#### SignDocument

Подписывает документ с поддержкой CAdES-BES и CAdES-T.

```go
func (c *CryptoCLI) SignDocument(
    ctx context.Context,
    thumbprint string,    // Отпечаток сертификата
    pin string,           // PIN-код
    dataBase64 string,    // Данные в base64
    attachSignature *bool, // true = attached, false/nil = detached
    signType *uint,       // 0 = CAdES-BES, 1 = CAdES-T, nil = из конфига
) (string, error)       // Возвращает подпись в base64
```

**Особенности:**
- Автоматический retry (до 3 попыток) при HTTP ошибках от TSP сервера
- Timeout: 5 минут на операцию подписи
- Thread-safe: каждый вызов работает в изолированной временной директории

#### InstallCertificate

Устанавливает сертификат из PKCS#12 (base64).

```go
func (c *CryptoCLI) InstallCertificate(
    ctx context.Context,
    certBase64 string,    // Сертификат PKCS#12 в base64
    pin string,           // PIN-код для сертификата
) error
```

#### DeleteCertificate

Удаляет сертификат по отпечатку.

```go
func (c *CryptoCLI) DeleteCertificate(
    ctx context.Context,
    thumbprint string,    // Отпечаток сертификата
) error
```

#### IsCertificateInstalled

Проверяет, установлен ли сертификат.

```go
func (c *CryptoCLI) IsCertificateInstalled(
    ctx context.Context,
    thumbprint string,    // Отпечаток сертификата
) bool
```

#### ListCertificates

Получает список всех сертификатов в хранилище.

```go
func (c *CryptoCLI) ListCertificates(
    ctx context.Context,
) (string, error)        // Возвращает текстовый список
```

## Обработка ошибок

Библиотека предоставляет типизированные ошибки:

```go
var (
    ErrCertificateInstallation = errors.New("ошибка установки сертификата")
    ErrCertificateDeletion     = errors.New("ошибка удаления сертификата")
    ErrSignature               = errors.New("ошибка подписи")
)
```

Пример обработки:

```go
signature, err := client.SignDocument(ctx, thumbprint, pin, data, nil, nil)
if err != nil {
    if errors.Is(err, cprovlib.ErrSignature) {
        // Обработка ошибки подписи
        log.Printf("Ошибка подписи: %v", err)
    }
    return err
}
```

## TSP серверы

По умолчанию используются следующие TSP серверы:

```go
DefaultTSPServers = []string{
    "http://qs.cryptopro.ru/tsp/tsp.srf",
    "http://pki.tax.gov.ru/tsp/tsp.srf",
    "http://tax4.tensor.ru/tsp/tsp.srf",
}
```

При создании клиента можно указать свои серверы:

```go
customTSP := []string{
    "http://your-tsp-server.com/tsp",
}

client := cprovlib.New("uMy", customTSP, 1, nil, false)
```

Библиотека автоматически выбирает случайный сервер из списка для балансировки нагрузки.

## Логирование

Библиотека поддерживает любой логгер, реализующий интерфейс `Logger` (встроенная поддержка `log/slog` и `zerolog`).

## Особенности реализации

### Thread Safety

Каждый вызов `SignDocument` создает уникальную временную директорию, что обеспечивает безопасность при параллельных вызовах.

### Retry механизм

При ошибках HTTP от TSP сервера автоматически выполняется до 3 попыток с экспоненциальной задержкой.

### Context Support

Все методы поддерживают `context.Context` для отмены операций и установки таймаутов.

### OpenTelemetry

Все основные операции трассируются через OpenTelemetry (tracer: `internal/cprovlib`).

## Хранилища сертификатов

Библиотека автоматически форматирует названия хранилищ:

- `"MY"` → `-uMy` (пользовательское хранилище личных сертификатов)
- `"CA"` → `-uCa` (пользовательское хранилище ЦС)
- `"uMy"` → `-uMy` (уже с префиксом)
- `"mMy"` → `-mMy` (машинное хранилище)

## Вклад в проект

Буду рад вашим pull request'ам! Пожалуйста:

1. Создайте issue с описанием проблемы или улучшения
2. Форкните репозиторий
3. Создайте ветку для ваших изменений
4. Отправьте pull request

## Автор

Musin Vitaly ([@vmpartner](https://github.com/vmpartner))