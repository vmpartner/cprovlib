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
    "encoding/base64"
    "fmt"
    "log"

    "github.com/vmpartner/cprovlib"
)

func main() {
    ctx := context.Background()

    // 1. Создаем клиент КриптоПро
    client := cprovlib.New(
        "uMy",                          // Хранилище сертификатов
        cprovlib.DefaultTSPServers,     // TSP серверы
        1,                              // Тип подписи: 1 = CAdES-T
        nil,                            // Logger (nil = default logger)
        false,                          // skipChainValidation
    )

    // 2. Устанавливаем сертификат (PKCS#12 в base64)
    certBase64 := "MIIK..." // ваш сертификат
    pin := "12345678"

    err := client.InstallCertificate(ctx, certBase64, pin)
    if err != nil {
        log.Fatal("Ошибка установки сертификата:", err)
    }

    // 3. Проверяем, что сертификат установлен
    thumbprint := "1234567890abcdef"
    if client.IsCertificateInstalled(ctx, thumbprint) {
        fmt.Println("Сертификат установлен")
    }

    // 4. Подписываем документ (CAdES-T с отсоединенной подписью)
    data := base64.StdEncoding.EncodeToString([]byte("Hello, World!"))
    signType := uint(1)     // CAdES-T
    detached := true        // отсоединенная подпись

    signature, err := client.SignDocument(ctx, thumbprint, pin, data, &detached, &signType)
    if err != nil {
        log.Fatal("Ошибка подписи:", err)
    }
    fmt.Println("Подпись:", signature)

    // 5. Получаем список всех сертификатов
    certs, err := client.ListCertificates(ctx)
    if err != nil {
        log.Fatal("Ошибка получения списка:", err)
    }
    fmt.Println("Сертификаты:", certs)

    // 6. Удаляем сертификат
    err = client.DeleteCertificate(ctx, thumbprint)
    if err != nil {
        log.Fatal("Ошибка удаления:", err)
    }
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
