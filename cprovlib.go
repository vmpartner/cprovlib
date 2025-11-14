package cprovlib

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
)

var (
	ErrCertificateInstallation = errors.New("ошибка установки сертификата")
	ErrCertificateDeletion     = errors.New("ошибка удаления сертификата")
	ErrSignature               = errors.New("ошибка подписи")
	DefaultTSPServers          = []string{
		"http://qs.cryptopro.ru/tsp/tsp.srf",
		"http://pki.tax.gov.ru/tsp/tsp.srf",
		"http://tax4.tensor.ru/tsp/tsp.srf",
	}
)

// CryptoCLI представляет обертку для работы с CLI утилитами КриптоПро
type CryptoCLI struct {
	store               string   // Хранилище сертификатов (например, "uMy")
	tspURL              string   // URL службы временных меток (TSP) - устаревшее, используйте tspServers
	tspServers          []string // Список URL служб временных меток (TSP)
	signType            uint     // Тип подписи: 0 = CAdES-BES, 1 = CAdES-T
	skipChainValidation bool     // Отключить проверку цепочки и отзыва сертификатов (флаги -nochain -norev)
	certmgrPath         string   // Путь к утилите certmgr
	cryptcpPath         string   // Путь к утилите cryptcp
	tmpDir              string   // Временная директория
	logger              Logger   // Логгер для вывода сообщений
}

func New(store string, tspServers []string, signType uint, logger Logger, skipChainValidation bool) *CryptoCLI {
	if logger == nil {
		logger = NewDefaultLogger()
	}

	if len(tspServers) == 0 {
		tspServers = DefaultTSPServers
	}

	return &CryptoCLI{
		store:               store,
		tspURL:              "",
		tspServers:          tspServers,
		signType:            signType,
		skipChainValidation: skipChainValidation,
		certmgrPath:         "/opt/cprocsp/bin/amd64/certmgr",
		cryptcpPath:         "/opt/cprocsp/bin/amd64/cryptcp",
		tmpDir:              "/tmp",
		logger:              logger,
	}
}

// SignDocument подписывает документ через cryptcp с поддержкой CAdES-T и CAdES-BES
// signType: nil или 1 = CAdES-T (с временной меткой), 0 = CAdES-BES (базовая подпись)
func (c *CryptoCLI) SignDocument(ctx context.Context, thumbprint string, pin string, dataBase64 string, attachSignature *bool, signType *uint) (string, error) {

	ctx, span := otel.Tracer("internal/cprovlib").Start(ctx, "SignDocument")
	defer span.End()

	// Декодируем данные из base64
	data, err := base64.StdEncoding.DecodeString(dataBase64)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode: %v", ErrSignature, err)
	}

	// Создаем уникальную временную директорию для изоляции каждого запроса
	// Это предотвращает конфликты при одновременных вызовах
	workDir, err := os.MkdirTemp(c.tmpDir, "cprov_*")
	if err != nil {
		return "", fmt.Errorf("%w: create work directory: %v", ErrSignature, err)
	}
	defer os.RemoveAll(workDir) // Удаляем всю директорию со всеми файлами

	// Создаем файл с данными в изолированной директории
	dataFilePath := workDir + "/data.txt"
	err = os.WriteFile(dataFilePath, data, 0600)
	if err != nil {
		return "", fmt.Errorf("%w: write data file: %v", ErrSignature, err)
	}

	// Определяем тип подписи: attached или detached
	// По умолчанию используем detached (если attachSignature == nil или false)
	isAttached := attachSignature != nil && *attachSignature

	// Формируем аргументы команды
	args := []string{
		"-sign",
		c.formatStoreOption(),
		"-thumbprint", thumbprint,
		"-pin", pin,
	}

	// Добавляем флаги пропуска проверки цепочки и отзыва (если включено)
	if c.skipChainValidation {
		args = append(args, "-nochain") // Не проверять цепочку сертификатов
		args = append(args, "-norev")   // Не проверять отзыв сертификатов (CRL/OCSP)
	}

	// Добавляем флаг attached/detached
	if isAttached {
		args = append(args, "-attached") // Создать присоединенную подпись
	} else {
		args = append(args, "-detached") // Создать отсоединенную подпись
	}

	args = append(args, "-der") // Использовать DER формат (бинарный) вместо BASE64

	// Определяем тип подписи CAdES
	// По умолчанию используем CAdES-T (signType == nil или signType == 1)
	effectiveSignType := c.signType // используем из конфига по умолчанию
	if signType != nil {
		effectiveSignType = *signType // переопределяем переданным значением
	}

	// Добавляем тип подписи CAdES
	var selectedTSP string
	if effectiveSignType == 1 {
		// CAdES-T (с временной меткой)
		selectedTSP = c.getRandomTSPServer()
		if selectedTSP == "" {
			return "", fmt.Errorf("%w: TSP server is required for CAdES-T signature type but none configured", ErrSignature)
		}
		args = append(args, "-cadest")
		args = append(args, "-cadestsa", selectedTSP)
	} else {
		// CAdES-BES (базовая подпись)
		args = append(args, "-cadesbes")
	}

	// Добавляем входной файл и расширение для выходного файла.
	// Используем только имя файла, т.к. cryptcp будет работать в workDir
	// Для attached используем .sig, для detached - .sgn
	fileExt := ".sgn"
	if isAttached {
		fileExt = ".sig"
	}
	args = append(args, "data.txt", "-fext", fileExt)

	c.logger.Debug("cryptcp args", "args", args)

	// Проверяем контекст перед запуском
	if ctx.Err() != nil {
		return "", fmt.Errorf("%w: context cancelled before cryptcp execution: %v", ErrSignature, ctx.Err())
	}

	logFields := []interface{}{
		"thumbprint", thumbprint,
		"workDir", workDir,
		"signType", effectiveSignType,
		"skipChainValidation", c.skipChainValidation,
	}
	if selectedTSP != "" {
		logFields = append(logFields, "tspURL", selectedTSP)
		logFields = append(logFields, "tspServersCount", len(c.tspServers))
	}
	c.logger.Info("cryptcp starting", logFields...)

	// Создаем контекст с таймаутом для операции подписи
	// Для CAdES-T (с TSP) операция может занять много времени
	signCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Retry логика: максимум 3 попытки при ошибках HTTP error от TSP сервера
	const maxAttempts = 3
	var lastErr error
	var stdoutStr, stderrStr string
	var duration time.Duration
	signFile := workDir + "/data.txt" + fileExt

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			c.logger.Warn("retrying signature",
				"attempt", attempt,
				"maxAttempts", maxAttempts,
				"previousError", lastErr)
			// Небольшая задержка между попытками
			time.Sleep(time.Second * time.Duration(attempt-1))
		}

		// Выполняем команду cryptcp с рабочей директорией = изолированная временная директория
		// Это гарантирует, что все файлы (включая промежуточные) создаются в workDir
		cmd := exec.CommandContext(signCtx, c.cryptcpPath, args...)
		cmd.Dir = workDir // устанавливаем рабочую директорию

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		// Засекаем время выполнения
		startTime := time.Now()
		err = cmd.Run()
		duration = time.Since(startTime)

		// Логируем stdout/stderr и результат выполнения
		stdoutStr = stdout.String()
		stderrStr = stderr.String()

		c.logger.Info("cryptcp completed",
			"attempt", attempt,
			"duration", duration.Seconds(),
			"hasError", err != nil,
			"hasStdout", stdoutStr != "",
			"hasStderr", stderrStr != "")

		if stdoutStr != "" || stderrStr != "" {
			c.logger.Debug("cryptcp output",
				"attempt", attempt,
				"stdout", stdoutStr,
				"stderr", stderrStr,
				"duration", duration.Seconds())
		}

		// Проверяем, был ли создан файл подписи
		// Это критично, т.к. cryptcp может вернуть err=nil, но не создать файл
		signFileExists := false
		if _, statErr := os.Stat(signFile); statErr == nil {
			signFileExists = true
		}

		// Проверяем наличие ошибок в выводе cryptcp
		// cryptcp может вернуть код 0, но записать ошибку в stdout
		errorText := strings.ToLower(fmt.Sprintf("%v %s %s", err, stdoutStr, stderrStr))
		hasErrorInOutput := strings.Contains(errorText, "error:")

		// Операция успешна только если:
		// 1. err == nil (команда завершилась без ошибки)
		// 2. файл подписи был создан
		// 3. в выводе нет текста "Error:"
		if err == nil && signFileExists && !hasErrorInOutput {
			c.logger.Info("signature created successfully",
				"attempt", attempt,
				"signFile", signFile)
			break
		}

		// Формируем сообщение об ошибке
		if !signFileExists {
			// Проверяем, какие файлы реально созданы в workDir для диагностики
			dirEntries, _ := os.ReadDir(workDir)
			var filesInDir []string
			for _, entry := range dirEntries {
				filesInDir = append(filesInDir, entry.Name())
			}
			lastErr = fmt.Errorf("signature file not created after %.2fs (expected: %s, workDir: %s, files: %v), stdout: %s, stderr: %s",
				duration.Seconds(), signFile, workDir, filesInDir, stdoutStr, stderrStr)
		} else if hasErrorInOutput {
			lastErr = fmt.Errorf("cryptcp reported error in output after %.2fs, stdout: %s, stderr: %s",
				duration.Seconds(), stdoutStr, stderrStr)
		} else {
			lastErr = fmt.Errorf("cryptcp failed after %.2fs: %v, stdout: %s, stderr: %s",
				duration.Seconds(), err, stdoutStr, stderrStr)
		}

		// Проверяем, содержит ли ошибка "HTTP error" (проблема с TSP сервером)
		isHTTPError := strings.Contains(errorText, "http error")

		// Если это последняя попытка или ошибка не связана с HTTP - прерываем
		if attempt == maxAttempts {
			c.logger.Error("all retry attempts exhausted",
				"attempt", attempt,
				"maxAttempts", maxAttempts,
				"lastError", lastErr)
			break
		}

		if !isHTTPError {
			c.logger.Warn("non-HTTP error detected, stopping retries",
				"attempt", attempt,
				"error", lastErr)
			break
		}

		c.logger.Warn("detected HTTP error from TSP server, will retry",
			"attempt", attempt,
			"maxAttempts", maxAttempts,
			"error", lastErr)
	}

	// Если после всех попыток есть ошибка - возвращаем её
	if lastErr != nil {
		return "", fmt.Errorf("%w: %v", ErrSignature, lastErr)
	}

	// Финальная проверка существования файла подписи (на всякий случай)
	if _, err := os.Stat(signFile); os.IsNotExist(err) {
		dirEntries, _ := os.ReadDir(workDir)
		var filesInDir []string
		for _, entry := range dirEntries {
			filesInDir = append(filesInDir, entry.Name())
		}
		c.logger.Error("signature file not created",
			"file", signFile,
			"workDir", workDir,
			"filesInDir", filesInDir,
			"contextErr", ctx.Err())
		return "", fmt.Errorf("%w: signature file not created (expected: %s, workDir: %s, files: %v)",
			ErrSignature, signFile, workDir, filesInDir)
	}

	// Читаем файл подписи (бинарный DER формат)
	signData, err := os.ReadFile(signFile)
	if err != nil {
		return "", fmt.Errorf("%w: read signature file %s: %v, stdout: %s, stderr: %s",
			ErrSignature, signFile, err, stdoutStr, stderrStr)
	}

	// Кодируем бинарные данные в base64 для передачи
	signBase64 := base64.StdEncoding.EncodeToString(signData)
	//slog.Info("signData", "len", len(signData), "base64Len", len(signBase64))

	return signBase64, nil
}

// getRandomTSPServer возвращает случайный TSP сервер из списка
func (c *CryptoCLI) getRandomTSPServer() string {
	if len(c.tspServers) == 0 {
		return ""
	}
	if len(c.tspServers) == 1 {
		return c.tspServers[0]
	}
	return c.tspServers[rand.Intn(len(c.tspServers))]
}

// formatStoreOption форматирует опцию хранилища для cryptcp
// "MY" -> "-uMy", "CA" -> "-uCa", "uMy" -> "-uMy"
func (c *CryptoCLI) formatStoreOption() string {
	store := c.store

	// Если уже начинается с "u" или "m", возвращаем как есть с минусом
	lowerStore := strings.ToLower(store)
	if strings.HasPrefix(lowerStore, "u") || strings.HasPrefix(lowerStore, "m") {
		return "-" + store
	}

	// Иначе добавляем префикс "u" и форматируем: первая буква заглавная, остальные строчные
	if len(store) > 0 {
		formatted := strings.ToUpper(string(store[0])) + strings.ToLower(store[1:])
		return "-u" + formatted
	}

	return "-u" + store
}

// ListCertificates получает список сертификатов в хранилище
func (c *CryptoCLI) ListCertificates(ctx context.Context) (string, error) {

	ctx, span := otel.Tracer("internal/cprovlib").Start(ctx, "ListCertificates")
	defer span.End()

	cmd := exec.CommandContext(ctx, c.certmgrPath,
		"-list",
		"-store", c.store,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("certmgr list: %v, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// IsCertificateInstalled проверяет, установлен ли сертификат
func (c *CryptoCLI) IsCertificateInstalled(ctx context.Context, thumbprint string) bool {
	output, err := c.ListCertificates(ctx)
	if err != nil {
		return false
	}

	// Проверяем наличие thumbprint в выводе
	return strings.Contains(strings.ToLower(output), strings.ToLower(thumbprint))
}

// InstallCertificate устанавливает сертификат из base64 строки
func (c *CryptoCLI) InstallCertificate(ctx context.Context, certBase64 string, pin string) error {

	ctx, span := otel.Tracer("internal/cprovlib").Start(ctx, "ensureCertificate")
	defer span.End()

	// Декодируем сертификат из base64
	certData, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return fmt.Errorf("%w: base64 decode: %v", ErrCertificateInstallation, err)
	}

	// Создаем уникальный временный файл для сертификата (безопасно для concurrent вызовов)
	certFile, err := os.CreateTemp(c.tmpDir, "cert_*.p12")
	if err != nil {
		return fmt.Errorf("%w: create temp file: %v", ErrCertificateInstallation, err)
	}
	certFilePath := certFile.Name()
	defer os.Remove(certFilePath)

	// Записываем данные и закрываем файл
	_, err = certFile.Write(certData)
	if err != nil {
		certFile.Close()
		return fmt.Errorf("%w: write file: %v", ErrCertificateInstallation, err)
	}
	err = certFile.Close()
	if err != nil {
		return fmt.Errorf("%w: close file: %v", ErrCertificateInstallation, err)
	}

	// Устанавливаем сертификат через certmgr
	cmd := exec.CommandContext(ctx, c.certmgrPath,
		"-install",
		"-pfx",
		"-store", c.store,
		"-file", certFilePath,
		"-pin", pin,
		"-newpin", pin,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("%w: certmgr: %v, stderr: %s", ErrCertificateInstallation, err, stderr.String())
	}

	return nil
}

// DeleteCertificate удаляет сертификат по thumbprint
func (c *CryptoCLI) DeleteCertificate(ctx context.Context, thumbprint string) error {

	ctx, span := otel.Tracer("internal/cprovlib").Start(ctx, "DeleteCertificate")
	defer span.End()

	cmd := exec.CommandContext(ctx, c.certmgrPath,
		"-delete",
		"-store", c.store,
		"-thumbprint", thumbprint,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("%w: certmgr: %v, stderr: %s", ErrCertificateDeletion, err, stderr.String())
	}

	return nil
}
