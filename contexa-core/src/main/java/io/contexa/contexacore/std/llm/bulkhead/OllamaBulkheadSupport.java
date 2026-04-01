package io.contexa.contexacore.std.llm.bulkhead;

import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;
import lombok.extern.slf4j.Slf4j;

import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

@Slf4j
final class OllamaBulkheadSupport {

    private OllamaBulkheadSupport() {
    }

    static <T> T execute(String bulkheadKey,
                         String operationName,
                         String modelName,
                         OllamaBulkheadSettings settings,
                         Callable<T> action) {
        enforceCircuitClosed(bulkheadKey, operationName, modelName, settings);
        Semaphore semaphore = OllamaBulkheadRegistry.getSemaphore(bulkheadKey, settings.maxConcurrent());
        long acquireStart = System.currentTimeMillis();
        try {
            if (!semaphore.tryAcquire(settings.acquireTimeoutMs(), TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("Ollama " + operationName + " bulkhead acquire timed out for model " + modelName);
            }
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Ollama " + operationName + " bulkhead", interruptedException);
        }
        recordAcquireLatency(operationName, System.currentTimeMillis() - acquireStart);

        try {
            int attempt = 0;
            while (true) {
                try {
                    T result = action.call();
                    recordSuccess(bulkheadKey);
                    return result;
                } catch (Exception e) {
                    if (!isRetryableBusy(e)) {
                        recordSuccess(bulkheadKey);
                        throw propagate(e);
                    }
                    if (attempt >= settings.retryAttempts()) {
                        recordBusyFailure(bulkheadKey, operationName, settings);
                        throw propagate(e);
                    }
                    attempt++;
                    recordRetry(operationName);
                    log.warn("[OllamaBulkhead] {} busy for model {}. retry {}/{}", operationName, modelName, attempt, settings.retryAttempts());
                    pauseBeforeRetry(settings.retryDelayMs());
                }
            }
        } finally {
            semaphore.release();
        }
    }

    static boolean tryAcquireForStreaming(String bulkheadKey, String modelName, OllamaBulkheadSettings settings) {
        enforceCircuitClosed(bulkheadKey, "chat", modelName, settings);
        Semaphore semaphore = OllamaBulkheadRegistry.getSemaphore(bulkheadKey, settings.maxConcurrent());
        long acquireStart = System.currentTimeMillis();
        try {
            if (!semaphore.tryAcquire(settings.acquireTimeoutMs(), TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("Ollama stream bulkhead acquire timed out for model " + modelName);
            }
            recordAcquireLatency("chat", System.currentTimeMillis() - acquireStart);
            return true;
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Ollama stream bulkhead", interruptedException);
        }
    }

    static void releaseStreaming(String bulkheadKey, OllamaBulkheadSettings settings) {
        Semaphore semaphore = OllamaBulkheadRegistry.getSemaphore(bulkheadKey, settings.maxConcurrent());
        semaphore.release();
        recordSuccess(bulkheadKey);
    }

    private static void enforceCircuitClosed(String bulkheadKey,
                                             String operationName,
                                             String modelName,
                                             OllamaBulkheadSettings settings) {
        long now = System.currentTimeMillis();
        OllamaBulkheadRegistry.CircuitState circuitState = OllamaBulkheadRegistry.getCircuit(bulkheadKey);
        if (!circuitState.isOpen(now)) {
            return;
        }
        SecurityEventTelemetryContext.put(operationName + "CircuitOpen", true);
        SecurityEventTelemetryContext.put(operationName + "CircuitOpenUntil", circuitState.openUntilEpochMs());
        throw new IllegalStateException("Ollama " + operationName + " circuit open for model " + modelName + " until " + circuitState.openUntilEpochMs());
    }

    private static void recordBusyFailure(String bulkheadKey, String operationName, OllamaBulkheadSettings settings) {
        OllamaBulkheadRegistry.CircuitState circuitState = OllamaBulkheadRegistry.getCircuit(bulkheadKey);
        int consecutiveFailures = circuitState.incrementBusyFailures();
        SecurityEventTelemetryContext.increment(operationName + "BusyFailures");
        if (consecutiveFailures < settings.busyTripThreshold()) {
            return;
        }
        if (settings.circuitOpenMs() <= 0) {
            return;
        }
        long openUntil = System.currentTimeMillis() + settings.circuitOpenMs();
        circuitState.openUntil(openUntil);
        SecurityEventTelemetryContext.put(operationName + "CircuitOpen", true);
        SecurityEventTelemetryContext.put(operationName + "CircuitOpenUntil", openUntil);
        log.warn("[OllamaBulkhead] {} circuit opened for {}ms after {} busy failures", operationName, settings.circuitOpenMs(), consecutiveFailures);
    }

    private static void recordSuccess(String bulkheadKey) {
        OllamaBulkheadRegistry.getCircuit(bulkheadKey).resetBusyFailures();
    }

    private static void pauseBeforeRetry(long retryDelayMs) {
        if (retryDelayMs <= 0) {
            return;
        }
        try {
            TimeUnit.MILLISECONDS.sleep(retryDelayMs);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting to retry Ollama request", interruptedException);
        }
    }

    private static boolean isRetryableBusy(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            String message = current.getMessage();
            if (message != null) {
                String normalized = message.toLowerCase(Locale.ROOT);
                if (normalized.contains("maximum pending requests exceeded")
                        || normalized.contains("service unavailable")
                        || normalized.contains("503")
                        || normalized.contains("too many requests")
                        || normalized.contains("busy")) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

    private static RuntimeException propagate(Exception exception) {
        if (exception instanceof RuntimeException runtimeException) {
            return runtimeException;
        }
        return new IllegalStateException(exception.getMessage(), exception);
    }

    private static void recordAcquireLatency(String operationName, long acquireLatencyMs) {
        if ("embedding".equalsIgnoreCase(operationName)) {
            SecurityEventTelemetryContext.put("embeddingAcquireMs", acquireLatencyMs);
            return;
        }
        SecurityEventTelemetryContext.put("chatAcquireMs", acquireLatencyMs);
    }

    private static void recordRetry(String operationName) {
        if ("embedding".equalsIgnoreCase(operationName)) {
            SecurityEventTelemetryContext.increment("embeddingRetryCount");
            return;
        }
        SecurityEventTelemetryContext.increment("chatRetryCount");
    }
}
