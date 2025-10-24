package io.contexa.contexacore.simulation.context;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.CompletableFuture;

/**
 * 시뮬레이션 모드 홀더
 *
 * ThreadLocal을 사용하여 현재 스레드의 시뮬레이션 모드를 저장하고 전파합니다.
 * 이를 통해 보안 체인 전체에서 시뮬레이션 모드를 인식할 수 있습니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
public class SimulationModeHolder {

    /**
     * 시뮬레이션 모드 열거형
     */
    public enum Mode {
        /**
         * 무방비 모드 - 보안 이벤트를 발행하지 않음
         */
        UNPROTECTED,

        /**
         * 방어 모드 - 보안 이벤트를 발행하여 자율보안체제 작동
         */
        PROTECTED,

        /**
         * 일반 모드 - 시뮬레이션이 아닌 정상 운영
         */
        NORMAL
    }

    /**
     * 시뮬레이션 컨텍스트 정보
     */
    public static class SimulationContext {
        private final Mode mode;
        private final String campaignId;
        private final String attackId;
        private final boolean bypassSecurity;

        public SimulationContext(Mode mode, String campaignId, String attackId) {
            this.mode = mode;
            this.campaignId = campaignId;
            this.attackId = attackId;
            this.bypassSecurity = (mode == Mode.UNPROTECTED);
        }

        public Mode getMode() {
            return mode;
        }

        public String getCampaignId() {
            return campaignId;
        }

        public String getAttackId() {
            return attackId;
        }

        public boolean shouldBypassSecurity() {
            return bypassSecurity;
        }

        public boolean isSimulation() {
            return mode != Mode.NORMAL;
        }

        @Override
        public String toString() {
            return String.format("SimulationContext[mode=%s, campaignId=%s, attackId=%s, bypassSecurity=%s]",
                    mode, campaignId, attackId, bypassSecurity);
        }
    }

    private static final ThreadLocal<SimulationContext> contextHolder = new ThreadLocal<>();

    /**
     * 시뮬레이션 컨텍스트 설정
     *
     * @param context 시뮬레이션 컨텍스트
     */
    public static void setContext(SimulationContext context) {
        if (context != null) {
            log.debug("Setting simulation context: {}", context);
            contextHolder.set(context);
        } else {
            log.debug("Clearing simulation context");
            contextHolder.remove();
        }
    }

    /**
     * 시뮬레이션 모드 설정 (간편 메서드)
     *
     * @param mode 시뮬레이션 모드
     * @param campaignId 캠페인 ID
     * @param attackId 공격 ID
     */
    public static void setMode(Mode mode, String campaignId, String attackId) {
        setContext(new SimulationContext(mode, campaignId, attackId));
    }

    /**
     * 현재 시뮬레이션 컨텍스트 조회
     *
     * @return 시뮬레이션 컨텍스트 (없으면 null)
     */
    public static SimulationContext getContext() {
        return contextHolder.get();
    }

    /**
     * 현재 시뮬레이션 모드 조회
     *
     * @return 시뮬레이션 모드 (기본값: NORMAL)
     */
    public static Mode getMode() {
        SimulationContext context = getContext();
        return context != null ? context.getMode() : Mode.NORMAL;
    }

    /**
     * 보안을 우회해야 하는지 확인
     *
     * @return 무방비 모드인 경우 true
     */
    public static boolean shouldBypassSecurity() {
        SimulationContext context = getContext();
        return context != null && context.shouldBypassSecurity();
    }

    /**
     * 시뮬레이션 중인지 확인
     *
     * @return 시뮬레이션 모드인 경우 true
     */
    public static boolean isSimulation() {
        SimulationContext context = getContext();
        return context != null && context.isSimulation();
    }

    /**
     * 무방비 모드인지 확인
     *
     * @return 무방비 모드인 경우 true
     */
    public static boolean isUnprotectedMode() {
        return getMode() == Mode.UNPROTECTED;
    }

    /**
     * 방어 모드인지 확인
     *
     * @return 방어 모드인 경우 true
     */
    public static boolean isProtectedMode() {
        return getMode() == Mode.PROTECTED;
    }

    /**
     * 시뮬레이션 컨텍스트 초기화
     */
    public static void clear() {
        log.debug("Clearing simulation context");
        contextHolder.remove();
    }

    /**
     * 임시로 다른 모드로 실행 (동기)
     *
     * @param temporaryMode 임시 모드
     * @param runnable 실행할 작업
     */
    public static void runWithMode(Mode temporaryMode, Runnable runnable) {
        SimulationContext originalContext = getContext();
        try {
            if (temporaryMode != Mode.NORMAL) {
                setMode(temporaryMode, "temp", "temp");
            } else {
                clear();
            }
            runnable.run();
        } finally {
            if (originalContext != null) {
                setContext(originalContext);
            } else {
                clear();
            }
        }
    }

    /**
     * 비동기 환경에서 시뮬레이션 컨텍스트와 함께 실행
     * ThreadLocal 컨텍스트를 새로운 스레드로 전파
     *
     * @param context 전파할 시뮬레이션 컨텍스트
     * @param runnable 실행할 작업
     * @return CompletableFuture
     */
    public static CompletableFuture<Void> runWithContextAsync(SimulationContext context, Runnable runnable) {
        return CompletableFuture.runAsync(() -> {
            SimulationContext originalContext = getContext();
            try {
                if (context != null) {
                    setContext(context);
                    log.debug("Async context propagated: {}", context);
                } else {
                    clear();
                }
                runnable.run();
            } catch (Exception e) {
                log.error("Error in async simulation execution", e);
                throw e;
            } finally {
                // 비동기 스레드에서는 항상 정리
                clear();
                log.debug("Async context cleared");
            }
        });
    }

    /**
     * 현재 컨텍스트를 비동기 환경으로 전파하여 실행
     *
     * @param runnable 실행할 작업
     * @return CompletableFuture
     */
    public static CompletableFuture<Void> runWithCurrentContextAsync(Runnable runnable) {
        SimulationContext currentContext = getContext();
        return runWithContextAsync(currentContext, runnable);
    }

    /**
     * 여러 비동기 작업을 동일한 컨텍스트로 병렬 실행
     *
     * @param context 전파할 시뮬레이션 컨텍스트
     * @param runnables 실행할 작업들
     * @return CompletableFuture
     */
    public static CompletableFuture<Void> runAllWithContextAsync(SimulationContext context, Runnable... runnables) {
        CompletableFuture<Void>[] futures = new CompletableFuture[runnables.length];

        for (int i = 0; i < runnables.length; i++) {
            futures[i] = runWithContextAsync(context, runnables[i]);
        }

        return CompletableFuture.allOf(futures);
    }

    /**
     * 현재 컨텍스트 정보를 문자열로 반환
     *
     * @return 컨텍스트 정보 문자열
     */
    public static String getContextInfo() {
        SimulationContext context = getContext();
        if (context != null) {
            return context.toString();
        } else {
            return "SimulationContext[mode=NORMAL, no simulation]";
        }
    }

    /**
     * 예외 상황에서 안전한 컨텍스트 복구
     * ThreadLocal 누수를 방지하고 시뮬레이션 상태를 정리합니다.
     *
     * @param exception 발생한 예외
     * @param operationName 실행 중이던 작업명
     */
    public static void handleException(Exception exception, String operationName) {
        try {
            SimulationContext context = getContext();
            if (context != null) {
                log.error("Exception during simulation operation '{}' in context: {}",
                    operationName, context, exception);
            } else {
                log.error("Exception during simulation operation '{}' with no context",
                    operationName, exception);
            }

            // 안전하게 컨텍스트 정리
            clear();
            log.debug("Simulation context cleared after exception in operation: {}", operationName);

        } catch (Exception clearException) {
            // 정리 과정에서도 예외가 발생할 수 있으므로 안전하게 처리
            log.error("Failed to clear simulation context after exception in operation: {}",
                operationName, clearException);

            // ThreadLocal을 강제로 제거
            try {
                contextHolder.remove();
            } catch (Exception forceException) {
                log.error("Failed to force remove ThreadLocal context", forceException);
            }
        }
    }

    /**
     * 시뮬레이션 실행 중 타임아웃 처리
     *
     * @param timeoutMs 타임아웃 시간 (밀리초)
     * @param operationName 실행 중이던 작업명
     */
    public static void handleTimeout(long timeoutMs, String operationName) {
        SimulationContext context = getContext();
        log.warn("Simulation operation '{}' timed out after {}ms in context: {}",
            operationName, timeoutMs, context);

        // 타임아웃 상황에서 컨텍스트 정리
        clear();
        log.debug("Simulation context cleared after timeout in operation: {}", operationName);
    }

    /**
     * 안전한 시뮬레이션 실행 wrapper
     * 예외 발생 시 자동으로 컨텍스트를 정리합니다.
     *
     * @param context 시뮬레이션 컨텍스트
     * @param operation 실행할 작업
     * @param operationName 작업명 (로깅용)
     * @return CompletableFuture
     */
    public static CompletableFuture<Void> runWithSafeContext(SimulationContext context,
                                                           Runnable operation,
                                                           String operationName) {
        return CompletableFuture.runAsync(() -> {
            SimulationContext originalContext = getContext();
            try {
                if (context != null) {
                    setContext(context);
                    log.debug("Safe simulation context set for operation: {} - {}", operationName, context);
                }
                operation.run();
                log.debug("Safe simulation operation completed: {}", operationName);

            } catch (Exception e) {
                handleException(e, operationName);
                throw new RuntimeException("Simulation operation failed: " + operationName, e);

            } finally {
                // 항상 컨텍스트 정리 (비동기 환경)
                clear();
                log.debug("Safe simulation context cleared for operation: {}", operationName);
            }
        });
    }

    /**
     * 모든 시뮬레이션 상태 강제 초기화
     * 심각한 오류 상황에서 사용하는 복구 메소드
     */
    public static void forceReset() {
        try {
            contextHolder.remove();
            log.warn("Forced reset of all simulation contexts completed");
        } catch (Exception e) {
            log.error("Failed to force reset simulation contexts", e);
        }
    }
}