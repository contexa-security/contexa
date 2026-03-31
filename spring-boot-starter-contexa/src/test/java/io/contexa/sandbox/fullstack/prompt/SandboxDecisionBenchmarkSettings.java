package io.contexa.sandbox.fullstack.prompt;

public final class SandboxDecisionBenchmarkSettings {

    private static final String REAL_LLM_FLAG = "sandbox.decision.real-llm";
    private static final String PINNED_MODEL_ID = "sandbox.decision.model-id";
    private static final String ROUND_COUNT = "sandbox.decision.rounds";
    private static final String SAMPLE_COUNT = "sandbox.decision.samples";
    private static final String SCENARIO_SELECTOR = "sandbox.decision.scenarios";
    private static final String TEMPERATURE = "sandbox.decision.temperature";
    private static final String RAG_TIMEOUT_MS = "sandbox.decision.rag-timeout.ms";
    private static final String STORE_TIMEOUT_MS = "sandbox.decision.store-timeout.ms";
    private static final String SEARCH_TIMEOUT_MS = "sandbox.decision.search-timeout.ms";
    private static final String TRACE_TIMEOUT_SECONDS = "sandbox.decision.trace-timeout.seconds";
    private static final String DECISION_APPLICATION_WAIT_MS = "sandbox.decision.application-wait.ms";
    private static final String LLM_EXECUTOR_CORE_POOL_SIZE = "sandbox.decision.llm-executor.core-pool-size";
    private static final String LLM_EXECUTOR_MAX_POOL_SIZE = "sandbox.decision.llm-executor.max-pool-size";
    private static final String LLM_EXECUTOR_QUEUE_CAPACITY = "sandbox.decision.llm-executor.queue-capacity";
    private static final String OUTPUT_MAX_TOKENS = "sandbox.decision.max-output-tokens";
    private static final String LLM_TIMEOUT_SECONDS = "sandbox.decision.llm-timeout.seconds";
    private static final String GOLD_VERSION = "2026.03.31-d1.0";
    private static final String ADJUDICATION_VERSION = "2026.03.31-a1.0";

    private SandboxDecisionBenchmarkSettings() {
    }

    public static boolean useRealLlm() {
        return Boolean.getBoolean(REAL_LLM_FLAG);
    }

    public static String boundaryMode() {
        return useRealLlm() ? "REAL_LLM" : "STABLE_MOCK";
    }

    public static String pinnedModelId() {
        String configured = System.getProperty(PINNED_MODEL_ID);
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        return useRealLlm() ? "qwen3:8b" : "SANDBOX_STABLE";
    }

    public static int roundCount() {
        return Math.max(3, Integer.getInteger(ROUND_COUNT, 12));
    }

    public static int sampleCount() {
        return Math.max(1, Integer.getInteger(SAMPLE_COUNT, 1));
    }

    public static String scenarioSelector() {
        String configured = System.getProperty(SCENARIO_SELECTOR);
        return configured != null && !configured.isBlank() ? configured.trim() : "DECISION_AMBIGUITY";
    }

    public static double temperature() {
        String configured = System.getProperty(TEMPERATURE);
        if (configured == null || configured.isBlank()) {
            return 0.0d;
        }
        try {
            return Double.parseDouble(configured.trim());
        } catch (NumberFormatException ignored) {
            return 0.0d;
        }
    }

    public static long ragTimeoutMs() {
        return Math.max(5000L, Long.getLong(RAG_TIMEOUT_MS, 20000L));
    }

    public static long searchTimeoutMs() {
        return Math.max(5000L, Long.getLong(SEARCH_TIMEOUT_MS, ragTimeoutMs()));
    }

    public static long storeTimeoutMs() {
        return Math.max(5000L, Long.getLong(STORE_TIMEOUT_MS, ragTimeoutMs()));
    }

    public static int traceTimeoutSeconds() {
        return Math.max(90, Integer.getInteger(TRACE_TIMEOUT_SECONDS, 180));
    }

    public static long decisionApplicationWaitMs() {
        return Math.max(500L, Long.getLong(DECISION_APPLICATION_WAIT_MS, 5000L));
    }

    public static int llmExecutorCorePoolSize() {
        return Math.max(1, Integer.getInteger(LLM_EXECUTOR_CORE_POOL_SIZE, 1));
    }

    public static int llmExecutorMaxPoolSize() {
        return Math.max(llmExecutorCorePoolSize(), Integer.getInteger(LLM_EXECUTOR_MAX_POOL_SIZE, 1));
    }

    public static int llmExecutorQueueCapacity() {
        return Math.max(1, Integer.getInteger(LLM_EXECUTOR_QUEUE_CAPACITY, 32));
    }

    public static int maxOutputTokens() {
        return Math.max(32, Integer.getInteger(OUTPUT_MAX_TOKENS, 96));
    }

    public static int llmTimeoutSeconds() {
        return Math.max(15, Integer.getInteger(LLM_TIMEOUT_SECONDS, 45));
    }

    public static String goldVersion() {
        return GOLD_VERSION;
    }

    public static String adjudicationVersion() {
        return ADJUDICATION_VERSION;
    }

    public static boolean enforceOfficialThresholds() {
        return useRealLlm();
    }
}
