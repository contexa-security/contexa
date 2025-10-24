package io.contexa.contexacore.std.llm.model;

import org.springframework.ai.chat.model.ChatModel;

import java.util.List;
import java.util.Map;

/**
 * LLM 모델 제공자 인터페이스
 *
 * 각 모델 제공자(Ollama, Anthropic, OpenAI 등)가 구현해야 하는
 * 표준 인터페이스를 정의합니다. 플러그인 방식의 확장을 지원합니다.
 */
public interface ModelProvider {

    /**
     * 제공자 이름 반환
     * 예: ollama, anthropic, openai, huggingface
     *
     * @return 제공자 고유 이름
     */
    String getProviderName();

    /**
     * 제공자 설명 반환
     *
     * @return 제공자에 대한 상세 설명
     */
    String getDescription();

    /**
     * 사용 가능한 모든 모델 목록 반환
     *
     * @return 이 제공자가 제공하는 모든 모델의 디스크립터 목록
     */
    List<ModelDescriptor> getAvailableModels();

    /**
     * 특정 모델의 디스크립터 반환
     *
     * @param modelId 모델 ID
     * @return 모델 디스크립터, 없으면 null
     */
    ModelDescriptor getModelDescriptor(String modelId);

    /**
     * 모델 인스턴스 생성
     *
     * @param descriptor 모델 디스크립터
     * @param config 모델 설정 (선택적)
     * @return ChatModel 인스턴스
     */
    ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config);

    /**
     * 모델 인스턴스 생성 (기본 설정 사용)
     *
     * @param descriptor 모델 디스크립터
     * @return ChatModel 인스턴스
     */
    default ChatModel createModel(ModelDescriptor descriptor) {
        return createModel(descriptor, null);
    }

    /**
     * 모델 ID로 직접 모델 생성
     *
     * @param modelId 모델 ID
     * @param config 모델 설정
     * @return ChatModel 인스턴스
     */
    default ChatModel createModelById(String modelId, Map<String, Object> config) {
        ModelDescriptor descriptor = getModelDescriptor(modelId);
        if (descriptor == null) {
            throw new IllegalArgumentException("Model not found: " + modelId);
        }
        return createModel(descriptor, config);
    }

    /**
     * 특정 모델 타입을 지원하는지 확인
     *
     * @param modelType 모델 타입 (예: chat, embedding, completion)
     * @return 지원 여부
     */
    boolean supportsModelType(String modelType);

    /**
     * 특정 모델 ID를 지원하는지 확인
     *
     * @param modelId 모델 ID
     * @return 지원 여부
     */
    boolean supportsModel(String modelId);

    /**
     * 모델의 건강 상태 확인
     *
     * @param modelId 모델 ID
     * @return 건강 상태
     */
    HealthStatus checkHealth(String modelId);

    /**
     * 제공자 초기화
     * 애플리케이션 시작 시 한 번 호출됨
     *
     * @param config 초기화 설정
     */
    void initialize(Map<String, Object> config);

    /**
     * 제공자 종료
     * 애플리케이션 종료 시 호출됨
     */
    void shutdown();

    /**
     * 제공자가 준비되었는지 확인
     *
     * @return 준비 상태
     */
    boolean isReady();

    /**
     * 모델 새로고침
     * 사용 가능한 모델 목록을 다시 로드
     */
    void refreshModels();

    /**
     * 제공자 우선순위 반환
     * 여러 제공자가 같은 모델을 제공할 때 우선순위 결정
     *
     * @return 우선순위 (낮을수록 높은 우선순위)
     */
    default int getPriority() {
        return 100;
    }

    /**
     * 제공자별 메트릭 반환
     *
     * @return 메트릭 맵
     */
    Map<String, Object> getMetrics();

    /**
     * 건강 상태 정의
     */
    class HealthStatus {
        private final boolean healthy;
        private final String message;
        private final long responseTimeMs;
        private final Map<String, Object> details;

        public HealthStatus(boolean healthy, String message, long responseTimeMs, Map<String, Object> details) {
            this.healthy = healthy;
            this.message = message;
            this.responseTimeMs = responseTimeMs;
            this.details = details;
        }

        public static HealthStatus healthy() {
            return new HealthStatus(true, "Healthy", 0, null);
        }

        public static HealthStatus unhealthy(String message) {
            return new HealthStatus(false, message, -1, null);
        }

        public boolean isHealthy() {
            return healthy;
        }

        public String getMessage() {
            return message;
        }

        public long getResponseTimeMs() {
            return responseTimeMs;
        }

        public Map<String, Object> getDetails() {
            return details;
        }
    }

    /**
     * 모델 타입 상수
     */
    interface ModelType {
        String CHAT = "chat";
        String EMBEDDING = "embedding";
        String COMPLETION = "completion";
        String IMAGE = "image";
        String AUDIO = "audio";
    }
}