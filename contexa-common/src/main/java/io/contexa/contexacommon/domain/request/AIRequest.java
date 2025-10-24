package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AI 시스템으로의 범용 요청 클래스
 * 제네릭을 활용하여 다양한 도메인 컨텍스트를 타입 안전하게 처리
 *
 * @param <T> 도메인 컨텍스트 타입
 */
@Getter
public class AIRequest<T extends DomainContext> {

    private final String requestId;
    private final LocalDateTime timestamp;
    private final T context;
    private final String promptTemplate;
    private final Map<String, Object> parameters;
    private final RequestPriority priority;
    private final RequestType requestType;
    private DiagnosisType diagnosisType;
    private String organizationId;
    private String tenantId;

    private List<Object> toolProviders = new ArrayList<>();

    private boolean isStreamingRequired = false;
    private int timeoutSeconds = 300;

    public AIRequest(T context, String promptTemplate, String organizationId) {
        this.requestId = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.context = context;
        this.promptTemplate = promptTemplate;
        this.parameters = new ConcurrentHashMap<>();
        this.priority = RequestPriority.NORMAL;
        this.requestType = RequestType.STANDARD;
        this.organizationId = organizationId;
    }

    public AIRequest(T context, String promptTemplate, RequestPriority priority, RequestType requestType) {
        this.requestId = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.context = context;
        this.promptTemplate = promptTemplate;
        this.parameters = new ConcurrentHashMap<>();
        this.priority = priority;
        this.requestType = requestType;
    }

    /**
     * 파라미터를 추가합니다
     * @param key 파라미터 키
     * @param value 파라미터 값
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withParameter(String key, Object value) {
        this.parameters.put(key, value);
        return this;
    }

    /**
     * 스트리밍 모드를 설정합니다
     * @param required 스트리밍 필요 여부
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withStreaming(boolean required) {
        this.isStreamingRequired = required;
        return this;
    }

    /**
     * AI 진단 타입을 설정합니다
     * @param diagnosisType 진단 타입
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withDiagnosisType(DiagnosisType diagnosisType) {
        this.diagnosisType = diagnosisType;
        return this;
    }

    /**
     * 타임아웃을 설정합니다
     * @param seconds 타임아웃 초
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withTimeout(int seconds) {
        this.timeoutSeconds = seconds;
        return this;
    }

    /**
     * 파라미터를 타입 안전하게 조회합니다
     * @param key 파라미터 키
     * @param type 파라미터 타입
     * @return 파라미터 값 (존재하지 않으면 null)
     */
    public <P> P getParameter(String key, Class<P> type) {
        Object value = parameters.get(key);
        return type.isInstance(value) ? (P) value : null;
    }

    public Map<String, Object> getParameters() { return Map.copyOf(parameters); }
    
    // Lombok @Getter가 작동하지 않는 경우를 위한 명시적 getter
    public T getContext() { return context; }
    public String getPromptTemplate() { return promptTemplate; }
    public String getRequestId() { return requestId; }

    /**
     * 조직 ID를 설정합니다
     * @param organizationId 조직 ID
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withOrganizationId(String organizationId) {
        this.organizationId = organizationId;
        return this;
    }

    /**
     * 테넌트 ID를 설정합니다
     * @param tenantId 테넌트 ID
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withTenantId(String tenantId) {
        this.tenantId = tenantId;
        return this;
    }

    /**
     * 도구 제공자를 추가합니다.
     * @param toolProvider 도구 제공자 객체
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withToolProvider(Object toolProvider) {
        this.toolProviders.add(toolProvider);
        return this;
    }

    /**
     * 도구 제공자 목록을 추가합니다.
     * @param toolProviders 도구 제공자 객체 목록
     * @return 체이닝을 위한 현재 객체
     */
    public AIRequest<T> withToolProviders(List<Object> toolProviders) {
        this.toolProviders.addAll(toolProviders);
        return this;
    }

    /**
     * 도구 제공자 목록을 반환합니다.
     * @return 도구 제공자 목록
     */
    public List<Object> getToolProviders() {
        return Collections.unmodifiableList(toolProviders);
    }

    /**
     * 도구 제공자가 있는지 확인합니다.
     * @return 도구 제공자가 있으면 true, 없으면 false
     */
    public boolean hasToolProviders() {
        return !toolProviders.isEmpty();
    }

    /**
     * 요청 우선순위 열거형
     */
    public enum RequestPriority {
        LOW(1), NORMAL(5), HIGH(8), CRITICAL(10);

        private final int level;

        RequestPriority(int level) {
            this.level = level;
        }

        public int getLevel() { return level; }
    }

    /**
     * 요청 타입 열거형
     */
    public enum RequestType {
        STANDARD,           // 표준 요청
        STREAMING,          // 스트리밍 요청
        BATCH,              // 배치 요청
        ANALYSIS,           // 분석 요청
        GENERATION,         // 생성 요청
        VALIDATION          // 검증 요청
    }

    @Override
    public String toString() {
        return String.format("AIRequest{id='%s', operation='%s', domain='%s', priority=%s}",
                requestId, promptTemplate, context.getDomainType(), priority);
    }
} 