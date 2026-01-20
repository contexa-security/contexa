package io.contexa.contexacore.autonomous.event.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.io.Serial;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Zero Trust 공통 Spring Event
 *
 * AI Native v13.0: 이벤트 기반 Zero Trust 아키텍처
 *
 * 확장성 설계:
 * - category: 핸들러 라우팅용 (열거형 - 안정적)
 * - eventType: 세부 이벤트 타입 (문자열 - 무제한 확장)
 * - payload: 이벤트별 데이터 (Map - 유연한 구조)
 *
 * 사용 예시:
 * - 기존 타입: category=AUTHORIZATION, eventType="WEB"
 * - 확장 타입: category=CUSTOM, eventType="MY_APP_AUDIT_EVENT"
 *
 * 플러그 앤 플레이:
 * - 애플리케이션에서 ZeroTrustEventPublisher만 주입하면 Zero Trust 작동
 * - 새 이벤트 타입 추가 시 공통 모듈 변경 불필요
 *
 * @author contexa
 * @since 4.0.0
 */
@Getter
@JsonIgnoreProperties({"source"})
@JsonDeserialize(builder = ZeroTrustSpringEvent.Builder.class)
public class ZeroTrustSpringEvent extends ApplicationEvent {

    @Serial
    private static final long serialVersionUID = 1L;

    // ========== 편의 상수: 기본 제공 이벤트 타입 ==========

    // Authentication 타입
    public static final String TYPE_AUTHENTICATION_SUCCESS = "SUCCESS";
    public static final String TYPE_AUTHENTICATION_FAILURE = "FAILURE";
    public static final String TYPE_AUTHENTICATION_MFA = "MFA";

    // Authorization 타입
    public static final String TYPE_AUTHORIZATION_WEB = "WEB";
    public static final String TYPE_AUTHORIZATION_METHOD = "METHOD";

    // Session 타입
    public static final String TYPE_SESSION_CREATED = "CREATED";
    public static final String TYPE_SESSION_EXPIRED = "EXPIRED";
    public static final String TYPE_SESSION_INVALIDATED = "INVALIDATED";

    // Threat 타입
    public static final String TYPE_THREAT_DETECTED = "DETECTED";
    public static final String TYPE_THREAT_ANOMALY = "ANOMALY";
    public static final String TYPE_THREAT_BLOCKED = "BLOCKED";

    // ========== 핵심 필드 ==========

    /**
     * 이벤트 카테고리 (핸들러 라우팅용)
     */
    private final ZeroTrustEventCategory category;

    /**
     * 이벤트 타입 (문자열 - 무제한 확장 가능)
     */
    private final String eventType;

    /**
     * 사용자 ID
     */
    private final String userId;

    /**
     * 세션 ID
     */
    private final String sessionId;

    /**
     * 클라이언트 IP
     */
    private final String clientIp;

    /**
     * User-Agent
     */
    private final String userAgent;

    /**
     * 접근 리소스 (URL, 메서드명 등)
     */
    private final String resource;

    /**
     * 이벤트 발생 시간
     * Note: ApplicationEvent.getTimestamp()가 final이므로 eventTimestamp로 명명
     *
     * AI Native v14.2: ISO 문자열 형식으로 일관성 보장
     * - ApplicationConfig ObjectMapper: WRITE_DATES_AS_TIMESTAMPS = false
     * - Producer/Consumer 모두 동일한 ObjectMapper 사용
     * - ISO-8601 형식으로 직렬화/역직렬화 (예: 2024-01-15T19:30:00Z)
     */
    private final Instant eventTimestamp;

    /**
     * 이벤트별 추가 데이터 (유연한 구조)
     */
    private final Map<String, Object> payload;

    // ========== 생성자 (빌더 패턴 사용 권장) ==========

    private ZeroTrustSpringEvent(
            Object source,
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            String resource,
            Instant eventTimestamp,
            Map<String, Object> payload) {
        super(source);
        this.category = category;
        this.eventType = eventType;
        this.userId = userId;
        this.sessionId = sessionId;
        this.clientIp = clientIp;
        this.userAgent = userAgent;
        this.resource = resource;
        this.eventTimestamp = eventTimestamp != null ? eventTimestamp : Instant.now();
        this.payload = payload != null ? Collections.unmodifiableMap(new HashMap<>(payload)) : Collections.emptyMap();
    }

    // ========== 편의 메서드 ==========

    /**
     * 카테고리 + 타입 조합 문자열 반환
     *
     * @return "AUTHORIZATION_WEB", "CUSTOM_MY_EVENT" 등
     */
    public String getFullEventType() {
        return category.name() + "_" + eventType;
    }

    /**
     * 특정 카테고리인지 확인
     */
    public boolean isCategory(ZeroTrustEventCategory target) {
        return category == target;
    }

    /**
     * 특정 이벤트 타입인지 확인
     */
    public boolean isEventType(String target) {
        return eventType != null && eventType.equals(target);
    }

    /**
     * payload에서 값 조회 (타입 캐스팅)
     */
    @SuppressWarnings("unchecked")
    public <T> T getPayloadValue(String key) {
        return (T) payload.get(key);
    }

    /**
     * payload에서 값 조회 (기본값 포함)
     */
    @SuppressWarnings("unchecked")
    public <T> T getPayloadValue(String key, T defaultValue) {
        Object value = payload.get(key);
        return value != null ? (T) value : defaultValue;
    }

    // ========== 빌더 패턴 ==========

    public static Builder builder(Object source) {
        return new Builder(source);
    }

    /**
     * Kafka/Jackson 역직렬화용 빌더
     * dummy source("kafka-deserialization") 사용
     */
    public static Builder builder() {
        return new Builder("kafka-deserialization");
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {
        private Object source = "kafka-deserialization";
        private ZeroTrustEventCategory category;
        private String eventType;
        private String userId;
        private String sessionId;
        private String clientIp;
        private String userAgent;
        private String resource;
        private Instant eventTimestamp;
        private Map<String, Object> payload;

        /**
         * Jackson 역직렬화용 기본 생성자
         */
        public Builder() {
        }

        private Builder(Object source) {
            this.source = source;
        }

        public Builder category(ZeroTrustEventCategory category) {
            this.category = category;
            return this;
        }

        public Builder eventType(String eventType) {
            this.eventType = eventType;
            return this;
        }

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder clientIp(String clientIp) {
            this.clientIp = clientIp;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        public Builder eventTimestamp(Instant eventTimestamp) {
            this.eventTimestamp = eventTimestamp;
            return this;
        }

        public Builder payload(Map<String, Object> payload) {
            this.payload = payload;
            return this;
        }

        /**
         * payload에 단일 항목 추가
         */
        public Builder addPayload(String key, Object value) {
            if (this.payload == null) {
                this.payload = new HashMap<>();
            }
            this.payload.put(key, value);
            return this;
        }

        public ZeroTrustSpringEvent build() {
            if (category == null) {
                throw new IllegalStateException("category is required");
            }
            if (eventType == null || eventType.isBlank()) {
                throw new IllegalStateException("eventType is required");
            }
            return new ZeroTrustSpringEvent(
                    source, category, eventType, userId, sessionId,
                    clientIp, userAgent, resource, eventTimestamp, payload
            );
        }
    }

    @Override
    public String toString() {
        return "ZeroTrustSpringEvent{" +
                "category=" + category +
                ", eventType='" + eventType + '\'' +
                ", userId='" + userId + '\'' +
                ", resource='" + resource + '\'' +
                ", eventTimestamp=" + eventTimestamp +
                '}';
    }
}
