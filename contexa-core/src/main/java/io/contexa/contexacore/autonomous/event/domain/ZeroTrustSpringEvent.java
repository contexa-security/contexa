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

@Getter
@JsonIgnoreProperties({"source"})
@JsonDeserialize(builder = ZeroTrustSpringEvent.Builder.class)
public class ZeroTrustSpringEvent extends ApplicationEvent {

    @Serial
    private static final long serialVersionUID = 1L;

    public static final String TYPE_AUTHENTICATION_SUCCESS = "SUCCESS";
    public static final String TYPE_AUTHENTICATION_FAILURE = "FAILURE";
    public static final String TYPE_AUTHENTICATION_MFA = "MFA";

    public static final String TYPE_AUTHORIZATION_WEB = "WEB";
    public static final String TYPE_AUTHORIZATION_METHOD = "METHOD";

    public static final String TYPE_SESSION_CREATED = "CREATED";
    public static final String TYPE_SESSION_EXPIRED = "EXPIRED";
    public static final String TYPE_SESSION_INVALIDATED = "INVALIDATED";

    public static final String TYPE_THREAT_DETECTED = "DETECTED";
    public static final String TYPE_THREAT_ANOMALY = "ANOMALY";
    public static final String TYPE_THREAT_BLOCKED = "BLOCKED";

    private final ZeroTrustEventCategory category;

    private final String eventType;

    private final String userId;

    private final String sessionId;

    private final String clientIp;

    private final String userAgent;

    private final String resource;

    private final Instant eventTimestamp;

    private final Map<String, Object> payload;

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

    public String getFullEventType() {
        return category.name() + "_" + eventType;
    }

    public boolean isCategory(ZeroTrustEventCategory target) {
        return category == target;
    }

    public boolean isEventType(String target) {
        return eventType != null && eventType.equals(target);
    }

    @SuppressWarnings("unchecked")
    public <T> T getPayloadValue(String key) {
        return (T) payload.get(key);
    }

    @SuppressWarnings("unchecked")
    public <T> T getPayloadValue(String key, T defaultValue) {
        Object value = payload.get(key);
        return value != null ? (T) value : defaultValue;
    }

    public static Builder builder(Object source) {
        return new Builder(source);
    }

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
