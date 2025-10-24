package io.contexa.contexaidentity.security.core.config;

import io.contexa.contexaidentity.security.enums.AuthType;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Getter
@Setter
@ToString
public class AuthenticationStepConfig {
    private String stepId; // 고유 식별자 필드
    private boolean isPrimary; // 고유 식별자 필드
    private String type;   // 예: "form", "ott", "passkey"
    private AuthType authType;   // 예: "form", "ott", "passkey"
    private final Map<String, Object> options = new HashMap<>();
    private int order = 0;
    // isRequired getter
    private boolean required = true; // 이 단계가 MFA 플로우에서 필수인지 여부, 기본값 true

    public AuthenticationStepConfig() {}

    public AuthenticationStepConfig(String type, int order) {
        this.type = type;
        this.order = order;
        // stepId는 DSL 빌드 시점에 설정
    }

    // flowName을 받아 stepId를 자동 생성하는 생성자
    public AuthenticationStepConfig(String flowName, String type, int order, boolean isPrimary) {
        this.type = type;
        this.order = order;
        this.isPrimary = isPrimary;
        this.stepId = generateId(flowName, type, order);
        this.authType = AuthType.valueOf(type);
    }

    public void addOption(String key, Object value) {
        this.options.put(key, value);
    }

    public <T> T getOption(String key) {
        return (T) this.options.get(key);
    }

    public static String generateId(String flowName, String factorType, int order) {
        return flowName.toLowerCase() + ":" + factorType.toLowerCase() + ":" + order;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationStepConfig that = (AuthenticationStepConfig) o;
        // stepId가 고유하므로 stepId로 비교하거나, 모든 필드 비교
        return order == that.order &&
                required == that.required &&
                Objects.equals(stepId, that.stepId) &&
                Objects.equals(type, that.type) &&
                Objects.equals(options, that.options);
    }

    @Override
    public int hashCode() {
        return Objects.hash(stepId, type, options, order, required);
    }
}