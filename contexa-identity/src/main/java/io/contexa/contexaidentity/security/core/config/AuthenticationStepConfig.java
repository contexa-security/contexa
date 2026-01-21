package io.contexa.contexaidentity.security.core.config;

import io.contexa.contexacommon.enums.AuthType;
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
    private String stepId; 
    private boolean isPrimary; 
    private String type;   
    private AuthType authType;   
    private final Map<String, Object> options = new HashMap<>();
    private int order = 0;
    
    private boolean required = true; 

    public AuthenticationStepConfig() {}

    public AuthenticationStepConfig(String type, int order) {
        this.type = type;
        this.order = order;
        
    }

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