package io.contexa.contexaiam.admin.verification.service.quality.runtime;

import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

public enum PromptRuntimeGovernanceScopeType {

    RESOURCE_ID(10),
    RESOURCE_URL_METHOD(20),
    METRIC_CHECK(30),
    RESOURCE_TYPE(40),
    ACTION_FAMILY(50),
    SENSITIVITY(60),
    TENANT(70),
    GLOBAL(80);

    private final int priority;

    PromptRuntimeGovernanceScopeType(int priority) {
        this.priority = priority;
    }

    public int priority() {
        return priority;
    }

    public static PromptRuntimeGovernanceScopeType from(String value) {
        if (!StringUtils.hasText(value)) {
            return GLOBAL;
        }
        return valueOf(value.trim().toUpperCase(Locale.ROOT));
    }

    public static boolean isSupported(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        try {
            from(value);
            return true;
        }
        catch (IllegalArgumentException exception) {
            return false;
        }
    }

    public static Set<String> supportedTypes() {
        return Arrays.stream(values())
                .map(Enum::name)
                .collect(Collectors.toUnmodifiableSet());
    }
}
