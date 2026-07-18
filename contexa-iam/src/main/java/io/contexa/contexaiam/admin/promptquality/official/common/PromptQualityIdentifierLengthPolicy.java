package io.contexa.contexaiam.admin.promptquality.official.common;

import org.springframework.util.StringUtils;

public final class PromptQualityIdentifierLengthPolicy {

    public static final int IDENTIFIER_MAX = 256;
    public static final int RESOURCE_ID_MAX = 512;
    public static final int RESOURCE_URL_MAX = 1000;
    public static final int EVIDENCE_REF_MAX = 1000;
    public static final int OPERATOR_TEXT_MAX = 3000;
    public static final int HTTP_METHOD_MAX = 16;

    private PromptQualityIdentifierLengthPolicy() {
    }

    public static String packageId(String value) {
        String normalized = optionalText("packageId", value, IDENTIFIER_MAX);
        if (!StringUtils.hasText(normalized)) {
            throw new PolicyViolationException("enterprise.pqa.validation.packageId.required");
        }
        return normalized;
    }

    public static String identifier(String field, String value) {
        return optionalText(field, value, IDENTIFIER_MAX);
    }

    public static String resourceId(String field, String value) {
        return optionalText(field, value, RESOURCE_ID_MAX);
    }

    public static String resourceUrl(String value) {
        return optionalText("resourceUrl", value, RESOURCE_URL_MAX);
    }

    public static String evidenceRef(String value) {
        return optionalText("evidenceRef", value, EVIDENCE_REF_MAX);
    }

    public static String operatorText(String field, String value) {
        return optionalText(field, value, OPERATOR_TEXT_MAX);
    }

    public static String httpMethod(String value) {
        return optionalText("httpMethod", value, HTTP_METHOD_MAX);
    }

    public static String requireText(String field, String value, int maxLength) {
        String normalized = optionalText(field, value, maxLength);
        if (!StringUtils.hasText(normalized)) {
            throw new PolicyViolationException("enterprise.pqa.validation.text.requiredTpl", field);
        }
        return normalized;
    }

    public static String optionalText(String field, String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > maxLength) {
            throw new PolicyViolationException(
                    "enterprise.pqa.validation.text.maxLengthTpl",
                    field,
                    maxLength,
                    normalized.length());
        }
        return normalized;
    }

    public static String validationMessageKey(IllegalArgumentException exception) {
        return exception instanceof PolicyViolationException violation ? violation.messageKey : null;
    }

    public static Object[] validationMessageArguments(IllegalArgumentException exception) {
        return exception instanceof PolicyViolationException violation
                ? violation.messageArguments.clone()
                : new Object[0];
    }

    private static final class PolicyViolationException extends IllegalArgumentException {

        private final String messageKey;
        private final Object[] messageArguments;

        private PolicyViolationException(String messageKey, Object... messageArguments) {
            super(messageKey);
            this.messageKey = messageKey;
            this.messageArguments = messageArguments == null ? new Object[0] : messageArguments.clone();
        }
    }
}
