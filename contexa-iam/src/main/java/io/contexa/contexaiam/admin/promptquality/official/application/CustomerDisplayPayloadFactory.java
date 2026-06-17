package io.contexa.contexaiam.admin.promptquality.official.application;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

final class CustomerDisplayPayloadFactory {

    Payload create(Request request) {
        if (request == null) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload request is required.");
        }
        if (request.evidenceDisplays() == null || request.evidenceDisplays().isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload requires evidence.");
        }
        String evidenceText = validateCustomerText(joinEvidence(request.evidenceDisplays()), "evidenceText");
        if (!StringUtils.hasText(evidenceText)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload has no evidence text.");
        }
        return new Payload(
                validateCustomerText(required(request.title(), "title"), "title"),
                evidenceText,
                validateCustomerText(required(request.whyItMatters(), "whyItMatters"), "whyItMatters"),
                validateOptionalCustomerText(request.resolutionAction(), "resolutionAction"),
                validateOptionalCustomerText(request.reverifyCondition(), "reverifyCondition"),
                rolePayloads(request, evidenceText));
    }

    private List<RolePayload> rolePayloads(Request request, String evidenceText) {
        List<RolePayload> rows = new ArrayList<>();
        String title = validateCustomerText(required(request.title(), "title"), "title");
        String whyItMatters = validateCustomerText(required(request.whyItMatters(), "whyItMatters"), "whyItMatters");
        String resolutionAction = validateOptionalCustomerText(request.resolutionAction(), "resolutionAction");
        String reverifyCondition = validateOptionalCustomerText(request.reverifyCondition(), "reverifyCondition");
        rows.add(new RolePayload("TITLE", title, "", "", "", "", ""));
        rows.add(new RolePayload(evidenceRole(request.purposeResult()), "", "", evidenceText, "", "", ""));
        rows.add(new RolePayload("WHY_IT_MATTERS", "", "", "", whyItMatters, "", ""));
        if (StringUtils.hasText(resolutionAction)) {
            rows.add(new RolePayload("RESOLUTION_ACTION", "", "", "", "", resolutionAction, ""));
        }
        if (StringUtils.hasText(reverifyCondition)) {
            rows.add(new RolePayload("REVERIFY_CONDITION", "", "", "", "", "", reverifyCondition));
        }
        return List.copyOf(rows);
    }

    private String evidenceRole(String purposeResult) {
        return "PURPOSE_FAILED".equalsIgnoreCase(safe(purposeResult)) ? "FAIL_EVIDENCE" : "PASS_EVIDENCE";
    }

    private String joinEvidence(List<EvidenceDisplay> displays) {
        StringBuilder result = new StringBuilder();
        List<String> seen = new ArrayList<>();
        for (EvidenceDisplay display : displays) {
            if (display == null || !StringUtils.hasText(display.evidenceValue())) {
                continue;
            }
            String value = display.evidenceValue().trim();
            if (seen.contains(value)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload repeats the same evidence text.");
            }
            seen.add(value);
            if (!result.isEmpty()) {
                result.append(' ');
            }
            result.append(value);
        }
        return result.toString().trim();
    }

    private String required(String value, String fieldName) {
        if (StringUtils.hasText(value)) {
            return value.trim();
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload requires " + fieldName + ".");
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private String validateOptionalCustomerText(String value, String fieldName) {
        String text = safe(value);
        return StringUtils.hasText(text) ? validateCustomerText(text, fieldName) : "";
    }

    private String validateCustomerText(String value, String fieldName) {
        String text = required(value, fieldName);
        if (containsForbiddenCustomerText(text)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload contains raw technical evidence. field="
                    + fieldName);
        }
        return text;
    }

    private boolean containsForbiddenCustomerText(String text) {
        return text.contains("|")
                || text.contains("...")
                || text.contains("{{")
                || text.contains("}}")
                || text.contains("finalUserPrompt.")
                || text.contains("finalSystemPrompt.")
                || text.contains("sealedEvidence.")
                || text.contains("internalGate.")
                || text.contains("truncatedField=")
                || text.contains("truncatedBullet=")
                || text.contains("truncatedNarrative=")
                || text.matches(".*[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*.*");
    }

    record Request(
            String title,
            List<EvidenceDisplay> evidenceDisplays,
            String whyItMatters,
            String resolutionAction,
            String reverifyCondition,
            String purposeResult) {
    }

    record EvidenceDisplay(
            String signalKey,
            String evidenceValue) {
    }

    record Payload(
            String title,
            String evidenceText,
            String whyItMatters,
            String resolutionAction,
            String reverifyCondition,
            List<RolePayload> rolePayloads) {
    }

    record RolePayload(
            String displayRole,
            String title,
            String summary,
            String evidenceText,
            String whyItMatters,
            String resolutionAction,
            String reverifyCondition) {
    }
}
