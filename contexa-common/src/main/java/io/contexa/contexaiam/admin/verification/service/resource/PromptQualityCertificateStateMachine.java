package io.contexa.contexaiam.admin.verification.service.resource;

import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.PromptQualityCertificateState;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.ProtectableResourceOperationalState;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class PromptQualityCertificateStateMachine {

    private static final Map<String, Set<String>> CERTIFICATE_TRANSITIONS = Map.of(
            "REVIEW_REQUIRED", Set.of("ISSUED", "BLOCKED", "EXPIRED", "REVOKED"),
            "BLOCKED", Set.of("REVIEW_REQUIRED", "ISSUED", "EXPIRED", "REVOKED"),
            "ISSUED", Set.of("EXPIRED", "REVOKED", "REVIEW_REQUIRED"),
            "EXPIRED", Set.of("REVIEW_REQUIRED", "REVOKED"),
            "REVOKED", Set.of()
    );

    private static final Map<String, Set<String>> RESOURCE_TRANSITIONS = Map.of(
            "DISCOVERED", Set.of("PENDING_VERIFICATION", "RETIRED"),
            "PENDING_VERIFICATION", Set.of("CERTIFIED", "ZERO_TRUST_ENABLED", "BLOCKED", "SUSPENDED", "RETIRED"),
            "CERTIFIED", Set.of("ZERO_TRUST_ENABLED", "BLOCKED", "EXPIRED", "SUSPENDED", "RETIRED"),
            "ZERO_TRUST_ENABLED", Set.of("SUSPENDED", "EXPIRED", "BLOCKED", "RETIRED"),
            "BLOCKED", Set.of("PENDING_VERIFICATION", "SUSPENDED", "RETIRED"),
            "SUSPENDED", Set.of("PENDING_VERIFICATION", "ZERO_TRUST_ENABLED", "RETIRED"),
            "EXPIRED", Set.of("PENDING_VERIFICATION", "RETIRED"),
            "RETIRED", Set.of()
    );

    public void requireCertificateTransition(String previousState, PromptQualityCertificateState nextState) {
        requireTransition("certificate", CERTIFICATE_TRANSITIONS, previousState, nextState.name());
    }

    public void requireResourceTransition(String previousState, ProtectableResourceOperationalState nextState) {
        requireTransition("resource", RESOURCE_TRANSITIONS, previousState, nextState.name());
    }

    public boolean canEnableZeroTrust(String certificateState, String operationalState) {
        return "ISSUED".equals(normalize(certificateState))
                && Set.of("CERTIFIED", "PENDING_VERIFICATION", "SUSPENDED").contains(normalize(operationalState));
    }

    private void requireTransition(
            String domain,
            Map<String, Set<String>> transitions,
            String previousState,
            String nextState
    ) {
        String previous = normalize(previousState);
        String next = normalize(nextState);
        if (previous.equals(next)) {
            return;
        }
        if (!transitions.getOrDefault(previous, Set.of()).contains(next)) {
            throw new IllegalStateException("Invalid " + domain + " state transition: " + previous + " -> " + next);
        }
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "REVIEW_REQUIRED";
    }
}
