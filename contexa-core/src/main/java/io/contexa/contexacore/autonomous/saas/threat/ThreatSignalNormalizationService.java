package io.contexa.contexacore.autonomous.saas.threat;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import org.springframework.util.StringUtils;

import java.util.*;

public class ThreatSignalNormalizationService {

    public NormalizedThreatSignal normalize(SecurityEvent event, ProcessingResult result) {
        Map<String, Object> eventMetadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        Map<String, Object> analysisData = result.getAnalysisData() != null ? result.getAnalysisData() : Map.of();
        List<String> behaviorPatterns = extractStringList(analysisData.get("behaviorPatterns"));
        List<String> threatIndicators = normalizeValues(result.getThreatIndicators());
        String requestPath = extractRequestPath(eventMetadata);
        String rawThreatCategory = firstNonBlank(
                extractText(analysisData, "threatCategory"),
                extractText(eventMetadata, "threatCategory"));
        String canonicalThreatClass = resolveCanonicalThreatClass(
                rawThreatCategory,
                behaviorPatterns,
                threatIndicators,
                requestPath,
                result.getAction());
        String targetSurfaceCategory = classifyTargetSurface(requestPath);
        return new NormalizedThreatSignal(
                rawThreatCategory,
                canonicalThreatClass,
                resolveMitreTacticHints(canonicalThreatClass, rawThreatCategory, threatIndicators),
                targetSurfaceCategory,
                resolveSignalTags(canonicalThreatClass, eventMetadata, behaviorPatterns, threatIndicators, targetSurfaceCategory));
    }

    public String classifyTargetSurface(String requestPath) {
        String normalizedPath = normalizeToken(requestPath);
        if (!StringUtils.hasText(normalizedPath)) {
            return "application";
        }
        if (containsText(normalizedPath, "login", "signin", "auth", "oauth", "mfa", "password", "token")) {
            return "authentication";
        }
        if (containsText(normalizedPath, "session", "cookie", "refresh")) {
            return "session";
        }
        if (containsText(normalizedPath, "admin", "role", "permission", "privilege", "policy")) {
            return "administration";
        }
        if (containsText(normalizedPath, "client", "credential", "secret", "apikey", "api_key", "service")) {
            return "credential_management";
        }
        if (containsText(normalizedPath, "audit", "export", "report", "compliance", "invoice", "billing")) {
            return "sensitive_data";
        }
        return "application";
    }

    private String resolveCanonicalThreatClass(
            String rawThreatCategory,
            List<String> behaviorPatterns,
            List<String> threatIndicators,
            String requestPath,
            String decision) {
        String normalizedCategory = normalizeToken(rawThreatCategory);
        if (StringUtils.hasText(normalizedCategory)) {
            if (normalizedCategory.contains("account_takeover")) {
                return "account_takeover";
            }
            if (normalizedCategory.contains("credential")) {
                return "credential_abuse";
            }
            if (normalizedCategory.contains("privilege")) {
                return "privilege_abuse";
            }
            if (normalizedCategory.contains("session")) {
                return "session_hijack";
            }
            if (normalizedCategory.contains("travel")) {
                return "impossible_travel";
            }
            if (normalizedCategory.contains("device")) {
                return "suspicious_device_change";
            }
            return normalizedCategory;
        }

        Set<String> tokens = new LinkedHashSet<>();
        tokens.addAll(normalizeValues(behaviorPatterns));
        tokens.addAll(normalizeValues(threatIndicators));
        String normalizedPath = normalizeToken(requestPath);

        if (containsAny(tokens, "credential", "password", "token", "account", "login", "mfa_bypass")) {
            if (containsAny(tokens, "takeover", "session", "cookie", "token_replay")) {
                return "account_takeover";
            }
            return "credential_abuse";
        }
        if (containsAny(tokens, "impossible_travel", "geo_velocity", "travel")) {
            return "impossible_travel";
        }
        if (containsAny(tokens, "new_device", "browser_fingerprint", "device_change", "device")) {
            return "suspicious_device_change";
        }
        if (containsAny(tokens, "privilege", "role_abuse", "admin_path", "elevation")) {
            return "privilege_abuse";
        }
        if (containsAny(tokens, "session", "cookie", "hijack")) {
            return "session_hijack";
        }
        if (StringUtils.hasText(normalizedPath) && (normalizedPath.contains("login") || normalizedPath.contains("signin"))) {
            return "anomalous_access";
        }
        if (StringUtils.hasText(decision) && decision.toUpperCase(Locale.ROOT).contains("BLOCK")) {
            return "anomalous_access";
        }
        return "unknown_threat";
    }

    private List<String> resolveMitreTacticHints(String canonicalThreatClass, String rawThreatCategory, List<String> threatIndicators) {
        LinkedHashSet<String> tactics = new LinkedHashSet<>();
        String normalizedCategory = normalizeToken(rawThreatCategory);
        if (containsText(normalizedCategory, "credential", "takeover", "session")) {
            tactics.add("Credential Access");
        }
        if (containsText(normalizedCategory, "initial_access", "phishing", "login")) {
            tactics.add("Initial Access");
        }
        if (containsText(normalizedCategory, "privilege", "elevation")) {
            tactics.add("Privilege Escalation");
        }

        switch (canonicalThreatClass) {
            case "account_takeover", "credential_abuse", "anomalous_access", "impossible_travel" -> {
                tactics.add("Initial Access");
                tactics.add("Credential Access");
            }
            case "session_hijack" -> {
                tactics.add("Credential Access");
                tactics.add("Defense Evasion");
            }
            case "privilege_abuse" -> tactics.add("Privilege Escalation");
            default -> {
            }
        }

        for (String indicator : threatIndicators) {
            if (containsText(indicator, "initial_access")) {
                tactics.add("Initial Access");
            }
            if (containsText(indicator, "credential")) {
                tactics.add("Credential Access");
            }
            if (containsText(indicator, "privilege")) {
                tactics.add("Privilege Escalation");
            }
            if (containsText(indicator, "exfiltration")) {
                tactics.add("Exfiltration");
            }
        }
        return List.copyOf(tactics);
    }

    private List<String> resolveSignalTags(
            String canonicalThreatClass,
            Map<String, Object> eventMetadata,
            List<String> behaviorPatterns,
            List<String> threatIndicators,
            String targetSurfaceCategory) {
        LinkedHashSet<String> tags = new LinkedHashSet<>();
        if (StringUtils.hasText(targetSurfaceCategory)) {
            tags.add("surface_" + normalizeToken(targetSurfaceCategory));
        }
        if (extractBoolean(eventMetadata, "isNewDevice")) {
            tags.add("new_device");
        }
        if (extractBoolean(eventMetadata, "isImpossibleTravel")) {
            tags.add("impossible_travel");
            tags.add("geo_velocity");
        }
        if (extractBoolean(eventMetadata, "isSensitiveResource")) {
            tags.add("sensitive_resource");
        }
        int failedLoginAttempts = extractInt(eventMetadata, "failedLoginAttempts");
        if (failedLoginAttempts <= 0) {
            failedLoginAttempts = extractInt(eventMetadata, "auth.failure_count");
        }
        if (failedLoginAttempts >= 3) {
            tags.add("failed_login_burst");
        }
        String userRoles = normalizeToken(extractText(eventMetadata, "userRoles"));
        if (containsText(userRoles, "admin", "privilege", "operator")) {
            tags.add("privileged_flow");
        }

        tags.addAll(normalizeValues(behaviorPatterns));
        tags.addAll(normalizeValues(threatIndicators));

        switch (canonicalThreatClass) {
            case "account_takeover" -> {
                tags.add("credential_reuse");
                tags.add("session_takeover_risk");
            }
            case "credential_abuse" -> tags.add("credential_targeted");
            case "session_hijack" -> tags.add("session_integrity_risk");
            case "privilege_abuse" -> tags.add("privileged_flow");
            case "impossible_travel" -> tags.add("geo_velocity");
            case "suspicious_device_change" -> tags.add("device_reputation_shift");
            default -> {
            }
        }
        return List.copyOf(tags);
    }

    private boolean containsAny(Set<String> tokens, String... values) {
        for (String token : tokens) {
            if (containsText(token, values)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsText(String value, String... fragments) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        for (String fragment : fragments) {
            if (value.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private String extractRequestPath(Map<String, Object> eventMetadata) {
        String direct = extractText(eventMetadata, "requestPath");
        if (StringUtils.hasText(direct)) {
            return direct;
        }
        return extractText(eventMetadata, "requestUri");
    }

    private String extractText(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private boolean extractBoolean(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        return false;
    }

    private int extractInt(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    @SuppressWarnings("unchecked")
    private List<String> extractStringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<String> normalized = new ArrayList<>();
        for (Object item : list) {
            if (item != null && StringUtils.hasText(String.valueOf(item))) {
                normalized.add(String.valueOf(item).trim());
            }
        }
        return List.copyOf(normalized);
    }

    private List<String> normalizeValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> normalized = new ArrayList<>();
        for (String value : values) {
            String token = normalizeToken(value);
            if (StringUtils.hasText(token)) {
                normalized.add(token);
            }
        }
        return List.copyOf(normalized);
    }

    private String normalizeToken(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim()
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_", "")
                .replaceAll("_$", "");
        return normalized.isBlank() ? null : normalized;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    public record NormalizedThreatSignal(
            String rawThreatCategory,
            String canonicalThreatClass,
            List<String> mitreTacticHints,
            String targetSurfaceCategory,
            List<String> signalTags) {
    }
}
