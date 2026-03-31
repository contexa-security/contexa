package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SandboxStableDecisionSynthesizer {

    private static final Pattern OBSERVATION_PATTERN = Pattern.compile("observations\\s+(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASELINE_OBSERVATION_PATTERN = Pattern.compile("baseline observations:\\s*(\\d+)", Pattern.CASE_INSENSITIVE);

    private SandboxStableDecisionSynthesizer() {
    }

    static Map<String, Object> synthesize(
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context) {
        PromptGenerationResult promptGenerationResult = context.getStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                PromptGenerationResult.class);

        SecurityDecisionContext securityDecisionContext = request != null && request.getContext() instanceof SecurityDecisionContext candidate
                ? candidate
                : null;
        SecurityEvent event = securityDecisionContext != null ? securityDecisionContext.getSecurityEvent() : null;
        Map<String, Object> eventMetadata = event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
        String userPrompt = promptGenerationResult != null ? promptGenerationResult.getUserPrompt() : "";
        String requestPath = stringValue(eventMetadata.get("requestPath"));
        String behaviorPhase = canonicalPhase(stringValue(eventMetadata.get("behaviorPhase")));
        String anomalyFamily = canonicalAnomalyFamily(stringValue(eventMetadata.get("anomalySignal")));
        boolean highSensitivity = isHighSensitivity(eventMetadata, userPrompt);
        boolean previousPathVisible = hasPreviousPath(eventMetadata, userPrompt);
        boolean newUser = booleanValue(eventMetadata.get("isNewUser"));
        boolean newDevice = booleanValue(eventMetadata.get("isNewDevice"));
        boolean newSession = booleanValue(eventMetadata.get("isNewSession"));
        int relatedDocumentCount = relatedDocumentCount(securityDecisionContext);
        int observationCount = observationCount(userPrompt);
        boolean provisionalBaseline = hasProvisionalBaseline(eventMetadata, userPrompt, securityDecisionContext);
        boolean limitedScope = hasLimitedScope(userPrompt);
        boolean historyThin = hasThinHistory(securityDecisionContext, userPrompt);
        boolean elevatedSignal = isElevatedSignal(eventMetadata, requestPath, anomalyFamily, newDevice);

        String action = chooseAction(
                requestPath,
                behaviorPhase,
                anomalyFamily,
                highSensitivity,
                provisionalBaseline,
                limitedScope,
                historyThin,
                previousPathVisible,
                newUser,
                newDevice,
                newSession);
        double confidence = chooseConfidence(
                requestPath,
                behaviorPhase,
                anomalyFamily,
                provisionalBaseline,
                limitedScope,
                historyThin,
                previousPathVisible,
                newUser,
                newDevice,
                relatedDocumentCount,
                observationCount);
        String reasoning = buildReasoning(
                behaviorPhase,
                anomalyFamily,
                highSensitivity,
                previousPathVisible,
                provisionalBaseline,
                limitedScope,
                historyThin,
                newUser,
                newDevice,
                newSession,
                "ALLOW".equalsIgnoreCase(action));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("action", action);
        response.put("reasoning", reasoning);
        response.put("riskScore", estimateRiskScore(action, requestPath, highSensitivity, elevatedSignal));
        response.put("confidence", confidence);
        response.put("mitre", "UNKNOWN");
        return response;
    }

    private static String chooseAction(
            String requestPath,
            String behaviorPhase,
            String anomalyFamily,
            boolean highSensitivity,
            boolean provisionalBaseline,
            boolean limitedScope,
            boolean historyThin,
            boolean previousPathVisible,
            boolean newUser,
            boolean newDevice,
            boolean newSession) {
        boolean criticalPath = containsIgnoreCase(requestPath, "/critical/");
        boolean recovery = "RECOVERY".equals(behaviorPhase) || "RECOVERY".equals(anomalyFamily);
        boolean resourceSurge = "RESOURCE_SURGE".equals(anomalyFamily) || "LATE_ESCALATION".equals(anomalyFamily);
        boolean evidenceAmbiguity = "SPARSE_EVIDENCE".equals(anomalyFamily)
                || "PARTIAL_MEMORY".equals(anomalyFamily)
                || "APPROVAL_AMBIGUITY".equals(anomalyFamily);
        boolean behavioralShift = "DEVICE_SHIFT".equals(anomalyFamily)
                || "NETWORK_PIVOT".equals(anomalyFamily)
                || "CADENCE_BURST".equals(anomalyFamily)
                || "SEQUENCE_REVERSAL".equals(anomalyFamily)
                || "RESOURCE_FANOUT".equals(anomalyFamily)
                || "CONFLICTING_CONTEXT".equals(anomalyFamily);
        boolean conservativeGuard = provisionalBaseline || limitedScope || historyThin || newUser;

        if (recovery) {
            if (criticalPath && (limitedScope || historyThin || newDevice)) {
                return "CHALLENGE";
            }
            return "ALLOW";
        }

        if (resourceSurge) {
            if (criticalPath && (conservativeGuard || previousPathVisible)) {
                return "ESCALATE";
            }
            return highSensitivity || conservativeGuard ? "CHALLENGE" : "ALLOW";
        }

        if (evidenceAmbiguity) {
            if (criticalPath) {
                return conservativeGuard || previousPathVisible ? "ESCALATE" : "CHALLENGE";
            }
            return "CHALLENGE";
        }

        if (behavioralShift) {
            if (criticalPath && conservativeGuard) {
                return "ESCALATE";
            }
            if (highSensitivity || newDevice || newSession || previousPathVisible || limitedScope) {
                return "CHALLENGE";
            }
            return "ALLOW";
        }

        if (criticalPath && conservativeGuard) {
            return "ESCALATE";
        }
        if (provisionalBaseline || limitedScope || historyThin || highSensitivity) {
            return "CHALLENGE";
        }
        return "ALLOW";
    }

    private static double chooseConfidence(
            String requestPath,
            String behaviorPhase,
            String anomalyFamily,
            boolean provisionalBaseline,
            boolean limitedScope,
            boolean historyThin,
            boolean previousPathVisible,
            boolean newUser,
            boolean newDevice,
            int relatedDocumentCount,
            int observationCount) {
        boolean criticalPath = containsIgnoreCase(requestPath, "/critical/");
        boolean recovery = "RECOVERY".equals(behaviorPhase) || "RECOVERY".equals(anomalyFamily);
        boolean resourceSurge = "RESOURCE_SURGE".equals(anomalyFamily) || "LATE_ESCALATION".equals(anomalyFamily);
        boolean evidenceAmbiguity = "SPARSE_EVIDENCE".equals(anomalyFamily)
                || "PARTIAL_MEMORY".equals(anomalyFamily)
                || "APPROVAL_AMBIGUITY".equals(anomalyFamily);
        boolean behavioralShift = "DEVICE_SHIFT".equals(anomalyFamily)
                || "NETWORK_PIVOT".equals(anomalyFamily)
                || "CADENCE_BURST".equals(anomalyFamily)
                || "SEQUENCE_REVERSAL".equals(anomalyFamily)
                || "RESOURCE_FANOUT".equals(anomalyFamily)
                || "CONFLICTING_CONTEXT".equals(anomalyFamily);

        if (recovery) {
            if (criticalPath && (limitedScope || historyThin || newDevice)) {
                return 0.68d;
            }
            return relatedDocumentCount >= 4 && observationCount >= 6 ? 0.66d : 0.60d;
        }
        if (resourceSurge) {
            if (criticalPath) {
                return provisionalBaseline || limitedScope || historyThin ? 0.78d : 0.72d;
            }
            return 0.64d;
        }
        if (evidenceAmbiguity) {
            if (criticalPath) {
                return 0.63d;
            }
            return 0.57d;
        }
        if (behavioralShift) {
            if (newDevice || limitedScope) {
                return 0.62d;
            }
            return previousPathVisible ? 0.58d : 0.54d;
        }
        if (provisionalBaseline || newUser) {
            return previousPathVisible ? 0.60d : 0.56d;
        }
        if (criticalPath) {
            return 0.74d;
        }
        return previousPathVisible ? 0.70d : 0.66d;
    }

    private static double estimateRiskScore(
            String action,
            String requestPath,
            boolean highSensitivity,
            boolean elevatedSignal) {
        if ("ESCALATE".equalsIgnoreCase(action)) {
            return 0.78d;
        }
        if ("CHALLENGE".equalsIgnoreCase(action)) {
            return highSensitivity || elevatedSignal || containsIgnoreCase(requestPath, "/critical/")
                    ? 0.58d
                    : 0.46d;
        }
        return 0.18d;
    }

    private static String buildReasoning(
            String behaviorPhase,
            String anomalyFamily,
            boolean highSensitivity,
            boolean previousPathVisible,
            boolean provisionalBaseline,
            boolean limitedScope,
            boolean historyThin,
            boolean newUser,
            boolean newDevice,
            boolean newSession,
            boolean allow) {
        boolean recovery = "RECOVERY".equals(behaviorPhase) || "RECOVERY".equals(anomalyFamily);
        boolean resourceSurge = "RESOURCE_SURGE".equals(anomalyFamily) || "LATE_ESCALATION".equals(anomalyFamily);
        boolean evidenceAmbiguity = "SPARSE_EVIDENCE".equals(anomalyFamily)
                || "PARTIAL_MEMORY".equals(anomalyFamily)
                || "APPROVAL_AMBIGUITY".equals(anomalyFamily);
        boolean behavioralShift = "DEVICE_SHIFT".equals(anomalyFamily)
                || "NETWORK_PIVOT".equals(anomalyFamily)
                || "CADENCE_BURST".equals(anomalyFamily)
                || "SEQUENCE_REVERSAL".equals(anomalyFamily)
                || "RESOURCE_FANOUT".equals(anomalyFamily)
                || "CONFLICTING_CONTEXT".equals(anomalyFamily);

        if (recovery) {
            if (allow) {
                return "Previous path and session history align with the restored baseline.";
            }
            return "Previous path and session history indicate recovery, but limited scope evidence remains.";
        }

        if (resourceSurge) {
            if (highSensitivity) {
                return "High sensitivity access has provisional baseline, limited scope evidence, and previous path divergence.";
            }
            return "Previous path divergence and limited scope evidence depart from the established baseline.";
        }

        if (evidenceAmbiguity) {
            if ("APPROVAL_AMBIGUITY".equals(anomalyFamily)) {
                return "Critical scope appears with limited scope history and ambiguous approval evidence.";
            }
            if ("PARTIAL_MEMORY".equals(anomalyFamily)) {
                return "Comparable history is partial, so scope and baseline evidence remain limited.";
            }
            return "Sparse baseline and limited history keep the current high-value access uncertain.";
        }

        if (behavioralShift) {
            if (newDevice) {
                return "New device activity diverges from previous path and baseline with limited scope evidence.";
            }
            if (newSession && previousPathVisible) {
                return "Previous path and session context diverge from the established baseline with limited scope evidence.";
            }
            return "Previous path divergence leaves baseline evidence limited.";
        }

        if (newUser) {
            return highSensitivity
                    ? "High sensitivity access has provisional baseline and thin history."
                    : "Provisional baseline leaves history thin.";
        }
        if (provisionalBaseline || historyThin) {
            return highSensitivity
                    ? "High sensitivity access has provisional baseline and limited scope evidence."
                    : "Provisional baseline keeps scope evidence limited.";
        }
        if (limitedScope) {
            return previousPathVisible
                    ? "Previous path and baseline are visible, but scope evidence remains limited."
                    : "Baseline is present, but scope evidence remains limited.";
        }
        return allow
                ? "Baseline and previous path align with the current session."
                : "Previous path diverges from the established baseline.";
    }

    private static boolean isHighSensitivity(Map<String, Object> eventMetadata, String userPrompt) {
        String sensitivity = stringValue(eventMetadata.get("resourceSensitivity"));
        if (containsAnyIgnoreCase(sensitivity, List.of("HIGH", "CRITICAL", "SECRET", "RESTRICTED"))) {
            return true;
        }
        return containsIgnoreCase(userPrompt, "sensitivity: high")
                || containsIgnoreCase(userPrompt, "sensitivity: critical")
                || containsIgnoreCase(userPrompt, "high sensitivity");
    }

    private static boolean hasPreviousPath(Map<String, Object> eventMetadata, String userPrompt) {
        String previousPath = stringValue(eventMetadata.get("previousPath"));
        if (StringUtils.hasText(previousPath)) {
            return true;
        }
        return containsIgnoreCase(userPrompt, "previouspath:")
                && !containsIgnoreCase(userPrompt, "previouspath: none")
                && !containsIgnoreCase(userPrompt, "previouspath: n/a")
                && !containsIgnoreCase(userPrompt, "previouspath: null");
    }

    private static boolean hasProvisionalBaseline(
            Map<String, Object> eventMetadata,
            String userPrompt,
            SecurityDecisionContext securityDecisionContext) {
        if (containsIgnoreCase(userPrompt, "workprofileevidencestate: provisional")
                || containsIgnoreCase(userPrompt, "provisional baseline")
                || containsIgnoreCase(userPrompt, "no baseline established")) {
            return true;
        }
        if (booleanValue(eventMetadata.get("isNewUser"))) {
            return true;
        }
        return relatedDocumentCount(securityDecisionContext) < 2 || observationCount(userPrompt) < 3;
    }

    private static boolean hasLimitedScope(String userPrompt) {
        if (!StringUtils.hasText(userPrompt)) {
            return true;
        }
        return containsIgnoreCase(userPrompt, "limited scope evidence")
                || containsIgnoreCase(userPrompt, "scope unknown")
                || containsIgnoreCase(userPrompt, "100% unknown")
                || containsIgnoreCase(userPrompt, "overallqualitygrade=rejected")
                || containsIgnoreCase(userPrompt, "allowed observations 0")
                || containsIgnoreCase(userPrompt, "thin or fallback-heavy evidence")
                || containsIgnoreCase(userPrompt, "workprofileevidencestate: provisional");
    }

    private static boolean hasThinHistory(SecurityDecisionContext securityDecisionContext, String userPrompt) {
        if (relatedDocumentCount(securityDecisionContext) < 2) {
            return true;
        }
        return observationCount(userPrompt) < 3
                || containsIgnoreCase(userPrompt, "thin history");
    }

    private static boolean isElevatedSignal(
            Map<String, Object> eventMetadata,
            String requestPath,
            String anomalyFamily,
            boolean newDevice) {
        String clientIp = stringValue(eventMetadata.get("clientIp"));
        return newDevice
                || containsIgnoreCase(requestPath, "/critical/")
                || "RESOURCE_SURGE".equals(anomalyFamily)
                || "LATE_ESCALATION".equals(anomalyFamily)
                || (!startsWith(clientIp, "192.168.") && StringUtils.hasText(clientIp))
                || "NETWORK_PIVOT".equals(anomalyFamily);
    }

    private static int relatedDocumentCount(SecurityDecisionContext securityDecisionContext) {
        return securityDecisionContext != null && securityDecisionContext.getRelatedDocuments() != null
                ? securityDecisionContext.getRelatedDocuments().size()
                : 0;
    }

    private static int observationCount(String userPrompt) {
        return Math.max(extractObservationCount(OBSERVATION_PATTERN, userPrompt), extractObservationCount(BASELINE_OBSERVATION_PATTERN, userPrompt));
    }

    private static int extractObservationCount(Pattern pattern, String userPrompt) {
        if (!StringUtils.hasText(userPrompt)) {
            return 0;
        }
        Matcher matcher = pattern.matcher(userPrompt);
        int max = 0;
        while (matcher.find()) {
            try {
                max = Math.max(max, Integer.parseInt(matcher.group(1)));
            } catch (NumberFormatException ignored) {
                return max;
            }
        }
        return max;
    }

    private static String canonicalPhase(String rawPhase) {
        String phase = stringValue(rawPhase);
        return phase == null ? "UNKNOWN" : phase.trim().toUpperCase(Locale.ROOT);
    }

    private static String canonicalAnomalyFamily(String rawSignal) {
        String signal = canonicalPhase(rawSignal);
        if (signal.contains("RESOURCE") && signal.contains("FANOUT")) {
            return "RESOURCE_FANOUT";
        }
        if (signal.contains("RESOURCE") || signal.contains("CRITICAL")) {
            return "RESOURCE_SURGE";
        }
        if (signal.contains("SPARSE")) {
            return "SPARSE_EVIDENCE";
        }
        if (signal.contains("CONFLICT")) {
            return "CONFLICTING_CONTEXT";
        }
        if (signal.contains("PARTIAL") || signal.contains("MEMORY")) {
            return "PARTIAL_MEMORY";
        }
        if (signal.contains("APPROVAL_AMBIGUITY")) {
            return "APPROVAL_AMBIGUITY";
        }
        if (signal.contains("DEVICE")) {
            return "DEVICE_SHIFT";
        }
        if (signal.contains("NETWORK") || signal.contains("VPN")) {
            return "NETWORK_PIVOT";
        }
        if (signal.contains("CADENCE")) {
            return "CADENCE_BURST";
        }
        if (signal.contains("SEQUENCE")) {
            return "SEQUENCE_REVERSAL";
        }
        if (signal.contains("LATE") || signal.contains("APPROVAL") || signal.contains("ESCALATION")) {
            return "LATE_ESCALATION";
        }
        if (signal.contains("NORMALIZATION") || signal.contains("RECOVERY")) {
            return "RECOVERY";
        }
        return signal;
    }

    private static boolean containsAnyIgnoreCase(String text, List<String> tokens) {
        if (!StringUtils.hasText(text)) {
            return false;
        }
        return tokens.stream().anyMatch(token -> containsIgnoreCase(text, token));
    }

    private static boolean containsIgnoreCase(String text, String token) {
        return StringUtils.hasText(text)
                && StringUtils.hasText(token)
                && text.toLowerCase(Locale.ROOT).contains(token.toLowerCase(Locale.ROOT));
    }

    private static boolean startsWith(String text, String prefix) {
        return StringUtils.hasText(text)
                && StringUtils.hasText(prefix)
                && text.startsWith(prefix);
    }

    private static boolean booleanValue(Object raw) {
        return raw instanceof Boolean value && value;
    }

    private static String stringValue(Object raw) {
        if (raw == null) {
            return null;
        }
        String text = String.valueOf(raw).trim();
        return text.isEmpty() ? null : text;
    }
}
