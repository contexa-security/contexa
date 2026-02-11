package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Builds security analysis prompts for Zero Trust AI evaluation.
 * <p>
 * Constructs structured prompts with sections for event data, behavioral patterns,
 * network context, and decision instructions. Each section is built by a dedicated
 * method for maintainability and clarity.
 * </p>
 */
@Slf4j
public class SecurityPromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;

    public SecurityPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null ? tieredStrategyProperties : new TieredStrategyProperties();
    }

    /**
     * Builds the complete security analysis prompt by assembling all sections.
     *
     * @param event the security event to analyze
     * @param sessionContext the current session context
     * @param behaviorAnalysis the behavioral analysis data
     * @param relatedDocuments the RAG-retrieved related documents
     * @return the complete prompt string
     */
    public String buildPrompt(SecurityEvent event,
                              SessionContext sessionContext,
                              BehaviorAnalysis behaviorAnalysis,
                              List<Document> relatedDocuments) {

        String userId = extractUserId(sessionContext);
        String baselineContext = extractBaselineContext(behaviorAnalysis);
        BaselineStatus baselineStatus = determineBaselineStatus(behaviorAnalysis, baselineContext);

        DetectedPatterns patterns = collectDetectedPatterns(relatedDocuments, userId);
        enrichPatternsFromBaseline(patterns, behaviorAnalysis);

        StringBuilder prompt = new StringBuilder();
        prompt.append(buildSystemInstruction());
        prompt.append(buildEventSection(event, userId));
        prompt.append(buildCurrentRequestSection(event));
        prompt.append(buildKnownPatternsSection(patterns));
        prompt.append(buildSignalComparisonSection());
        prompt.append(buildNetworkPromptSection(event));
        appendIfPresent(prompt, buildPayloadSection(event));
        prompt.append(buildSessionSection(sessionContext, event, behaviorAnalysis, baselineStatus));
        appendIfPresent(prompt, buildSessionDeviceChangeSection(behaviorAnalysis));
        prompt.append(buildBehaviorSection(behaviorAnalysis));
        prompt.append(buildRelatedContextSection(patterns));
        appendIfPresent(prompt, buildNewUserBaselineSection(baselineStatus));
        prompt.append(buildDecisionSection());

        return prompt.toString();
    }

    private String extractUserId(SessionContext sessionContext) {
        return (sessionContext != null) ? sessionContext.getUserId() : null;
    }

    private String extractBaselineContext(BehaviorAnalysis behaviorAnalysis) {
        return (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
    }

    private String buildSystemInstruction() {
        return """
                You are a Zero Trust security analyst AI.
                Analyze the security context and respond with ONLY a JSON object.
                No explanation, no markdown.

                """;
    }

    private String buildEventSection(SecurityEvent event, String userId) {
        StringBuilder section = new StringBuilder();
        section.append("=== EVENT ===\n");

        if (isValidData(event.getEventId())) {
            section.append("EventId: ").append(PromptTemplateUtils.sanitizeUserInput(event.getEventId())).append("\n");
        }
        if (event.getTimestamp() != null) {
            section.append("Timestamp: ").append(event.getTimestamp()).append("\n");
            section.append("CurrentHour: ").append(event.getTimestamp().getHour()).append("\n");
        }
        if (userId != null) {
            section.append("User: ").append(PromptTemplateUtils.sanitizeUserInput(userId)).append("\n");
        }

        Map<String, Object> metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            Object httpMethod = metadataObj.get("httpMethod");
            if (httpMethod != null && !httpMethod.toString().isEmpty()) {
                section.append("HttpMethod: ").append(httpMethod).append("\n");
            }
            appendMetadataIfPresent(section, metadataObj, "auth.failure_count", "FailureCount");
        }

        String eventPath = extractRequestPath(event);
        if (eventPath != null && !eventPath.isEmpty()) {
            section.append("Path: ").append(PromptTemplateUtils.sanitizeUserInput(eventPath)).append("\n");
        }

        return section.toString();
    }

    private String buildCurrentRequestSection(SecurityEvent event) {
        String currentOS = extractOSFromUserAgent(event.getUserAgent());
        String currentIP = normalizeIP(event.getSourceIp());
        String currentHour = event.getTimestamp() != null
                ? String.valueOf(event.getTimestamp().getHour())
                : null;
        String currentUA = extractUASignature(event.getUserAgent());

        StringBuilder section = new StringBuilder();
        section.append("\n=== CURRENT REQUEST ===\n");
        section.append("OS: ").append(currentOS != null ? currentOS : "N/A").append("\n");
        section.append("IP: ").append(currentIP != null ? currentIP : "N/A").append("\n");
        section.append("Hour: ").append(currentHour != null ? currentHour : "N/A").append("\n");
        section.append("UA: ").append(currentUA != null ? currentUA : "N/A").append("\n");

        return section.toString();
    }

    private String buildKnownPatternsSection(DetectedPatterns patterns) {
        String knownOSStr = !patterns.osSet.isEmpty() ? String.join(", ", patterns.osSet) : "N/A";
        String knownIPStr = !patterns.ipSet.isEmpty() ? String.join(", ", normalizeIPSet(patterns.ipSet)) : "N/A";
        String knownHourStr = !patterns.hourSet.isEmpty() ? String.join(", ", patterns.hourSet) : "N/A";
        String knownUAStr = !patterns.uaSet.isEmpty() ? String.join(", ", patterns.uaSet) : "N/A";
        String knownPathStr = !patterns.pathSet.isEmpty() ? String.join(", ", patterns.pathSet) : "N/A";

        StringBuilder section = new StringBuilder();
        section.append("\n=== KNOWN PATTERNS ===\n");
        section.append("OS: [").append(knownOSStr).append("]\n");
        section.append("IP: [").append(knownIPStr).append("]\n");
        section.append("Hour: [").append(knownHourStr).append("]\n");
        section.append("UA: [").append(knownUAStr).append("]\n");
        section.append("Path: [").append(knownPathStr).append("]\n");

        return section.toString();
    }

    private String buildSignalComparisonSection() {
        StringBuilder section = new StringBuilder();
        section.append("\n=== SIGNAL COMPARISON ===\n");
        section.append("For OS, IP, Hour, UA - check if CURRENT value exists in KNOWN list:\n");
        section.append("- IN list = MATCH (established pattern)\n");
        section.append("- NOT in list = MISMATCH (new/unusual)\n");
        section.append("Example: CURRENT 'Android' in KNOWN [Windows, Android] = MATCH\n");
        section.append("Signal context (each mismatch is significant, not minor):\n");
        section.append("- IP mismatch: New network location (security-sensitive)\n");
        section.append("- OS mismatch: New device type (potential account compromise)\n");
        section.append("- Hour mismatch: Unusual access time (behavior anomaly)\n");
        section.append("- UA mismatch: New browser/client (credential sharing risk)\n");
        section.append("Risk assessment by mismatch count:\n");
        section.append("- 0 = All patterns match (low risk)\n");
        section.append("- 1 = Single deviation (evaluate context)\n");
        section.append("- 2+ = Multiple deviations (elevated risk)\n");

        return section.toString();
    }

    private String buildNetworkPromptSection(SecurityEvent event) {
        String networkDetails = buildNetworkDetails(event);

        StringBuilder section = new StringBuilder();
        section.append("\n=== NETWORK ===\n");
        section.append(networkDetails).append("\n");

        return section.toString();
    }

    private String buildPayloadSection(SecurityEvent event) {
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);
        Optional<String> payloadSummary = summarizePayload(decodedPayload.orElse(null));

        if (payloadSummary.isEmpty()) {
            return null;
        }

        return "\n=== PAYLOAD ===\n" + payloadSummary.get() + "\n";
    }

    private String buildSessionSection(SessionContext sessionContext, SecurityEvent event,
                                       BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== SESSION ===\n");

        if (sessionContext == null) {
            section.append("Session context not available (see DATA AVAILABILITY)\n");
            return section.toString();
        }

        Integer sessionAge = sessionContext.getSessionAgeMinutes();
        if (sessionAge != null) {
            section.append("SessionAge: ").append(sessionAge).append(" minutes\n");
        }

        Integer requestCount = sessionContext.getRequestCount();
        if (requestCount != null && requestCount > 0) {
            section.append("RequestCount: ").append(requestCount).append("\n");
        }

        String authMethod = sessionContext.getAuthMethod();
        if (authMethod != null && !authMethod.isEmpty()) {
            String sanitizedAuthMethod = PromptTemplateUtils.sanitizeUserInput(authMethod);
            section.append("AuthMethod: ").append(sanitizedAuthMethod).append("\n");
        }

        appendZeroTrustSignals(section, event, behaviorAnalysis, baselineStatus);

        return section.toString();
    }

    private String buildSessionDeviceChangeSection(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return null;
        }

        String previousOS = behaviorAnalysis.getPreviousUserAgentOS();
        String currentOS = behaviorAnalysis.getCurrentUserAgentOS();

        if (previousOS == null || currentOS == null || previousOS.equals(currentOS)) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== SESSION DEVICE CHANGE ===\n");
        section.append("OBSERVATION: Same SessionId with different device fingerprint detected.\n");
        section.append("Previous OS: ").append(previousOS).append("\n");
        section.append("Current OS: ").append(currentOS).append("\n");
        section.append("OS Transition: ").append(previousOS).append(" -> ").append(currentOS).append("\n");

        return section.toString();
    }

    private String buildBehaviorSection(BehaviorAnalysis behaviorAnalysis) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== BEHAVIOR ===\n");

        if (behaviorAnalysis == null) {
            section.append("Behavior analysis not available (see DATA AVAILABILITY)\n");
            return section.toString();
        }

        List<String> similarEvents = behaviorAnalysis.getSimilarEvents();
        if (similarEvents == null || similarEvents.isEmpty()) {
            section.append("No similar events in history (see DATA AVAILABILITY)\n");
            return section.toString();
        }

        int maxSimilarEvents = tieredStrategyProperties.getLayer1().getPrompt().getMaxSimilarEvents();
        int maxEvents = Math.min(maxSimilarEvents, similarEvents.size());
        section.append("SimilarEvents Detail:\n");
        for (int i = 0; i < maxEvents; i++) {
            String sanitizedEvent = PromptTemplateUtils.sanitizeUserInput(similarEvents.get(i));
            section.append("  ").append(i + 1).append(". ").append(sanitizedEvent).append("\n");
        }

        return section.toString();
    }

    private String buildRelatedContextSection(DetectedPatterns patterns) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== RELATED CONTEXT ===\n");
        section.append("Historical events for this user:\n\n");

        if (patterns.hasRelatedDocs) {
            String sanitizedContext = PromptTemplateUtils.sanitizeUserInput(patterns.relatedContext);
            section.append(sanitizedContext).append("\n");
        } else {
            section.append("No related context found (see DATA AVAILABILITY)\n");
        }

        return section.toString();
    }

    private String buildNewUserBaselineSection(BaselineStatus baselineStatus) {
        if (baselineStatus != BaselineStatus.NEW_USER) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== BASELINE ===\n");
        section.append("STATUS: ").append(baselineStatus.getStatusLabel()).append("\n");
        section.append("IMPACT: ").append(baselineStatus.getImpactDescription()).append("\n");
        section.append("\nZERO TRUST WARNING:\n");
        section.append("- This is a new user without established behavioral baseline.\n");
        section.append("- Cannot verify if this is the legitimate user or an attacker.\n");
        section.append("- confidence MUST be <= 0.5 due to insufficient historical data.\n");
        section.append("- riskScore should be >= 0.5 for unverified users.\n");

        return section.toString();
    }

    private String buildDecisionSection() {
        return """

                === DECISION ===

                RESPOND WITH JSON ONLY:
                {"riskScore":<0.0-1.0>,"confidence":<0.3-0.95>,"action":"<ACTION>","reasoning":"<analysis>","mitre":"<TAG|none>"}

                ACTIONS:
                - ALLOW: Consistent with known patterns (low risk)
                - CHALLENGE: Needs verification (moderate risk)
                - BLOCK: Unauthorized access indicators (high risk)
                - ESCALATE: Requires human review (critical risk)

                MITRE (if applicable): T1078, T1110, T1185

                """;
    }

    private DetectedPatterns collectDetectedPatterns(List<Document> relatedDocuments, String userId) {
        DetectedPatterns patterns = new DetectedPatterns();
        StringBuilder relatedContextBuilder = new StringBuilder();

        int maxRagDocs = tieredStrategyProperties.getLayer1().getPrompt().getMaxRagDocuments();
        int maxDocs = (relatedDocuments != null) ? Math.min(maxRagDocs, relatedDocuments.size()) : 0;
        int addedDocs = 0;

        for (int i = 0; i < maxDocs && addedDocs < maxRagDocs; i++) {
            Document doc = relatedDocuments.get(i);

            Map<String, Object> docMetadata = doc.getMetadata();
            if (userId != null) {
                Object docUserId = docMetadata.get("userId");
                if (docUserId != null && !userId.equals(docUserId.toString())) {
                    continue;
                }
            }

            String content = doc.getText();
            if (content == null || content.isBlank()) {
                continue;
            }

            if (addedDocs > 0) {
                relatedContextBuilder.append("\n");
            }

            String docMeta = buildDocumentMetadata(doc, addedDocs + 1);
            int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getRagDocument();
            String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

            relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
            collectPatternFromDocument(docMetadata, patterns);
            addedDocs++;
        }

        patterns.hasRelatedDocs = relatedContextBuilder.length() > 0;
        patterns.relatedContext = patterns.hasRelatedDocs ? relatedContextBuilder.toString() : null;

        return patterns;
    }

    private void collectPatternFromDocument(Map<String, Object> metadata, DetectedPatterns patterns) {
        Object userAgentOS = metadata.get("userAgentOS");
        if (userAgentOS != null && !userAgentOS.toString().isEmpty()) {
            patterns.osSet.add(userAgentOS.toString());
        }

        Object sourceIp = metadata.get("sourceIp");
        if (sourceIp != null && !sourceIp.toString().isEmpty()) {
            String ipStr = sourceIp.toString();
            if (ipStr.contains("127.0.0.1") || ipStr.contains("0:0:0:0:0:0:0:1")) {
                patterns.ipSet.add("loopback");
            } else {
                patterns.ipSet.add(ipStr);
            }
        }

        Object hour = metadata.get("hour");
        if (hour != null) {
            patterns.hourSet.add(hour.toString());
        }

        Object userAgentBrowser = metadata.get("userAgentBrowser");
        if (userAgentBrowser != null && !userAgentBrowser.toString().isEmpty()) {
            patterns.uaSet.add(userAgentBrowser.toString());
        }

        Object requestPath = metadata.get("requestPath");
        if (requestPath != null && !requestPath.toString().isEmpty()) {
            String pathStr = requestPath.toString();
            int secondSlash = pathStr.indexOf('/', 1);
            int thirdSlash = secondSlash > 0 ? pathStr.indexOf('/', secondSlash + 1) : -1;
            if (thirdSlash > 0) {
                patterns.pathSet.add(pathStr.substring(0, thirdSlash) + "/*");
            } else {
                patterns.pathSet.add(pathStr);
            }
        }
    }

    private void enrichPatternsFromBaseline(DetectedPatterns patterns, BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return;
        }

        addAllNonEmpty(patterns.ipSet, behaviorAnalysis.getBaselineIpRanges());
        addAllNonEmpty(patterns.osSet, behaviorAnalysis.getBaselineOperatingSystems());
        addAllNonEmpty(patterns.uaSet, behaviorAnalysis.getBaselineUserAgents());
        addAllNonEmpty(patterns.pathSet, behaviorAnalysis.getBaselineFrequentPaths());

        if (behaviorAnalysis.getBaselineAccessHours() != null) {
            for (Integer hour : behaviorAnalysis.getBaselineAccessHours()) {
                if (hour != null) {
                    patterns.hourSet.add(hour.toString());
                }
            }
        }
    }

    private void addAllNonEmpty(Set<String> target, String[] source) {
        if (source == null) {
            return;
        }
        for (String value : source) {
            if (value != null && !value.isEmpty()) {
                target.add(value);
            }
        }
    }

    private void appendZeroTrustSignals(StringBuilder prompt, SecurityEvent event,
                                        BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus) {

        boolean isNewUserForLlm = (baselineStatus != BaselineStatus.ESTABLISHED);
        prompt.append("IsNewUser: ").append(isNewUserForLlm);
        if (isNewUserForLlm) {
            prompt.append(" (no baseline established)");
        }
        prompt.append("\n");

        Boolean isNewSession = getIsNewSession(behaviorAnalysis, event);
        if (isNewSession != null) {
            prompt.append("IsNewSession: ").append(isNewSession).append("\n");
        }

        Boolean isNewDevice = getIsNewDevice(behaviorAnalysis, event);
        if (isNewDevice != null) {
            prompt.append("IsNewDevice: ").append(isNewDevice).append("\n");

            if (isNewDevice) {
                prompt.append("  -> First time seeing this device for this user\n");
            }
        }
    }

    private Boolean getIsNewSession(BehaviorAnalysis behaviorAnalysis, SecurityEvent event) {
        if (behaviorAnalysis != null && behaviorAnalysis.getIsNewSession() != null) {
            return behaviorAnalysis.getIsNewSession();
        }

        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;
            Object value = metadata.get("isNewSession");
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return null;
    }

    private Boolean getIsNewDevice(BehaviorAnalysis behaviorAnalysis, SecurityEvent event) {
        if (behaviorAnalysis != null && behaviorAnalysis.getIsNewDevice() != null) {
            return behaviorAnalysis.getIsNewDevice();
        }

        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;
            Object value = metadata.get("isNewDevice");
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return null;
    }

    private String buildNetworkDetails(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        PromptTemplateUtils.appendIpWithValidation(network, event.getSourceIp());

        if (isValidData(event.getSessionId())) {
            String sanitizedSessionId = PromptTemplateUtils.sanitizeUserInput(event.getSessionId());
            network.append("SessionId: ").append(sanitizedSessionId).append("\n");
        } else {
            network.append("SessionId: NOT_PROVIDED [CRITICAL: Cannot verify session]\n");
        }

        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
            int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer1().getUserAgent();
            String sanitizedUa = PromptTemplateUtils.sanitizeAndTruncate(ua, maxUserAgent);
            network.append("UserAgent: ").append(sanitizedUa).append("\n");

            String currentOS = extractOSFromUserAgent(ua);
            if (currentOS != null) {
                network.append("CurrentOS: ").append(currentOS).append("\n");
            }

            String currentUA = extractUASignature(ua);
            network.append("CurrentUA: ").append(currentUA).append("\n");
        }

        return network.toString().trim();
    }

    private Optional<String> summarizePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return Optional.empty();
        }
        int maxPayload = tieredStrategyProperties.getTruncation().getLayer1().getPayload();
        if (payload.length() > maxPayload) {
            return Optional.of(payload.substring(0, maxPayload) + "... (truncated)");
        }
        return Optional.of(payload);
    }

    private String buildDocumentMetadata(Document doc, int docIndex) {
        StringBuilder meta = new StringBuilder();
        meta.append("[Doc").append(docIndex);

        Map<String, Object> metadata = doc.getMetadata();
        Object scoreObj = metadata.get(VectorDocumentMetadata.SIMILARITY_SCORE);
        if (scoreObj == null) {
            scoreObj = metadata.get("score");
        }
        if (scoreObj instanceof Number) {
            meta.append("|sim=").append(String.format("%.2f", ((Number) scoreObj).doubleValue()));
        }

        Object typeObj = metadata.get("documentType");
        if (typeObj == null) {
            typeObj = metadata.get("type");
        }
        if (typeObj != null) {
            meta.append("|type=").append(typeObj.toString());
        }

        Object userId = metadata.get("userId");
        if (userId != null) {
            meta.append("|user=").append(userId);
        }

        Object sourceIp = metadata.get("sourceIp");
        if (sourceIp != null) {
            meta.append("|ip=").append(sourceIp);
        }

        Object hour = metadata.get("hour");
        if (hour != null) {
            meta.append("|hour=").append(hour);
        } else {
            Object timestamp = metadata.get("timestamp");
            if (timestamp != null) {
                String timeStr = timestamp.toString();
                if (timeStr.contains("T") && timeStr.length() > 13) {
                    meta.append("|hour=").append(timeStr.substring(11, 13));
                }
            }
        }

        Object requestUri = metadata.get("requestPath");
        if (requestUri != null) {
            meta.append("|path=").append(requestUri);
        }

        meta.append("]");
        return meta.toString();
    }

    private boolean isValidData(String value) {
        return PromptTemplateUtils.isValidData(value);
    }

    private String extractOSFromUserAgent(String userAgent) {
        return SecurityEventEnricher.extractOSFromUserAgent(userAgent);
    }

    private String normalizeIP(String ip) {
        return SecurityEventEnricher.normalizeIP(ip);
    }

    private Set<String> normalizeIPSet(Set<String> ipSet) {
        if (ipSet == null || ipSet.isEmpty()) {
            return ipSet;
        }

        Set<String> normalized = new LinkedHashSet<>();
        for (String ip : ipSet) {
            normalized.add(normalizeIP(ip));
        }
        return normalized;
    }

    private String extractUASignature(String userAgent) {
        String signature = SecurityEventEnricher.extractBrowserSignature(userAgent);
        return signature != null ? signature : "Browser";
    }

    private String extractRequestPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object path = metadata.get("requestPath");
            if (path != null && !path.toString().isEmpty()) {
                return path.toString();
            }

            Object uri = metadata.get("requestUri");
            if (uri != null && !uri.toString().isEmpty()) {
                return uri.toString();
            }
        }

        String desc = event.getDescription();
        if (desc != null && desc.contains(" /")) {
            int pathStart = desc.indexOf(" /") + 1;
            int pathEnd = desc.indexOf(" ", pathStart);
            if (pathEnd == -1) pathEnd = desc.length();
            String path = desc.substring(pathStart, pathEnd);
            if (!path.isEmpty()) {
                return path;
            }
        }

        return null;
    }

      private BaselineStatus determineBaselineStatus(BehaviorAnalysis behaviorAnalysis, String baselineContext) {

        if (behaviorAnalysis == null) {
            return BaselineStatus.ANALYSIS_UNAVAILABLE;
        }

        if (isValidBaseline(baselineContext)) {
            return BaselineStatus.ESTABLISHED;
        }

        if (baselineContext != null && baselineContext.startsWith("[")) {
            if (baselineContext.startsWith("[SERVICE_UNAVAILABLE]")) {
                return BaselineStatus.SERVICE_UNAVAILABLE;
            }
            if (baselineContext.startsWith("[NO_USER_ID]")) {
                return BaselineStatus.MISSING_USER_ID;
            }
            if (baselineContext.startsWith("[NO_DATA]")) {
                return BaselineStatus.NOT_LOADED;
            }
            return BaselineStatus.NEW_USER;
        }

        if (baselineContext != null &&
                (baselineContext.contains("CRITICAL") || baselineContext.contains("NO USER BASELINE"))) {
            return BaselineStatus.NEW_USER;
        }

        if (behaviorAnalysis.isBaselineEstablished()) {
            return BaselineStatus.NOT_LOADED;
        }

        return BaselineStatus.NEW_USER;
    }

    private boolean isValidBaseline(String baseline) {
        if (baseline == null || baseline.isEmpty()) {
            return false;
        }
        if (baseline.startsWith("[SERVICE_UNAVAILABLE]") ||
                baseline.startsWith("[NO_USER_ID]") ||
                baseline.startsWith("[NO_DATA]")) {
            return false;
        }
        if (baseline.contains("CRITICAL") || baseline.contains("NO USER BASELINE") ||
                baseline.contains("[NEW_USER]")) {
            return false;
        }
        return !baseline.equalsIgnoreCase("Not available")
                && !baseline.equalsIgnoreCase("none")
                && !baseline.equalsIgnoreCase("N/A");
    }

    private void appendMetadataIfPresent(StringBuilder sb, Map<String, Object> metadata, String metadataKey, String promptLabel) {
        if (metadata == null) {
            return;
        }
        Object value = metadata.get(metadataKey);
        if (value != null) {
            sb.append(promptLabel).append(": ").append(value).append("\n");
        }
    }

    private void appendIfPresent(StringBuilder sb, String section) {
        if (section != null) {
            sb.append(section);
        }
    }

    private static class DetectedPatterns {
        final Set<String> osSet = new HashSet<>();
        final Set<String> ipSet = new HashSet<>();
        final Set<String> hourSet = new HashSet<>();
        final Set<String> uaSet = new HashSet<>();
        final Set<String> pathSet = new HashSet<>();
        String relatedContext;
        boolean hasRelatedDocs;
    }

    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions;

        private Integer sessionAgeMinutes;
        private Integer requestCount;

        public String getSessionId() {
            return sessionId;
        }

        public void setSessionId(String sessionId) {
            this.sessionId = sessionId;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getAuthMethod() {
            return authMethod;
        }

        public void setAuthMethod(String authMethod) {
            this.authMethod = authMethod;
        }

        public List<String> getRecentActions() {
            return recentActions != null ? recentActions : List.of();
        }

        public void setRecentActions(List<String> recentActions) {
            this.recentActions = recentActions;
        }

        public Integer getSessionAgeMinutes() {
            return sessionAgeMinutes;
        }

        public void setSessionAgeMinutes(Integer sessionAgeMinutes) {
            this.sessionAgeMinutes = sessionAgeMinutes;
        }

        public Integer getRequestCount() {
            return requestCount;
        }

        public void setRequestCount(Integer requestCount) {
            this.requestCount = requestCount;
        }
    }

    public static class BehaviorAnalysis {
        private List<String> similarEvents;
        private String baselineContext;
        private boolean baselineEstablished;

        private Boolean isNewUser;
        private Boolean isNewSession;
        private Boolean isNewDevice;

        private String previousUserAgentOS;
        private String currentUserAgentOS;

        private String[] baselineIpRanges;
        private String[] baselineOperatingSystems;
        private String[] baselineUserAgents;
        private String[] baselineFrequentPaths;
        private Integer[] baselineAccessHours;

        public List<String> getSimilarEvents() {
            return similarEvents != null ? similarEvents : List.of();
        }

        public void setSimilarEvents(List<String> events) {
            this.similarEvents = events;
        }

        public String getBaselineContext() {
            return baselineContext;
        }

        public void setBaselineContext(String baselineContext) {
            this.baselineContext = baselineContext;
        }

        public boolean isBaselineEstablished() {
            return baselineEstablished;
        }

        public void setBaselineEstablished(boolean baselineEstablished) {
            this.baselineEstablished = baselineEstablished;
        }

        public Boolean getIsNewUser() {
            return isNewUser;
        }

        public void setIsNewUser(Boolean isNewUser) {
            this.isNewUser = isNewUser;
        }

        public Boolean getIsNewSession() {
            return isNewSession;
        }

        public void setIsNewSession(Boolean isNewSession) {
            this.isNewSession = isNewSession;
        }

        public Boolean getIsNewDevice() {
            return isNewDevice;
        }

        public void setIsNewDevice(Boolean isNewDevice) {
            this.isNewDevice = isNewDevice;
        }

        public String getPreviousUserAgentOS() {
            return previousUserAgentOS;
        }

        public void setPreviousUserAgentOS(String previousUserAgentOS) {
            this.previousUserAgentOS = previousUserAgentOS;
        }

        public String getCurrentUserAgentOS() {
            return currentUserAgentOS;
        }

        public void setCurrentUserAgentOS(String currentUserAgentOS) {
            this.currentUserAgentOS = currentUserAgentOS;
        }

        public String[] getBaselineIpRanges() {
            return baselineIpRanges;
        }

        public void setBaselineIpRanges(String[] baselineIpRanges) {
            this.baselineIpRanges = baselineIpRanges;
        }

        public String[] getBaselineOperatingSystems() {
            return baselineOperatingSystems;
        }

        public void setBaselineOperatingSystems(String[] baselineOperatingSystems) {
            this.baselineOperatingSystems = baselineOperatingSystems;
        }

        public String[] getBaselineUserAgents() {
            return baselineUserAgents;
        }

        public void setBaselineUserAgents(String[] baselineUserAgents) {
            this.baselineUserAgents = baselineUserAgents;
        }

        public String[] getBaselineFrequentPaths() {
            return baselineFrequentPaths;
        }

        public void setBaselineFrequentPaths(String[] baselineFrequentPaths) {
            this.baselineFrequentPaths = baselineFrequentPaths;
        }

        public Integer[] getBaselineAccessHours() {
            return baselineAccessHours;
        }

        public void setBaselineAccessHours(Integer[] baselineAccessHours) {
            this.baselineAccessHours = baselineAccessHours;
        }
    }
}
