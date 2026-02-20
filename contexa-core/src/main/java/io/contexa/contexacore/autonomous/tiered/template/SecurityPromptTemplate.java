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
        prompt.append(buildCurrentRequestNarrative(event, behaviorAnalysis, patterns));
        prompt.append(buildUserProfileNarrative(patterns, behaviorAnalysis, baselineStatus));
        prompt.append(buildNetworkPromptSection(event));
        appendIfPresent(prompt, buildPayloadSection(event));
        prompt.append(buildSessionTimelineSection(sessionContext, behaviorAnalysis));
        appendIfPresent(prompt, buildSessionDeviceChangeSection(behaviorAnalysis));
        prompt.append(buildSimilarEventsSection(behaviorAnalysis, patterns));
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
                You will receive contextual information about a security event,
                including the user's behavioral profile, session timeline,
                and similar past events.

                Read all context carefully and make a holistic judgment
                about whether this request is legitimate or suspicious.
                Do NOT apply simple rule-matching. Interpret the overall
                narrative and meaning of the combined signals.

                Respond with ONLY a JSON object. No explanation, no markdown.

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

    private String buildCurrentRequestNarrative(SecurityEvent event,
            BehaviorAnalysis behaviorAnalysis, DetectedPatterns patterns) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== CURRENT REQUEST ===\n");

        StringBuilder narrative = new StringBuilder();
        narrative.append("User is requesting ");

        String method = null;
        String path = extractRequestPath(event);
        if (event.getMetadata() != null) {
            Object m = event.getMetadata().get("httpMethod");
            if (m != null) method = m.toString();
        }
        if (method != null) narrative.append(method).append(" ");
        if (path != null) {
            narrative.append(PromptTemplateUtils.sanitizeUserInput(path));
        } else {
            narrative.append("a resource");
        }

        String ip = SecurityEventEnricher.normalizeIP(event.getSourceIp());
        if (ip != null) {
            narrative.append(" from ").append(ip);
        }

        String os = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
        String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
        if (os != null || browser != null) {
            narrative.append(" using ");
            if (browser != null) narrative.append(browser);
            if (os != null) narrative.append(" on ").append(os);
        }

        if (event.getTimestamp() != null) {
            narrative.append(" at ").append(String.format("%02d:%02d",
                    event.getTimestamp().getHour(),
                    event.getTimestamp().getMinute()));
        }

        narrative.append(".");
        section.append(narrative).append("\n");

        if (behaviorAnalysis != null) {
            if (behaviorAnalysis.getPreviousPath() != null) {
                section.append("Previous request path: ")
                       .append(PromptTemplateUtils.sanitizeUserInput(
                               behaviorAnalysis.getPreviousPath()))
                       .append(".\n");
            }
            if (behaviorAnalysis.getLastRequestIntervalMs() != null) {
                long intervalSec = behaviorAnalysis.getLastRequestIntervalMs() / 1000;
                section.append("Time since last request: ")
                       .append(intervalSec).append(" seconds.\n");
            }
        }

        return section.toString();
    }

    private String buildUserProfileNarrative(DetectedPatterns patterns,
            BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== USER PROFILE ===\n");

        if (baselineStatus == BaselineStatus.NEW_USER) {
            section.append("This is a new user without established behavioral baseline.\n");
            section.append("No historical data available to compare against.\n");
            return section.toString();
        }

        if (baselineStatus != BaselineStatus.ESTABLISHED) {
            section.append("User profile data is limited or unavailable.\n");
            return section.toString();
        }

        StringBuilder profile = new StringBuilder("This user normally ");

        if (!patterns.hourSet.isEmpty()) {
            profile.append("accesses the system during hours ")
                   .append(String.join(", ", patterns.hourSet));
        }

        if (!patterns.ipSet.isEmpty()) {
            profile.append(", from network ")
                   .append(String.join(", ", normalizeIPSet(patterns.ipSet)));
        }

        if (!patterns.osSet.isEmpty() || !patterns.uaSet.isEmpty()) {
            profile.append(", using ");
            if (!patterns.uaSet.isEmpty()) {
                profile.append(String.join("/", patterns.uaSet));
            }
            if (!patterns.osSet.isEmpty()) {
                profile.append(" on ").append(String.join("/", patterns.osSet));
            }
        }

        profile.append(".");
        section.append(profile).append("\n");

        if (!patterns.pathSet.isEmpty()) {
            section.append("Frequent paths: ")
                   .append(String.join(", ", patterns.pathSet))
                   .append(".\n");
        }

        if (behaviorAnalysis != null) {
            if (behaviorAnalysis.getBaselineUpdateCount() != null) {
                section.append("Baseline observations: ")
                       .append(behaviorAnalysis.getBaselineUpdateCount()).append(".\n");
            }
            if (behaviorAnalysis.getBaselineAvgTrustScore() != null) {
                section.append(String.format("Historical trust score: %.2f.\n",
                        behaviorAnalysis.getBaselineAvgTrustScore()));
            }
        }

        if (behaviorAnalysis != null && behaviorAnalysis.getBaselineContext() != null
                && !behaviorAnalysis.getBaselineContext().startsWith("[")) {
            section.append("\nEstablished baseline (from learned behavior):\n");
            section.append(PromptTemplateUtils.sanitizeUserInput(
                    behaviorAnalysis.getBaselineContext()));
            section.append("\n");
        }

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

    private String buildSessionTimelineSection(SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== SESSION TIMELINE ===\n");

        if (sessionContext == null) {
            section.append("No session context available.\n");
            return section.toString();
        }

        Integer sessionAge = sessionContext.getSessionAgeMinutes();
        String authMethod = sessionContext.getAuthMethod();
        if (sessionAge != null || authMethod != null) {
            section.append("Session started ");
            if (sessionAge != null) {
                section.append(sessionAge).append(" minutes ago");
            }
            if (authMethod != null) {
                section.append(" via ").append(
                        PromptTemplateUtils.sanitizeUserInput(authMethod))
                       .append(" authentication");
            }
            section.append(".\n");
        }

        Integer requestCount = sessionContext.getRequestCount();
        if (requestCount != null && requestCount > 0) {
            if (sessionAge != null && sessionAge > 0) {
                double requestsPerMinute = (double) requestCount / sessionAge;
                section.append(String.format(
                        "Requests in this session: %d (%.1f per minute).\n",
                        requestCount, requestsPerMinute));
            } else {
                section.append(String.format("Requests in this session: %d.\n", requestCount));
            }
        }

        List<String> recentActions = sessionContext.getRecentActions();
        if (recentActions != null && !recentActions.isEmpty()) {
            section.append("\nRecent activity in this session ");
            section.append("(observed responses are prior policy decisions, ");
            section.append("not ground truth - reassess independently):\n");
            int maxActions = Math.min(10, recentActions.size());
            for (int i = 0; i < maxActions; i++) {
                String action = PromptTemplateUtils.sanitizeUserInput(
                        recentActions.get(i));
                section.append("  ").append(i + 1).append(". ")
                       .append(action).append("\n");
            }
        }

        return section.toString();
    }

    private String buildSessionDeviceChangeSection(BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return null;
        }

        String previousOS = behaviorAnalysis.getPreviousUserAgentOS();
        String currentOS = behaviorAnalysis.getCurrentUserAgentOS();
        String previousBrowser = behaviorAnalysis.getPreviousUserAgentBrowser();
        String currentBrowser = behaviorAnalysis.getCurrentUserAgentBrowser();

        boolean osChanged = previousOS != null && currentOS != null
                && !previousOS.equals(currentOS);
        boolean browserChanged = previousBrowser != null && currentBrowser != null
                && !previousBrowser.equals(currentBrowser);

        if (!osChanged && !browserChanged) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== SESSION DEVICE CHANGE ===\n");
        section.append("OBSERVATION: Same SessionId with different device fingerprint detected.\n");

        if (osChanged) {
            section.append("Previous OS: ").append(previousOS).append("\n");
            section.append("Current OS: ").append(currentOS).append("\n");
            section.append("OS Transition: ").append(previousOS)
                   .append(" -> ").append(currentOS).append("\n");
        }

        if (browserChanged) {
            section.append("Previous Browser: ").append(previousBrowser).append("\n");
            section.append("Current Browser: ").append(currentBrowser).append("\n");
            section.append("Browser Transition: ").append(previousBrowser)
                   .append(" -> ").append(currentBrowser).append("\n");
        }

        return section.toString();
    }

    private String buildSimilarEventsSection(BehaviorAnalysis behaviorAnalysis,
            DetectedPatterns patterns) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== SIMILAR PAST EVENTS ===\n");

        boolean hasContent = false;

        if (behaviorAnalysis != null) {
            List<String> similarEvents = behaviorAnalysis.getSimilarEvents();
            if (similarEvents != null && !similarEvents.isEmpty()) {
                int max = Math.min(
                        tieredStrategyProperties.getLayer1().getPrompt()
                                .getMaxSimilarEvents(),
                        similarEvents.size());
                for (int i = 0; i < max; i++) {
                    String sanitized = PromptTemplateUtils.sanitizeUserInput(
                            similarEvents.get(i));
                    section.append("  ").append(i + 1).append(". ")
                           .append(sanitized).append("\n");
                }
                hasContent = true;
            }
        }

        if (!hasContent && patterns.hasRelatedDocs) {
            section.append("Historical records for context:\n");
            String sanitized = PromptTemplateUtils.sanitizeUserInput(
                    patterns.relatedContext);
            section.append(sanitized).append("\n");
            hasContent = true;
        }

        if (!hasContent) {
            section.append("No similar past events found for this user.\n");
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

                Based on ALL the context above - user profile, session timeline,
                similar past events, and current request - make a holistic
                security judgment.

                Consider the overall narrative: Does this session's activity
                pattern tell a story of legitimate use or suspicious behavior?

                You MUST provide both a legitimate and suspicious hypothesis
                before making your final decision. Extract specific evidence
                from the timeline and profile to support each hypothesis.

                RESPOND WITH JSON ONLY:
                {
                  "action":"ALLOW|CHALLENGE|BLOCK|ESCALATE",
                  "riskScore":<0.0-1.0>,
                  "confidence":<0.3-0.95>,
                  "reasoning":"<your final interpretation>",
                  "evidence":["<fact from timeline>","<fact from profile>"],
                  "legitimateHypothesis":"<why this could be normal behavior>",
                  "suspiciousHypothesis":"<why this could be malicious>",
                  "mitre":"<TAG|none>"
                }

                ACTIONS:
                - ALLOW: Legitimate hypothesis is strongly supported
                - CHALLENGE: Both hypotheses are plausible, need verification
                - BLOCK: Suspicious hypothesis is strongly supported
                - ESCALATE: Insufficient context for confident judgment

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
            patterns.ipSet.add(SecurityEventEnricher.normalizeIP(sourceIp.toString()));
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

            String currentOS = SecurityEventEnricher.extractOSFromUserAgent(ua);
            if (currentOS != null) {
                network.append("CurrentOS: ").append(currentOS).append("\n");
            }

            String sig = SecurityEventEnricher.extractBrowserSignature(ua);
            network.append("CurrentUA: ").append(sig != null ? sig : "Browser").append("\n");
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
        Double docScore = doc.getScore();
        if (docScore != null) {
            meta.append("|sim=").append(String.format("%.2f", docScore));
        } else {
            Object scoreObj = metadata.get(VectorDocumentMetadata.SIMILARITY_SCORE);
            if (scoreObj == null) {
                scoreObj = metadata.get("score");
            }
            if (scoreObj == null) {
                scoreObj = metadata.get("distance");
            }
            if (scoreObj instanceof Number) {
                meta.append("|sim=").append(String.format("%.2f", ((Number) scoreObj).doubleValue()));
            }
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

    private Set<String> normalizeIPSet(Set<String> ipSet) {
        if (ipSet == null || ipSet.isEmpty()) {
            return ipSet;
        }

        Set<String> normalized = new LinkedHashSet<>();
        for (String ip : ipSet) {
            normalized.add(SecurityEventEnricher.normalizeIP(ip));
        }
        return normalized;
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

        private Boolean isNewSession;
        private Boolean isNewDevice;

        private String previousUserAgentOS;
        private String currentUserAgentOS;

        private String[] baselineIpRanges;
        private String[] baselineOperatingSystems;
        private String[] baselineUserAgents;
        private String[] baselineFrequentPaths;
        private Integer[] baselineAccessHours;

        private Long baselineUpdateCount;
        private Double baselineAvgTrustScore;

        private String previousUserAgentBrowser;
        private String currentUserAgentBrowser;

        private Long lastRequestIntervalMs;
        private String previousPath;

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

        public Long getBaselineUpdateCount() {
            return baselineUpdateCount;
        }

        public void setBaselineUpdateCount(Long baselineUpdateCount) {
            this.baselineUpdateCount = baselineUpdateCount;
        }

        public Double getBaselineAvgTrustScore() {
            return baselineAvgTrustScore;
        }

        public void setBaselineAvgTrustScore(Double baselineAvgTrustScore) {
            this.baselineAvgTrustScore = baselineAvgTrustScore;
        }

        public String getPreviousUserAgentBrowser() {
            return previousUserAgentBrowser;
        }

        public void setPreviousUserAgentBrowser(String previousUserAgentBrowser) {
            this.previousUserAgentBrowser = previousUserAgentBrowser;
        }

        public String getCurrentUserAgentBrowser() {
            return currentUserAgentBrowser;
        }

        public void setCurrentUserAgentBrowser(String currentUserAgentBrowser) {
            this.currentUserAgentBrowser = currentUserAgentBrowser;
        }

        public Long getLastRequestIntervalMs() {
            return lastRequestIntervalMs;
        }

        public void setLastRequestIntervalMs(Long lastRequestIntervalMs) {
            this.lastRequestIntervalMs = lastRequestIntervalMs;
        }

        public String getPreviousPath() {
            return previousPath;
        }

        public void setPreviousPath(String previousPath) {
            this.previousPath = previousPath;
        }
    }
}
