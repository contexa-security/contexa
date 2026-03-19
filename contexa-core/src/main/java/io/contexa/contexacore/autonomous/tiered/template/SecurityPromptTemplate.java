package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.mcp.McpSecurityContextProvider;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;

import java.util.*;

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
    private final McpSecurityContextProvider mcpSecurityContextProvider;

    public SecurityPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            McpSecurityContextProvider mcpSecurityContextProvider) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null ? tieredStrategyProperties : new TieredStrategyProperties();
        this.mcpSecurityContextProvider = mcpSecurityContextProvider;
    }

    public SecurityPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        this(eventEnricher, tieredStrategyProperties, null);
    }

    /**
     * Structured prompt with separated system (fixed) and user (variable) text.
     * Splitting enables Ollama KV cache prefix reuse for the system portion.
     */
    public record StructuredPrompt(String systemText, String userText) {}

    /**
     * Builds a structured prompt with system/user separation for KV cache optimization.
     * The system text (instructions + decision format) is fixed across requests,
     * allowing Ollama to reuse its KV cache prefix.
     *
     * @param event the security event to analyze
     * @param sessionContext the current session context
     * @param behaviorAnalysis the behavioral analysis data
     * @param relatedDocuments the RAG-retrieved related documents
     * @return structured prompt with separated system and user text
     */
    public StructuredPrompt buildStructuredPrompt(SecurityEvent event,
                                                   SessionContext sessionContext,
                                                   BehaviorAnalysis behaviorAnalysis,
                                                   List<Document> relatedDocuments) {

        String userId = extractUserId(sessionContext);
        String baselineContext = extractBaselineContext(behaviorAnalysis);
        BaselineStatus baselineStatus = determineBaselineStatus(behaviorAnalysis, baselineContext);

        DetectedPatterns patterns = collectDetectedPatterns(relatedDocuments, userId);
        enrichPatternsFromBaseline(patterns, behaviorAnalysis);

        String systemText = buildSystemInstruction() + buildDecisionSection();

        StringBuilder userPart = new StringBuilder();
        userPart.append(buildEventSection(event, userId));
        userPart.append(buildCurrentRequestNarrative(event, behaviorAnalysis, patterns));
        userPart.append(buildUserProfileNarrative(event, patterns, behaviorAnalysis, baselineStatus));
        userPart.append(buildNetworkPromptSection(event));
        appendIfPresent(userPart, buildPayloadSection(event));
        userPart.append(buildSessionTimelineSection(sessionContext, behaviorAnalysis));
        appendIfPresent(userPart, buildSessionDeviceChangeSection(behaviorAnalysis));
        userPart.append(buildSimilarEventsSection(behaviorAnalysis, patterns));
        appendIfPresent(userPart, buildMcpSecurityContextSection(event));
        appendIfPresent(userPart, buildNewUserBaselineSection(baselineStatus, baselineContext));

        return new StructuredPrompt(systemText, userPart.toString());
    }

    /**
     * Builds the complete security analysis prompt as a single string.
     * Backward-compatible wrapper around buildStructuredPrompt().
     */
    public String buildPrompt(SecurityEvent event,
                              SessionContext sessionContext,
                              BehaviorAnalysis behaviorAnalysis,
                              List<Document> relatedDocuments) {

        StructuredPrompt structured = buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
        return structured.systemText() + structured.userText();
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
        TieredStrategyProperties.Layer1.Prompt promptConfig = tieredStrategyProperties.getLayer1().getPrompt();
        StringBuilder section = new StringBuilder();
        section.append("=== EVENT ===\n");

        if (promptConfig.isIncludeEventId() && isValidData(event.getEventId())) {
            section.append("EventId: ").append(PromptTemplateUtils.sanitizeUserInput(event.getEventId())).append("\n");
        }
        if (event.getTimestamp() != null) {
            if (promptConfig.isIncludeRawTimestamp()) {
                section.append("Timestamp: ").append(event.getTimestamp()).append("\n");
            }
            section.append("CurrentHour: ").append(event.getTimestamp().getHour()).append("\n");
            int dow = event.getTimestamp().getDayOfWeek().getValue();
            section.append("CurrentDay: ").append(dayOfWeekLabel(dow))
                   .append(" (").append(dow).append(")\n");
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
            appendMetadataIfPresent(section, metadataObj, "failedLoginAttempts", "FailedLoginAttempts");
            appendMetadataIfPresent(section, metadataObj, "isNewDevice", "NewDevice");
            appendMetadataIfPresent(section, metadataObj, "isNewSession", "NewSession");
            appendMetadataIfPresent(section, metadataObj, "isNewUser", "NewUser");
            appendMetadataIfPresent(section, metadataObj, "mfaVerified", "MfaVerified");
        }

        String eventPath = extractRequestPath(event);
        if (eventPath != null && !eventPath.isEmpty()) {
            section.append("Path: ").append(PromptTemplateUtils.sanitizeUserInput(eventPath)).append("\n");
        } else {
            section.append("Path: unknown\n");
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

        if (event.getMetadata() != null) {
            Object sensitiveResource = event.getMetadata().get("isSensitiveResource");
            if (sensitiveResource == null) {
                section.append("Resource sensitivity: unknown.\n");
            } else if (Boolean.TRUE.equals(sensitiveResource)) {
                section.append("This is a SENSITIVE resource.\n");
            } else {
                section.append("This is NOT a sensitive resource.\n");
            }
        } else {
            section.append("Resource sensitivity: unknown.\n");
        }

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

        if (event.getMetadata() != null) {
            Object recentCount = event.getMetadata().get("recentRequestCount");
            if (recentCount instanceof Number && ((Number) recentCount).intValue() > 0) {
                int count = ((Number) recentCount).intValue();
                section.append("Requests in last 5 minutes: ").append(count).append(".\n");
            }
        }

        return section.toString();
    }

    private String buildUserProfileNarrative(SecurityEvent event, DetectedPatterns patterns,
            BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus) {
        StringBuilder section = new StringBuilder();
        section.append("\n=== USER PROFILE ===\n");

        Map<String, Object> meta = event != null ? event.getMetadata() : null;
        if (meta != null) {
            Object userRoles = meta.get("userRoles");
            if (userRoles != null) {
                String rolesStr = userRoles.toString();
                rolesStr = rolesStr.replaceAll("ROLE_PENDING_ANALYSIS,?\\s*", "")
                                   .replaceAll("ROLE_BLOCKED,?\\s*", "")
                                   .replaceAll("ROLE_MFA_REQUIRED,?\\s*", "")
                                   .replaceAll("ROLE_REVIEW_REQUIRED,?\\s*", "")
                                   .replaceAll(",\\s*]", "]")
                                   .replaceAll("\\[\\s*,", "[");
                if (!rolesStr.equals("[]") && !rolesStr.isBlank()) {
                    section.append("User roles: ").append(rolesStr).append(".\n");
                }
            }
            Object baselineConfidence = meta.get("baselineConfidence");
            if (baselineConfidence instanceof Number) {
                double confidence = ((Number) baselineConfidence).doubleValue();
                if (!Double.isNaN(confidence)) {
                    section.append(String.format("Baseline confidence: %.1f", confidence));
                    if (confidence < 0.1) {
                        section.append(" (insufficient observations - baseline NOT yet established)");
                    } else if (confidence < 0.4) {
                        section.append(" (weak baseline - limited observations)");
                    } else if (confidence < 0.8) {
                        section.append(" (moderate baseline)");
                    } else {
                        section.append(" (strong baseline)");
                    }
                    section.append(".\n");
                }
            }
        }

        if (baselineStatus == BaselineStatus.NEW_USER) {
            section.append("User is registered but has NO established behavioral baseline yet.\n");
            section.append("Insufficient observation data to compare against.\n");
            section.append("NOTE: NewUser in EVENT section reflects registration status, not baseline status.\n");
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
            if (!patterns.daySet.isEmpty()) {
                profile.append(" (primarily ").append(String.join("/", patterns.daySet)).append(")");
            }
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

        if (behaviorAnalysis != null && Boolean.TRUE.equals(behaviorAnalysis.getContextBindingHashMismatch())) {
            section.append("ALERT: Context binding hash MISMATCH detected. ");
            section.append("The session fingerprint (IP+UserAgent+SessionId) does not match ");
            section.append("the stored binding hash. This is a strong indicator of session hijacking.\n");
        }

        Integer requestCount = sessionContext.getRequestCount();
        if (requestCount != null && requestCount > 0) {
            if (sessionAge != null && sessionAge > 0) {
                double requestsPerMinute = (double) requestCount / sessionAge;
                section.append(String.format(
                        "Requests in this session: %d (%.1f per minute).\n",
                        requestCount, requestsPerMinute));

                if (behaviorAnalysis != null && behaviorAnalysis.getBaselineAvgRequestRate() != null
                        && behaviorAnalysis.getBaselineAvgRequestRate() > 0) {
                    double baselineRate = behaviorAnalysis.getBaselineAvgRequestRate();
                    double ratio = requestsPerMinute / baselineRate;
                    section.append(String.format(
                            "Baseline average request rate: %.1f per minute (current is %.1fx of baseline).\n",
                            baselineRate, ratio));
                }
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
        section.append("Factual access records from past events. Evaluate the CURRENT request independently.\n");

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

    private String buildNewUserBaselineSection(BaselineStatus baselineStatus, String baselineContext) {
        if (baselineStatus != BaselineStatus.NEW_USER) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        section.append("\n=== BASELINE ===\n");
        section.append("STATUS: ").append(baselineStatus.getStatusLabel()).append("\n");
        section.append("IMPACT: ").append(baselineStatus.getImpactDescription()).append("\n");

        if (baselineContext != null && baselineContext.contains("Organization Baseline")) {
            section.append("\n");
            section.append(PromptTemplateUtils.sanitizeUserInput(baselineContext));
            section.append("\n");
        }

        section.append("\nZERO TRUST WARNING:\n");
        section.append("- This is a new user without established behavioral baseline.\n");
        section.append("- Cannot verify if this is the legitimate user or an attacker.\n");
        section.append("- confidence MUST be <= 0.5 due to insufficient historical data.\n");
        section.append("- riskScore should be >= 0.5 for unverified users.\n");
        section.append("- If this request targets a SENSITIVE resource: BLOCK is strongly recommended.\n");
        section.append("- If this request targets a non-sensitive resource: CHALLENGE to verify identity.\n");

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

                Use the strongest signals from the request, timeline,
                and baseline to make a concise decision.
                Keep reasoning short and focused.
                Do not generate extra hypotheses or evidence lists unless explicitly requested.

                RESPOND WITH JSON ONLY:
                {
                  "action":"ALLOW|CHALLENGE|BLOCK|ESCALATE",
                  "riskScore":<0.0-1.0>,
                  "confidence":<0.1-0.95>,
                  "reasoning":"<1-2 sentence explanation of key factors>"
                }

                CONFIDENCE CALIBRATION:
                - 0.1-0.3: Very low - insufficient data or conflicting signals, prefer ESCALATE
                - 0.3-0.5: Low - some signals present but ambiguous
                - 0.5-0.7: Moderate - clear primary signal with minor ambiguity
                - 0.7-0.85: High - multiple consistent signals confirming judgment
                - 0.85-0.95: Very high - overwhelming evidence, baseline match/mismatch clear

                ACTION DECISION GUIDE:

                BLOCK - Active threat detected, immediate denial required:
                  - Session hijacking indicators (context binding hash mismatch, mid-session device/OS change)
                  - IMPOSSIBLE TRAVEL DETECTED (physically impossible geographic movement between requests)
                  - Similar past events show threat patterns matching current request
                  - Multiple high-risk signals combined (unknown IP + unknown device + sensitive resource + MfaVerified: false)
                  - Known attack patterns (credential stuffing: high FailedLoginAttempts + new location + new device)
                  - No baseline at all (neither personal nor organization) and accessing a SENSITIVE resource

                CHALLENGE - Suspicious but verifiable, require re-authentication:
                  - Partial mismatch with baseline (1-2 signals differ, e.g., new IP but same device/OS)
                  - New device from known IP range
                  - Unusual time but matching device fingerprint
                  - SENSITIVE resource access with MfaVerified: false (when baseline otherwise matches)
                  - Single anomalous signal in otherwise normal session

                ALLOW - Legitimate access confirmed:
                  - Current request matches established baseline patterns (IP, device, time, path)
                  - Similar past events show consistent normal behavior
                  - No anomalous signals detected

                ESCALATE - Insufficient data for any confident judgment:
                  - Context is too ambiguous or incomplete to form either hypothesis
                  - Conflicting signals that cannot be resolved with available data

                CRITICAL RULES:
                - Base your judgment ONLY on explicitly provided data above. Do NOT assume or infer information not present.
                - If SENSITIVE status says "NOT a sensitive resource", do NOT treat it as sensitive.
                - If a field is not mentioned, treat it as unknown/not applicable, NOT as suspicious.
                - Do NOT hallucinate facts. If the context does not mention something, it does not exist.

                Risk signal reference (from EVENT and NETWORK sections):
                  - MfaVerified: false/true (MFA authentication status)
                  - NewDevice/NewSession/NewUser: true (first-time indicators)
                  - FailedLoginAttempts: N (brute-force indicator)
                  - SENSITIVE resource flag (from CURRENT REQUEST section)
                  - Context binding hash MISMATCH (from SESSION TIMELINE)
                  - IMPOSSIBLE TRAVEL DETECTED (from NETWORK section - physically impossible location change)
                  - SIMILAR PAST EVENTS contain factual access records only - judge independently

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

        if (behaviorAnalysis.getBaselineAccessDays() != null) {
            for (Integer day : behaviorAnalysis.getBaselineAccessDays()) {
                if (day != null) {
                    patterns.daySet.add(dayOfWeekLabel(day));
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
        TieredStrategyProperties.Layer1.Prompt promptConfig = tieredStrategyProperties.getLayer1().getPrompt();
        StringBuilder network = new StringBuilder();

        PromptTemplateUtils.appendIpWithValidation(network, event.getSourceIp());

        if (promptConfig.isIncludeRawSessionId()) {
            if (isValidData(event.getSessionId())) {
                String sanitizedSessionId = PromptTemplateUtils.sanitizeUserInput(event.getSessionId());
                network.append("SessionId: ").append(sanitizedSessionId).append("\n");
            } else {
                network.append("SessionId: NOT_PROVIDED [CRITICAL: Cannot verify session]\n");
            }
        }

        Map<String, Object> meta = event.getMetadata();
        if (meta != null) {
            Object country = meta.get("geoCountry");
            Object city = meta.get("geoCity");
            if (country != null || city != null) {
                StringBuilder location = new StringBuilder("Location: ");
                if (city != null) location.append(city);
                if (city != null && country != null) location.append(", ");
                if (country != null) location.append(country);
                Object lat = meta.get("geoLatitude");
                Object lon = meta.get("geoLongitude");
                if (lat instanceof Number && lon instanceof Number) {
                    location.append(String.format(" (%.4f, %.4f)",
                            ((Number) lat).doubleValue(), ((Number) lon).doubleValue()));
                }
                network.append(location).append("\n");
            }

            if (Boolean.TRUE.equals(meta.get("impossibleTravel"))) {
                network.append("ALERT: IMPOSSIBLE TRAVEL DETECTED\n");
                Object prevLoc = meta.get("previousLocation");
                Object distKm = meta.get("travelDistanceKm");
                Object elapsedMin = meta.get("travelElapsedMinutes");
                if (prevLoc != null) {
                    network.append("Previous location: ").append(prevLoc).append("\n");
                }
                if (distKm != null && elapsedMin != null) {
                    network.append(String.format("Distance: %s km in %s minutes (physically impossible)\n",
                            distKm, elapsedMin));
                }
            }
        }

        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();

            if (promptConfig.isIncludeFullUserAgent()) {
                int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer1().getUserAgent();
                String sanitizedUa = PromptTemplateUtils.sanitizeAndTruncate(ua, maxUserAgent);
                network.append("UserAgent: ").append(sanitizedUa).append("\n");
            }

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

    private static String dayOfWeekLabel(int dow) {
        return switch (dow) {
            case 1 -> "Mon";
            case 2 -> "Tue";
            case 3 -> "Wed";
            case 4 -> "Thu";
            case 5 -> "Fri";
            case 6 -> "Sat";
            case 7 -> "Sun";
            default -> "?";
        };
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

        if (baselineContext != null && baselineContext.contains("[NO_PERSONAL_BASELINE]")) {
            return BaselineStatus.NEW_USER;
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

    private String buildMcpSecurityContextSection(SecurityEvent event) {
        if (mcpSecurityContextProvider == null || event == null) {
            return null;
        }

        try {
            McpSecurityContextProvider.McpSecurityContext context = mcpSecurityContextProvider.resolve(event);
            if (context == null || !context.hasEntries()) {
                return null;
            }

            StringBuilder section = new StringBuilder();
            section.append("\n=== MCP SECURITY CONTEXT ===\n");
            appendMcpEntries(section, "Resources", context.resources());
            appendMcpEntries(section, "Prompts", context.prompts());
            return section.toString();
        }
        catch (Exception e) {
            log.error("Failed to resolve MCP security context", e);
            return null;
        }
    }

    private void appendMcpEntries(StringBuilder section, String label,
                                  List<McpSecurityContextProvider.ContextEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return;
        }

        section.append(label).append(":\n");
        for (McpSecurityContextProvider.ContextEntry entry : entries) {
            if (entry == null) {
                continue;
            }

            String name = PromptTemplateUtils.sanitizeAndTruncate(entry.name(), 120);
            String description = PromptTemplateUtils.sanitizeAndTruncate(entry.description(), 200);
            String content = PromptTemplateUtils.sanitizeAndTruncate(entry.content(), 800);

            if (name != null) {
                section.append("- ").append(name);
                if (description != null) {
                    section.append(" (").append(description).append(")");
                }
                section.append(":\n");
            }

            if (content != null) {
                section.append(content).append("\n");
            }
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
        final Set<String> daySet = new HashSet<>();
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
        private Integer[] baselineAccessDays;

        private Long baselineUpdateCount;
        private Double baselineAvgTrustScore;

        private String previousUserAgentBrowser;
        private String currentUserAgentBrowser;

        private Long lastRequestIntervalMs;
        private String previousPath;

        private Boolean contextBindingHashMismatch;
        private Double baselineAvgRequestRate;

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

        public Integer[] getBaselineAccessDays() {
            return baselineAccessDays;
        }

        public void setBaselineAccessDays(Integer[] baselineAccessDays) {
            this.baselineAccessDays = baselineAccessDays;
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

        public Boolean getContextBindingHashMismatch() {
            return contextBindingHashMismatch;
        }

        public void setContextBindingHashMismatch(Boolean contextBindingHashMismatch) {
            this.contextBindingHashMismatch = contextBindingHashMismatch;
        }

        public Double getBaselineAvgRequestRate() {
            return baselineAvgRequestRate;
        }

        public void setBaselineAvgRequestRate(Double baselineAvgRequestRate) {
            this.baselineAvgRequestRate = baselineAvgRequestRate;
        }
    }
}
