package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;


@Slf4j
public class SecurityPromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;
    
    private final BaselineLearningService baselineLearningService;

    @Autowired
    public SecurityPromptTemplate(
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties,
            @Autowired(required = false) BaselineLearningService baselineLearningService) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
        this.baselineLearningService = baselineLearningService;
    }

    
    public String buildPrompt(SecurityEvent event,
                               SessionContext sessionContext,
                               BehaviorAnalysis behaviorAnalysis,
                               List<Document> relatedDocuments) {

        
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);

        
        Optional<String> payloadSummary = summarizePayload(decodedPayload.orElse(null));

        String networkSection = buildNetworkSection(event);

        
        String baselineContextForQuality = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event, baselineContextForQuality);

        
        String userId = (sessionContext != null) ? sessionContext.getUserId() : null;

        
        String baselineContext = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
        BaselineStatus baselineStatus = determineBaselineStatus(behaviorAnalysis, baselineContext);

        
        
        
        
        StringBuilder baselineSectionBuilder = new StringBuilder();

        if (baselineStatus == BaselineStatus.NEW_USER) {
            baselineSectionBuilder.append("=== BASELINE ===\n");
            baselineSectionBuilder.append("STATUS: ").append(baselineStatus.getStatusLabel()).append("\n");
            baselineSectionBuilder.append("IMPACT: ").append(baselineStatus.getImpactDescription()).append("\n");

            
            
            
            baselineSectionBuilder.append("\nZERO TRUST WARNING:\n");
            baselineSectionBuilder.append("- This is a new user without established behavioral baseline.\n");
            baselineSectionBuilder.append("- Cannot verify if this is the legitimate user or an attacker.\n");
            baselineSectionBuilder.append("- confidence MUST be <= 0.5 due to insufficient historical data.\n");
            baselineSectionBuilder.append("- riskScore should be >= 0.5 for unverified users.\n");
        }

        String baselineSection = baselineSectionBuilder.toString();

        
        
        
        
        StringBuilder relatedContextBuilder = new StringBuilder();
        Set<String> detectedOSSet = new HashSet<>();
        Set<String> detectedIPSet = new HashSet<>();
        Set<String> detectedHourSet = new HashSet<>();
        Set<String> detectedUASet = new HashSet<>();
        Set<String> detectedPathSet = new HashSet<>();
        int maxRagDocs = tieredStrategyProperties.getLayer1().getPrompt().getMaxRagDocuments();
        int maxDocs = (relatedDocuments != null) ? Math.min(maxRagDocs, relatedDocuments.size()) : 0;
        int addedDocs = 0;
        int filteredDocs = 0;
        for (int i = 0; i < maxDocs && addedDocs < maxRagDocs; i++) {
            Document doc = relatedDocuments.get(i);

            
            
            Map<String, Object> docMetadata = doc.getMetadata();
            if (userId != null) {
                Object docUserId = docMetadata.get("userId");
                if (docUserId != null && !userId.equals(docUserId.toString())) {
                    filteredDocs++;
                    log.debug("[SecurityPromptTemplate] 다른 사용자 문서 제외: docUser={}, currentUser={}",
                        docUserId, userId);
                    continue;  
                }
            }

            String content = doc.getText();
            if (content != null && !content.isBlank()) {
                if (addedDocs > 0) {
                    relatedContextBuilder.append("\n");
                }

                String docMeta = buildDocumentMetadata(doc, addedDocs + 1);
                int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getRagDocument();
                String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);

                
                
                Object userAgentOS = docMetadata.get("userAgentOS");
                if (userAgentOS != null && !userAgentOS.toString().isEmpty()) {
                    detectedOSSet.add(userAgentOS.toString());
                }

                
                Object sourceIp = docMetadata.get("sourceIp");
                if (sourceIp != null && !sourceIp.toString().isEmpty()) {
                    String ipStr = sourceIp.toString();
                    if (ipStr.contains("127.0.0.1") || ipStr.contains("0:0:0:0:0:0:0:1")) {
                        detectedIPSet.add("loopback");
                    } else {
                        detectedIPSet.add(ipStr);
                    }
                }

                
                Object hour = docMetadata.get("hour");
                if (hour != null) {
                    detectedHourSet.add(hour.toString());
                }

                
                Object userAgentBrowser = docMetadata.get("userAgentBrowser");
                if (userAgentBrowser != null && !userAgentBrowser.toString().isEmpty()) {
                    detectedUASet.add(userAgentBrowser.toString());
                }

                
                Object requestPath = docMetadata.get("requestPath");
                if (requestPath != null && !requestPath.toString().isEmpty()) {
                    String pathStr = requestPath.toString();
                    
                    int secondSlash = pathStr.indexOf('/', 1);
                    int thirdSlash = secondSlash > 0 ? pathStr.indexOf('/', secondSlash + 1) : -1;
                    if (thirdSlash > 0) {
                        detectedPathSet.add(pathStr.substring(0, thirdSlash) + "/*");
                    } else {
                        detectedPathSet.add(pathStr);
                    }
                }

                addedDocs++;
            }
        }

        
        
        
        if (userId != null && baselineLearningService != null) {
            BaselineVector baseline = baselineLearningService.getBaseline(userId);
            if (baseline != null) {
                
                if (baseline.getNormalIpRanges() != null) {
                    for (String ip : baseline.getNormalIpRanges()) {
                        if (ip != null && !ip.isEmpty()) {
                            detectedIPSet.add(ip);
                        }
                    }
                }
                
                if (baseline.getNormalAccessHours() != null) {
                    for (Integer hour : baseline.getNormalAccessHours()) {
                        if (hour != null) {
                            detectedHourSet.add(hour.toString());
                        }
                    }
                }
                
                if (baseline.getNormalUserAgents() != null) {
                    for (String ua : baseline.getNormalUserAgents()) {
                        if (ua != null && !ua.isEmpty()) {
                            detectedUASet.add(ua);
                        }
                    }
                }
                
                if (baseline.getFrequentPaths() != null) {
                    for (String path : baseline.getFrequentPaths()) {
                        if (path != null && !path.isEmpty()) {
                            detectedPathSet.add(path);
                        }
                    }
                }
                
                if (baseline.getNormalOperatingSystems() != null) {
                    for (String os : baseline.getNormalOperatingSystems()) {
                        if (os != null && !os.isEmpty()) {
                            detectedOSSet.add(os);
                        }
                    }
                }
                log.debug("[SecurityPromptTemplate][AI Native v11.6] Baseline 데이터 병합: userId={}, " +
                    "IPs={}, Hours={}, UAs={}, Paths={}, OSs={}",
                    userId,
                    baseline.getNormalIpRanges() != null ? baseline.getNormalIpRanges().length : 0,
                    baseline.getNormalAccessHours() != null ? baseline.getNormalAccessHours().length : 0,
                    baseline.getNormalUserAgents() != null ? baseline.getNormalUserAgents().length : 0,
                    baseline.getFrequentPaths() != null ? baseline.getFrequentPaths().length : 0,
                    baseline.getNormalOperatingSystems() != null ? baseline.getNormalOperatingSystems().length : 0);
            }
        }

        if (filteredDocs > 0) {
            log.info("[SecurityPromptTemplate][AI Native v7.1] userId 필터링: {}개 문서 제외, {}개 포함",
                filteredDocs, addedDocs);
        }
        boolean hasRelatedDocs = relatedContextBuilder.length() > 0;
        String relatedContext = hasRelatedDocs ? relatedContextBuilder.toString() : null;

        
        
        
        
        
        StringBuilder prompt = new StringBuilder();
        prompt.append("""
            You are a Zero Trust security analyst AI.
            Analyze the security context and respond with ONLY a JSON object.
            No explanation, no markdown.

            """);

        
        prompt.append("=== EVENT ===\n");
        if (isValidData(event.getEventId())) {
            prompt.append("EventId: ").append(PromptTemplateUtils.sanitizeUserInput(event.getEventId())).append("\n");
        }
        if (event.getTimestamp() != null) {
            prompt.append("Timestamp: ").append(event.getTimestamp()).append("\n");

            
            prompt.append("CurrentHour: ").append(event.getTimestamp().getHour()).append("\n");
        }
        if (userId != null) {
            prompt.append("User: ").append(PromptTemplateUtils.sanitizeUserInput(userId)).append("\n");
        }

        
        Map<String, Object> metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            Object httpMethod = metadataObj.get("httpMethod");
            if (httpMethod != null && !httpMethod.toString().isEmpty()) {
                prompt.append("HttpMethod: ").append(httpMethod).append("\n");
            }
            
            appendMetadataIfPresent(prompt, metadataObj, "auth.failure_count", "FailureCount");
        }

        
        String eventPath = extractRequestPath(event);
        if (eventPath != null && !eventPath.isEmpty()) {
            prompt.append("Path: ").append(PromptTemplateUtils.sanitizeUserInput(eventPath)).append("\n");
        }

        
        
        
        String currentOS = extractOSFromUserAgent(event.getUserAgent());
        String currentIP = normalizeIP(event.getSourceIp());
        
        String currentHour = event.getTimestamp() != null
            ? String.valueOf(event.getTimestamp().getHour())
            : null;
        String currentUA = extractUASignature(event.getUserAgent());

        prompt.append("\n=== CURRENT REQUEST ===\n");
        prompt.append("OS: ").append(currentOS != null ? currentOS : "N/A").append("\n");
        prompt.append("IP: ").append(currentIP != null ? currentIP : "N/A").append("\n");
        prompt.append("Hour: ").append(currentHour != null ? currentHour : "N/A").append("\n");
        prompt.append("UA: ").append(currentUA != null ? currentUA : "N/A").append("\n");

        
        
        String knownOSStr = !detectedOSSet.isEmpty() ? String.join(", ", detectedOSSet) : "N/A";
        String knownIPStr = !detectedIPSet.isEmpty() ? String.join(", ", normalizeIPSet(detectedIPSet)) : "N/A";
        String knownHourStr = !detectedHourSet.isEmpty() ? String.join(", ", detectedHourSet) : "N/A";
        String knownUAStr = !detectedUASet.isEmpty() ? String.join(", ", detectedUASet) : "N/A";
        String knownPathStr = !detectedPathSet.isEmpty() ? String.join(", ", detectedPathSet) : "N/A";

        prompt.append("\n=== KNOWN PATTERNS ===\n");
        prompt.append("OS: [").append(knownOSStr).append("]\n");
        prompt.append("IP: [").append(knownIPStr).append("]\n");
        prompt.append("Hour: [").append(knownHourStr).append("]\n");
        prompt.append("UA: [").append(knownUAStr).append("]\n");
        prompt.append("Path: [").append(knownPathStr).append("]\n");

        
        
        
        prompt.append("\n=== SIGNAL COMPARISON ===\n");
        prompt.append("For OS, IP, Hour, UA - check if CURRENT value exists in KNOWN list:\n");
        prompt.append("- IN list = MATCH (established pattern)\n");
        prompt.append("- NOT in list = MISMATCH (new/unusual)\n");
        prompt.append("Example: CURRENT 'Android' in KNOWN [Windows, Android] = MATCH\n");
        prompt.append("Signal context (each mismatch is significant, not minor):\n");
        prompt.append("- IP mismatch: New network location (security-sensitive)\n");
        prompt.append("- OS mismatch: New device type (potential account compromise)\n");
        prompt.append("- Hour mismatch: Unusual access time (behavior anomaly)\n");
        prompt.append("- UA mismatch: New browser/client (credential sharing risk)\n");
        prompt.append("Risk assessment by mismatch count:\n");
        prompt.append("- 0 = All patterns match (low risk)\n");
        prompt.append("- 1 = Single deviation (evaluate context)\n");
        prompt.append("- 2+ = Multiple deviations (elevated risk)\n");

        
        prompt.append("\n=== NETWORK ===\n");
        prompt.append(networkSection).append("\n");

        
        if (payloadSummary.isPresent()) {
            prompt.append("\n=== PAYLOAD ===\n");
            prompt.append(payloadSummary.get()).append("\n");
        }

        
        prompt.append("\n=== SESSION ===\n");
        if (sessionContext != null) {
            
            Integer sessionAge = sessionContext.getSessionAgeMinutes();
            if (sessionAge != null) {
                prompt.append("SessionAge: ").append(sessionAge).append(" minutes\n");
            }
            Integer requestCount = sessionContext.getRequestCount();
            if (requestCount != null && requestCount > 0) {
                prompt.append("RequestCount: ").append(requestCount).append("\n");
            }

            
            
            

            
            String authMethod = sessionContext.getAuthMethod();
            if (authMethod != null && !authMethod.isEmpty()) {
                String sanitizedAuthMethod = PromptTemplateUtils.sanitizeUserInput(authMethod);
                prompt.append("AuthMethod: ").append(sanitizedAuthMethod).append("\n");
            }
            
            
            appendZeroTrustSignals(prompt, event, behaviorAnalysis, baselineStatus);
        } else {
            
            prompt.append("Session context not available (see DATA AVAILABILITY)\n");
        }

        
        
        if (behaviorAnalysis != null) {
            String previousSessionOS = behaviorAnalysis.getPreviousUserAgentOS();
            String currentSessionOS = behaviorAnalysis.getCurrentUserAgentOS();

            if (previousSessionOS != null && currentSessionOS != null && !previousSessionOS.equals(currentSessionOS)) {
                prompt.append("\n=== SESSION DEVICE CHANGE ===\n");
                prompt.append("OBSERVATION: Same SessionId with different device fingerprint detected.\n");
                prompt.append("Previous OS: ").append(previousSessionOS).append("\n");
                prompt.append("Current OS: ").append(currentSessionOS).append("\n");
                prompt.append("OS Transition: ").append(previousSessionOS).append(" -> ").append(currentSessionOS).append("\n");
                
            }
        }

        
        prompt.append("\n=== BEHAVIOR ===\n");
        if (behaviorAnalysis != null) {
            List<String> similarEvents = behaviorAnalysis.getSimilarEvents();
            if (similarEvents != null && !similarEvents.isEmpty()) {
                int maxSimilarEvents = tieredStrategyProperties.getLayer1().getPrompt().getMaxSimilarEvents();
                int maxEvents = Math.min(maxSimilarEvents, similarEvents.size());
                prompt.append("SimilarEvents Detail:\n");
                for (int i = 0; i < maxEvents; i++) {
                    String sanitizedEvent = PromptTemplateUtils.sanitizeUserInput(similarEvents.get(i));
                    prompt.append("  ").append(i + 1).append(". ").append(sanitizedEvent).append("\n");
                }
            } else {
                
                prompt.append("No similar events in history (see DATA AVAILABILITY)\n");
            }
        } else {
            
            prompt.append("Behavior analysis not available (see DATA AVAILABILITY)\n");
        }

        
        
        
        
        prompt.append("\n=== RELATED CONTEXT ===\n");
        prompt.append("Historical events for this user:\n\n");
        if (hasRelatedDocs) {
            String sanitizedContext = PromptTemplateUtils.sanitizeUserInput(relatedContext);
            prompt.append(sanitizedContext).append("\n");
        } else {
            
            prompt.append("No related context found (see DATA AVAILABILITY)\n");
        }

        

        
        if (baselineStatus == BaselineStatus.NEW_USER) {
            prompt.append("\n").append(baselineSection);
        }

        
        
        
        
        prompt.append("""

            === DECISION ===

            RESPOND WITH JSON ONLY:
            {"riskScore":<0.0-1.0>,"confidence":<0.3-0.95>,"action":"<ACTION>","reasoning":"<analysis>","mitre":"<TAG|none>"}

            ACTIONS:
            - ALLOW: Consistent with known patterns (low risk)
            - CHALLENGE: Needs verification (moderate risk)
            - BLOCK: Unauthorized access indicators (high risk)
            - ESCALATE: Requires human review (critical risk)

            MITRE (if applicable): T1078, T1110, T1185

            """);

        return prompt.toString();
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
            @SuppressWarnings("unchecked")
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

    
    private String buildDocumentMetadata(Document doc, int docIndex) {
        StringBuilder meta = new StringBuilder();
        meta.append("[Doc").append(docIndex);

        Map<String, Object> metadata = doc.getMetadata();
        if (metadata != null) {
            
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

            
            
            
            
        }

        meta.append("]");
        return meta.toString();
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

    
    private String buildNetworkSection(SecurityEvent event) {
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

    
    private boolean isValidData(String value) {
        return PromptTemplateUtils.isValidData(value);
    }

    
    private String extractOSFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        
        if (userAgent.contains("Android")) {
            return "Android";
        }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iPod")) {
            return "iOS";
        }

        
        if (userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Mac OS") || userAgent.contains("Macintosh")) {
            return "Mac";
        }
        if (userAgent.contains("Linux") && !userAgent.contains("Android")) {
            return "Linux";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }

        return null;
    }

    
    private String normalizeIP(String ip) {
        if (ip == null || ip.isEmpty()) {
            return ip;
        }

        String trimmed = ip.trim().toLowerCase();

        
        if (trimmed.equals("loopback") ||
            trimmed.equals("::1") ||
            trimmed.equals("0:0:0:0:0:0:0:1") ||
            trimmed.equals("127.0.0.1") ||
            trimmed.equals("localhost")) {
            return "loopback";
        }

        return ip;
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

    
    private String extractUASignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser";
        }

        
        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/");
        } else if (userAgent.contains("Edg/")) {
            String browser = extractBrowserVersion(userAgent, "Edg/");
            return browser.replace("Edg", "Edge");
        } else if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/");
        } else if (userAgent.contains("Safari/") && !userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            String browser = extractBrowserVersion(userAgent, "Version/");
            return browser.replace("Version", "Safari");
        }

        return "Browser";
    }

    
    private String extractBrowserVersion(String userAgent, String prefix) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return "Browser";

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return "Browser";

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) return "Browser";

        String version = userAgent.substring(start, end);
        String browserName = prefix.replace("/", "");
        return browserName + "/" + version;
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

    
    private boolean matchesPathPattern(String currentPath, Set<String> knownPaths) {
        if (currentPath == null || knownPaths == null || knownPaths.isEmpty()) {
            return false;
        }

        for (String knownPath : knownPaths) {
            
            if (currentPath.equals(knownPath)) {
                return true;
            }

            
            if (knownPath.endsWith("/*")) {
                String prefix = knownPath.substring(0, knownPath.length() - 1); 
                if (currentPath.startsWith(prefix)) {
                    return true;
                }
            }

            
            if (currentPath.startsWith(knownPath) || knownPath.startsWith(currentPath)) {
                return true;
            }
        }

        return false;
    }

    
    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions;

        
        private Integer sessionAgeMinutes;    
        private Integer requestCount;         

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public List<String> getRecentActions() { return recentActions != null ? recentActions : List.of(); }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        
        public Integer getSessionAgeMinutes() { return sessionAgeMinutes; }
        public void setSessionAgeMinutes(Integer sessionAgeMinutes) { this.sessionAgeMinutes = sessionAgeMinutes; }

        public Integer getRequestCount() { return requestCount; }
        public void setRequestCount(Integer requestCount) { this.requestCount = requestCount; }
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

        public List<String> getSimilarEvents() { return similarEvents != null ? similarEvents : List.of(); }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }

        
        public Boolean getIsNewUser() { return isNewUser; }
        public void setIsNewUser(Boolean isNewUser) { this.isNewUser = isNewUser; }

        public Boolean getIsNewSession() { return isNewSession; }
        public void setIsNewSession(Boolean isNewSession) { this.isNewSession = isNewSession; }

        public Boolean getIsNewDevice() { return isNewDevice; }
        public void setIsNewDevice(Boolean isNewDevice) { this.isNewDevice = isNewDevice; }

        

        
        public String getPreviousUserAgentOS() { return previousUserAgentOS; }
        public void setPreviousUserAgentOS(String previousUserAgentOS) { this.previousUserAgentOS = previousUserAgentOS; }

        public String getCurrentUserAgentOS() { return currentUserAgentOS; }
        public void setCurrentUserAgentOS(String currentUserAgentOS) { this.currentUserAgentOS = currentUserAgentOS; }
    }
}
