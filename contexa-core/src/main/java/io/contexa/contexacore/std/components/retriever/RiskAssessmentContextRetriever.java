package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacore.std.labs.risk.RiskAssessmentVectorService;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class RiskAssessmentContextRetriever extends ContextRetriever {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final BusinessResourceActionRepository resourceActionRepository;
    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final RiskAssessmentVectorService vectorService;

    public RiskAssessmentContextRetriever(
            VectorStore vectorStore,
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            BusinessResourceActionRepository resourceActionRepository,
            ContextRetrieverRegistry contextRetrieverRegistry,
            RiskAssessmentVectorService vectorService) {
        super(vectorStore);
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.resourceActionRepository = resourceActionRepository;
        this.contextRetrieverRegistry = contextRetrieverRegistry;
        this.vectorService = vectorService;
    }

    @PostConstruct
    public void registerSelf() {
        contextRetrieverRegistry.registerRetriever(RiskAssessmentContext.class, this);
            }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {

        if (request.getContext() instanceof RiskAssessmentContext) {
            String contextInfo = retrieveRiskAssessmentContext((AIRequest<RiskAssessmentContext>) request);
            return new ContextRetrievalResult(
                contextInfo, 
                List.of(), 
                Map.of("retrieverType", "RiskAssessmentContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }

        return super.retrieveContext(request);
    }

    public String retrieveRiskAssessmentContext(AIRequest<RiskAssessmentContext> request) {

        try {
            RiskAssessmentContext context = request.getContext();
            StringBuilder contextBuilder = new StringBuilder();

            String historicalRiskPatterns = searchHistoricalRiskPatterns(context);
            if (!historicalRiskPatterns.isEmpty()) {
                contextBuilder.append("## Historical Risk Assessment Analysis\n");
                contextBuilder.append(historicalRiskPatterns).append("\n\n");
            }

            String userBehaviorAnalysis = analyzeUserBehaviorPatterns(context);
            contextBuilder.append("## User Behavior Pattern Analysis\n");
            contextBuilder.append(userBehaviorAnalysis).append("\n\n");

            String resourceRiskProfile = buildResourceRiskProfile(context);
            contextBuilder.append("## Resource Risk Profile\n");
            contextBuilder.append(resourceRiskProfile).append("\n\n");

            String anomalyDetectionResult = performAnomalyDetection(context);
            contextBuilder.append("## Real-time Anomaly Detection Results\n");
            contextBuilder.append(anomalyDetectionResult).append("\n\n");

            String riskAssessmentGuidelines = getRiskAssessmentGuidelines();
            contextBuilder.append("## Risk Assessment Guidelines\n");
            contextBuilder.append(riskAssessmentGuidelines);

            return contextBuilder.toString();

        } catch (Exception e) {
            log.error("Risk assessment context retrieval failed", e);
            return getDefaultRiskAssessmentContext();
        }
    }

    private String searchHistoricalRiskPatterns(RiskAssessmentContext context) {
        try {
            List<Document> similarRisks = vectorService.findSimilarRiskPatterns(
                context.getUserId(),
                context.getResourceIdentifier(),
                5
            );

            if (similarRisks.isEmpty()) {
                return "No historical risk assessment cases found for this user/resource/action combination.";
            }

            return similarRisks.stream()
                .map(doc -> "- " + doc.getText())
                .collect(Collectors.joining("\n"));

        } catch (Exception e) {
            log.error("RAG risk case search failed: {}", e.getMessage());
            return "Error occurred during risk case search.";
        }
    }

    private String analyzeUserBehaviorPatterns(RiskAssessmentContext context) {
        try {
            StringBuilder analysis = new StringBuilder();

            userRepository.findByUsernameWithGroupsRolesAndPermissions(context.getUserId()).ifPresent(user -> {
                analysis.append(String.format("- User: %s (ID: %d)\n", user.getName(), user.getId()));
                analysis.append(String.format("- Account Status: %s\n", "Active"));
                analysis.append(String.format("- Created At: %s\n", user.getCreatedAt()));
                analysis.append(String.format("- MFA Enabled: %s\n", user.isMfaEnabled() ? "Yes" : "No"));
            });

            List<AuditLog> recentLogs = auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(context.getUserId());

            if (!recentLogs.isEmpty()) {
                analysis.append(String.format("- Recent Activity Count: %d\n", recentLogs.size()));

                Map<String, Long> actionStats = recentLogs.stream()
                    .collect(Collectors.groupingBy(
                        auditLog -> auditLog.getAction(),
                        Collectors.counting()
                    ));

                analysis.append("- Action Statistics:\n");
                actionStats.forEach((action, count) ->
                    analysis.append(String.format("  * %s: %d\n", action, count))
                );

                long distinctIpCount = recentLogs.stream()
                    .map(auditLog -> auditLog.getClientIp())
                    .distinct()
                    .count();

                if (distinctIpCount > 3) {
                    analysis.append(String.format("Warning: Access from %d different IPs recently\n", distinctIpCount));
                }

                LocalDateTime oneWeekAgo = LocalDateTime.now().minusWeeks(1);
                long totalWeeklyActivities = auditLogRepository.countByPrincipalNameAndTimeRange(
                    context.getUserId(), oneWeekAgo, LocalDateTime.now());
                analysis.append(String.format("- Total Activity in Last 7 Days: %d\n", totalWeeklyActivities));

            } else {
                analysis.append("- No recent activity records.\n");
            }

            return analysis.toString();

        } catch (Exception e) {
            log.error("User behavior pattern analysis failed: {}", e.getMessage());
            return "Error occurred during user behavior pattern analysis.";
        }
    }

    private String buildResourceRiskProfile(RiskAssessmentContext context) {
        try {
            StringBuilder profile = new StringBuilder();

            profile.append(String.format("- Target Resource: %s\n", context.getResourceIdentifier()));
            profile.append(String.format("- Requested Action: %s\n", context.getActionType()));

            if (context.getResourceIdentifier() != null) {
                long actionCount = resourceActionRepository.countActionsByResourceIdentifier(context.getResourceIdentifier());
                profile.append(String.format("- Allowed Actions Count: %d\n", actionCount));

                resourceActionRepository.getResourceSensitivityLevel(context.getResourceIdentifier())
                    .ifPresent(level -> profile.append(String.format("- Resource Sensitivity: %s\n", level)));

                resourceActionRepository.findByResourceIdentifier(context.getResourceIdentifier())
                    .ifPresentOrElse(
                        resource -> profile.append(String.format("- Resource Type: %s\n", resource.getResourceType())),
                        () -> profile.append("- Resource not registered in the system.\n")
                    );
            }

            if (context.getResourceIdentifier() != null) {
                long totalAccess = auditLogRepository.countByResourceIdentifier(context.getResourceIdentifier());
                long uniqueUsers = auditLogRepository.countDistinctUsersByResourceIdentifier(context.getResourceIdentifier());
                long recentFailures = auditLogRepository.countFailedAttemptsSince(
                    context.getResourceIdentifier(), LocalDateTime.now().minusHours(24));

                profile.append(String.format("- Total Access Count: %d\n", totalAccess));
                profile.append(String.format("- Unique Users Accessed: %d\n", uniqueUsers));
                profile.append(String.format("- Failed Attempts in Last 24h: %d\n", recentFailures));
            }

            if (context.getResourceIdentifier() != null) {
                if (context.getResourceIdentifier().toLowerCase().contains("admin")) {
                    profile.append("Risk Indicator: Admin resource access\n");
                } else if (context.getResourceIdentifier().toLowerCase().contains("user")) {
                    profile.append("Risk Indicator: User resource access\n");
                } else {
                    profile.append("Risk Indicator: General resource access\n");
                }
            }

            return profile.toString();

        } catch (Exception e) {
            log.error("Resource risk profile construction failed: {}", e.getMessage());
            return "Error occurred during resource risk profile construction.";
        }
    }

    private String performAnomalyDetection(RiskAssessmentContext context) {
        StringBuilder detection = new StringBuilder();
        List<String> anomalyIndicators = new ArrayList<>();

        if (context.getRemoteIp() != null) {
            if (context.getRemoteIp().startsWith("10.") ||
                context.getRemoteIp().startsWith("192.168.") ||
                context.getRemoteIp().startsWith("172.")) {
                detection.append("- Network: Internal network access\n");
            } else {
                detection.append("- Network: External network access from ").append(context.getRemoteIp()).append("\n");
                anomalyIndicators.add("External network access");
            }
        }

        int currentHour = LocalDateTime.now().getHour();
        if (currentHour >= 18 || currentHour <= 8) {
            detection.append("- Time: After-hours access attempt\n");
            anomalyIndicators.add("After-hours access");
        } else {
            detection.append("- Time: Normal business hours access\n");
        }

        if (!anomalyIndicators.isEmpty()) {
            detection.append("- Anomaly Indicators: ").append(String.join(", ", anomalyIndicators)).append("\n");
        }

        return detection.toString();
    }

    private String getRiskAssessmentGuidelines() {
        return """
        ### Action Decision Framework
        Based on the above information, determine the appropriate action:

        **ALLOW** - Grant access when:
        - User behavior matches historical patterns
        - Access from known network location
        - Normal business hours access
        - No anomaly indicators detected

        **CHALLENGE** - Require additional verification when:
        - Minor deviations from normal patterns
        - Access from new but legitimate location
        - Slightly unusual access time
        - Resource sensitivity requires verification

        **BLOCK** - Deny access when:
        - Multiple anomaly indicators detected
        - Access from suspicious network
        - Pattern indicates potential threat
        - Failed authentication history present

        **ESCALATE** - Require human analyst review when:
        - Conflicting indicators present
        - High-value resource access with anomalies
        - Potential insider threat indicators
        - Unprecedented access pattern

        ### Required Output
        - Selected Action (ALLOW/CHALLENGE/BLOCK/ESCALATE)
        - Confidence Level (HIGH/MEDIUM/LOW)
        - Key factors that influenced the decision
        - Recommended follow-up actions if any
        """;
    }

    private String getDefaultRiskAssessmentContext() {
        return """
        ## Default Risk Assessment Context

        Error occurred while constructing risk assessment context.
        Applying default security policy.

        Recommended Action: CHALLENGE
        - Request additional verification
        - Log detailed audit information
        - Escalate if verification fails
        """;
    }

    private static class RiskQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;

        public RiskQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }

        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }

            String prompt = String.format("""
                Optimize the search query for risk assessment:

                Original query: %s

                Optimization guidelines:
                1. Include security threat and anomalous behavior related terms
                2. Consider user behavior patterns and access frequency
                3. Reflect resource sensitivity and importance
                4. Include contextual information such as time, IP address
                5. Add Zero Trust security model related keywords

                Return only the optimized query.
                """, originalQuery.text());

            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();

            return new Query(transformedText);
        }
    }
} 