package io.contexa.contexacore.simulation.publisher;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.*;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent.AuthorizationResult;
import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.injector.EventInjectionService;
import io.contexa.contexacore.simulation.generator.ZeroTrustEventGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Simulation Event Publisher - Bridge Pattern Implementation
 *
 * Unifies event publishing across Spring ApplicationEvent and Kafka/Redis systems.
 * Ensures all attack simulations are properly detected by the autonomous security system.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SimulationEventPublisher {

    private final ApplicationEventPublisher applicationEventPublisher;
    private final EventInjectionService eventInjectionService;
    private final ZeroTrustEventGenerator zeroTrustEventGenerator;

    // Event tracking
    private final AtomicLong authSuccessEvents = new AtomicLong(0);
    private final AtomicLong authFailureEvents = new AtomicLong(0);
    private final AtomicLong authDecisionEvents = new AtomicLong(0);
    private final AtomicLong securityEvents = new AtomicLong(0);

    /**
     * Publish authentication failure event for brute force, credential stuffing, etc.
     */
    public void publishAuthenticationFailure(AttackResult attackResult,
                                             String username,
                                             String sourceIp,
                                             String failureReason,
                                             int failureCount) {

        log.info("Publishing authentication failure: user={}, ip={}, reason={}",
                username, sourceIp, failureReason);

        // Determine attack indicators based on attack type
        boolean bruteForceDetected = attackResult.getAttackType() == AttackResult.AttackType.BRUTE_FORCE;
        boolean credentialStuffingDetected = attackResult.getAttackType() == AttackResult.AttackType.CREDENTIAL_STUFFING;

        // Build attack indicators map
        Map<String, Object> attackIndicators = new HashMap<>();
        attackIndicators.put("attackType", attackResult.getAttackType().toString());
        attackIndicators.put("attackId", attackResult.getAttackId());
        attackIndicators.put("campaignId", attackResult.getCampaignId());
        attackIndicators.put("riskScore", attackResult.getRiskScore());
        attackIndicators.put("attackVector", attackResult.getAttackVector());

        // Create authentication failure event
        AuthenticationFailureEvent failureEvent = AuthenticationFailureEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .userId(username)
            .username(username)
            .sessionId(UUID.randomUUID().toString())
            .eventTimestamp(LocalDateTime.now())
            .sourceIp(sourceIp)
            .userAgent("SimulationClient/1.0")
            .deviceId("simulation-device-" + UUID.randomUUID().toString().substring(0, 8))
            .failureReason(failureReason)
            .exceptionClass("SimulatedAuthenticationException")
            .exceptionMessage(failureReason)
            .failureCount(failureCount)
            .authenticationType("PASSWORD")
            .attemptedMethod("POST /api/login")
            .riskScore(attackResult.getRiskScore())
            .attackIndicators(attackIndicators)
            .bruteForceDetected(bruteForceDetected)
            .credentialStuffingDetected(credentialStuffingDetected)
            .metadata(buildMetadata(attackResult))
            .build();

        // Publish Spring application event
        applicationEventPublisher.publishEvent(failureEvent);
        authFailureEvents.incrementAndGet();

        // Also publish as SecurityEvent to Kafka/Redis
        publishSecurityEvent(convertToSecurityEvent(failureEvent, attackResult));

        log.debug("Authentication failure event published: eventId={}", failureEvent.getEventId());
    }

    /**
     * Publish authentication success event (for session hijacking, anomaly detection)
     */
    public void publishAuthenticationSuccess(AttackResult attackResult,
                                            String username,
                                            String sourceIp,
                                            String sessionId,
                                            boolean anomalyDetected,
                                            double trustScore) {

        log.info("Publishing authentication success: user={}, ip={}, anomaly={}",
                username, sourceIp, anomalyDetected);

        // Build risk indicators
        Map<String, Object> riskIndicators = new HashMap<>();
        riskIndicators.put("anomalyDetected", anomalyDetected);
        riskIndicators.put("attackType", attackResult.getAttackType().toString());
        riskIndicators.put("impossibleTravel", attackResult.getAttackType() == AttackResult.AttackType.IMPOSSIBLE_TRAVEL);
        riskIndicators.put("sessionHijacking", attackResult.getAttackType() == AttackResult.AttackType.SESSION_HIJACKING);

        // Create authentication success event
        AuthenticationSuccessEvent successEvent = AuthenticationSuccessEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .userId(username)
            .username(username)
            .sessionId(sessionId != null ? sessionId : UUID.randomUUID().toString())
            .eventTimestamp(LocalDateTime.now())
            .sourceIp(sourceIp)
            .userAgent("SimulationClient/1.0")
            .deviceId("simulation-device-" + UUID.randomUUID().toString().substring(0, 8))
            .authenticationType("PASSWORD")
            .mfaCompleted(false)
            .mfaMethod(null)
            .trustScore(trustScore)
            .anomalyDetected(anomalyDetected)
            .riskIndicators(riskIndicators)
            .lastLoginTime(LocalDateTime.now().minusHours(24))
            .previousSessionId(UUID.randomUUID().toString())
            .sessionContext(new HashMap<>())
            .metadata(buildMetadata(attackResult))
            .build();

        // Publish Spring application event
        applicationEventPublisher.publishEvent(successEvent);
        authSuccessEvents.incrementAndGet();

        // Also publish as SecurityEvent to Kafka/Redis
        publishSecurityEvent(convertToSecurityEvent(successEvent, attackResult));

        log.debug("Authentication success event published: eventId={}", successEvent.getEventId());
    }

    /**
     * Publish authorization decision event for all authorization and behavioral attacks
     */
    public void publishAuthorizationDecision(AttackResult attackResult,
                                            String userId,
                                            String resource,
                                            String action,
                                            boolean granted,
                                            String reason) {

        log.info("Publishing authorization decision: user={}, resource={}, action={}, granted={}",
                userId, resource, action, granted);

        // Build comprehensive metadata
        Map<String, Object> metadata = buildMetadata(attackResult);

        // Add attack-specific information
        switch (attackResult.getAttackType()) {
            case PRIVILEGE_ESCALATION:
                metadata.put("escalationAttempt", true);
                metadata.put("targetPrivilege", "ADMIN");
                metadata.put("currentPrivilege", "USER");
                break;

            case IDOR:
                metadata.put("idorAttempt", true);
                metadata.put("unauthorizedResource", resource);
                metadata.put("resourceOwner", "other-user");
                break;

            case API_BYPASS:
                metadata.put("apiBypassAttempt", true);
                metadata.put("bypassMethod", "parameter_manipulation");
                break;

            case IMPOSSIBLE_TRAVEL:
                metadata.put("impossibleTravel", true);
                metadata.put("location1", "Seoul, Korea");
                metadata.put("location2", "New York, USA");
                metadata.put("timeDifference", "30 minutes");
                metadata.put("distance", "10965 km");
                break;

            case VELOCITY_ATTACK:
                metadata.put("velocityAttack", true);
                metadata.put("transactionCount", attackResult.getAttemptCount());
                metadata.put("timeWindow", "1 minute");
                metadata.put("velocityThreshold", "10 tx/min");
                break;

            case BEHAVIORAL_ANOMALY:
                metadata.put("behavioralAnomaly", true);
                metadata.put("anomalyScore", attackResult.getRiskScore());
                metadata.put("expectedBehavior", "normal_pattern");
                metadata.put("actualBehavior", "anomalous_pattern");
                break;

            case SEQUENCE_BREAKING:
                metadata.put("sequenceBreaking", true);
                metadata.put("expectedSequence", "login->dashboard->action");
                metadata.put("actualSequence", "direct->action");
                break;

            default:
                metadata.put("genericAttack", true);
                break;
        }

        // Create authorization decision event
        AuthorizationDecisionEvent decisionEvent = AuthorizationDecisionEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .timestamp(Instant.now())
            .principal(userId)
            .userId(userId)
            .resource(resource)
            .action(action)
            .result(granted ? AuthorizationDecisionEvent.AuthorizationResult.ALLOWED : AuthorizationDecisionEvent.AuthorizationResult.DENIED)
            .reason(reason)
            .clientIp(attackResult.getSourceIp() != null ? attackResult.getSourceIp() : generateRandomIP())
            .userAgent("SimulationClient/1.0")
            .requestId(UUID.randomUUID().toString())
            .sessionId(UUID.randomUUID().toString())
            .riskScore(attackResult.getRiskScore())
            .metadata(metadata)
            .build();

        // Publish Spring application event
        applicationEventPublisher.publishEvent(decisionEvent);
        authDecisionEvents.incrementAndGet();

        // Also publish as SecurityEvent to Kafka/Redis
        publishSecurityEvent(convertToSecurityEvent(decisionEvent, attackResult));

        log.debug("Authorization decision event published: eventId={}", decisionEvent.getEventId());
    }

    /**
     * Publish security event directly to Kafka/Redis
     */
    public void publishSecurityEvent(SecurityEvent event) {
        try {
            // Use EventInjectionService for Kafka/Redis publishing
            CompletableFuture<Boolean> future = eventInjectionService.injectEvent(event);

            future.thenAccept(success -> {
                if (success) {
                    securityEvents.incrementAndGet();
                    log.debug("Security event published to Kafka/Redis: {}", event.getEventId());
                } else {
                    log.error("Failed to publish security event to Kafka/Redis: {}", event.getEventId());
                }
            });

        } catch (Exception e) {
            log.error("Error publishing security event", e);
        }
    }

    /**
     * Convert AuthenticationFailureEvent to SecurityEvent
     */
    private SecurityEvent convertToSecurityEvent(AuthenticationFailureEvent authEvent, AttackResult attackResult) {
        return SecurityEvent.builder()
            .eventId(authEvent.getEventId())
            .eventType(determineEventType(attackResult))
            .severity(determineSeverity(attackResult))
            .sourceIp(authEvent.getSourceIp())
            .targetSystem("authentication-service")
            .description(String.format("%s attack: %s",
                attackResult.getAttackType(), authEvent.getFailureReason()))
            .riskScore(attackResult.getRiskScore())
            .confidenceScore(0.95)
            .timestamp(authEvent.getEventTimestamp())
            .details(convertToDetails(authEvent, attackResult))
            .build();
    }

    /**
     * Convert AuthenticationSuccessEvent to SecurityEvent
     */
    private SecurityEvent convertToSecurityEvent(AuthenticationSuccessEvent authEvent, AttackResult attackResult) {
        return SecurityEvent.builder()
            .eventId(authEvent.getEventId())
            .eventType(authEvent.isAnomalyDetected() ?
                SecurityEvent.EventType.SUSPICIOUS_ACTIVITY : SecurityEvent.EventType.AUTH_SUCCESS)
            .severity(authEvent.isAnomalyDetected() ?
                SecurityEvent.Severity.HIGH : SecurityEvent.Severity.LOW)
            .sourceIp(authEvent.getSourceIp())
            .targetSystem("authentication-service")
            .description(String.format("Authentication success with %s",
                authEvent.isAnomalyDetected() ? "anomaly detected" : "normal pattern"))
            .riskScore(attackResult.getRiskScore())
            .confidenceScore(authEvent.getTrustScore())
            .timestamp(authEvent.getEventTimestamp())
            .details(convertToDetails(authEvent, attackResult))
            .build();
    }

    /**
     * Convert AuthorizationDecisionEvent to SecurityEvent
     */
    private SecurityEvent convertToSecurityEvent(AuthorizationDecisionEvent authEvent, AttackResult attackResult) {
        boolean isGranted = authEvent.getResult() == AuthorizationResult.ALLOWED;
        return SecurityEvent.builder()
            .eventId(authEvent.getEventId())
            .eventType(isGranted ?
                SecurityEvent.EventType.AUTH_SUCCESS : SecurityEvent.EventType.ACCESS_CONTROL_VIOLATION)
            .severity(determineSeverity(attackResult))
            .sourceIp(authEvent.getClientIp())
            .targetSystem("authorization-service")
            .description(String.format("%s: %s access to %s",
                attackResult.getAttackType(),
                isGranted ? "granted" : "denied",
                authEvent.getResource()))
            .riskScore(attackResult.getRiskScore())
            .confidenceScore(0.90)
            .timestamp(LocalDateTime.now())
            .details(convertToDetails(authEvent, attackResult))
            .build();
    }

    /**
     * Determine SecurityEvent.EventType based on attack type
     */
    private SecurityEvent.EventType determineEventType(AttackResult attackResult) {
        switch (attackResult.getAttackType()) {
            case BRUTE_FORCE:
                return SecurityEvent.EventType.BRUTE_FORCE;
            case CREDENTIAL_STUFFING:
                return SecurityEvent.EventType.CREDENTIAL_STUFFING;
            case PRIVILEGE_ESCALATION:
                return SecurityEvent.EventType.PRIVILEGE_ESCALATION;
            case SESSION_HIJACKING:
                return SecurityEvent.EventType.SUSPICIOUS_ACTIVITY;
            case IMPOSSIBLE_TRAVEL:
                return SecurityEvent.EventType.ANOMALY_DETECTED;
            case API_BYPASS:
            case IDOR:
                return SecurityEvent.EventType.ACCESS_CONTROL_VIOLATION;
            default:
                return SecurityEvent.EventType.SUSPICIOUS_ACTIVITY;
        }
    }

    /**
     * Determine severity based on attack result
     */
    private SecurityEvent.Severity determineSeverity(AttackResult attackResult) {
        double riskScore = attackResult.getRiskScore();
        if (riskScore >= 0.8) return SecurityEvent.Severity.CRITICAL;
        if (riskScore >= 0.6) return SecurityEvent.Severity.HIGH;
        if (riskScore >= 0.4) return SecurityEvent.Severity.MEDIUM;
        if (riskScore >= 0.2) return SecurityEvent.Severity.LOW;
        return SecurityEvent.Severity.INFO;
    }

    /**
     * Build metadata map from attack result
     */
    private Map<String, Object> buildMetadata(AttackResult attackResult) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("attackId", attackResult.getAttackId());
        metadata.put("campaignId", attackResult.getCampaignId());
        metadata.put("attackType", attackResult.getAttackType().toString());
        metadata.put("attackName", attackResult.getAttackName());
        metadata.put("targetUser", attackResult.getTargetUser());
        metadata.put("targetResource", attackResult.getTargetResource());
        metadata.put("attemptCount", attackResult.getAttemptCount());
        metadata.put("riskScore", attackResult.getRiskScore());
        metadata.put("riskLevel", attackResult.getRiskLevel());
        metadata.put("successful", attackResult.isSuccessful());
        metadata.put("detected", attackResult.isDetected());
        metadata.put("blocked", attackResult.isBlocked());
        metadata.put("executionTime", attackResult.getExecutionTime());

        if (attackResult.getAttackDetails() != null) {
            metadata.putAll(attackResult.getAttackDetails());
        } else if (attackResult.getDetails() != null) {
            metadata.putAll(attackResult.getDetails());
        }

        return metadata;
    }

    /**
     * Convert event to details map for SecurityEvent
     */
    private Map<String, Object> convertToDetails(Object event, AttackResult attackResult) {
        Map<String, Object> details = new HashMap<>();
        details.put("simulationAttack", true);
        details.put("attackResult", attackResult);
        details.put("eventClass", event.getClass().getSimpleName());
        details.put("timestamp", LocalDateTime.now().toString());
        return details;
    }

    /**
     * Get event publishing statistics
     */
    public Map<String, Long> getStatistics() {
        Map<String, Long> stats = new HashMap<>();
        stats.put("authSuccessEvents", authSuccessEvents.get());
        stats.put("authFailureEvents", authFailureEvents.get());
        stats.put("authDecisionEvents", authDecisionEvents.get());
        stats.put("securityEvents", securityEvents.get());
        stats.put("totalEvents",
            authSuccessEvents.get() + authFailureEvents.get() +
            authDecisionEvents.get() + securityEvents.get());
        return stats;
    }

    private String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }
}