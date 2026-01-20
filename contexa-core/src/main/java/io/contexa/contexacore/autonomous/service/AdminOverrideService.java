package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;


@Slf4j
public class AdminOverrideService {

    private final AdminOverrideRepository repository;
    private final BaselineLearningService baselineLearningService;
    private final RedisTemplate<String, Object> redisTemplate;

    public AdminOverrideService(AdminOverrideRepository repository,
                                 BaselineLearningService baselineLearningService,
                                 RedisTemplate<String, Object> redisTemplate) {
        this.repository = repository;
        this.baselineLearningService = baselineLearningService;
        this.redisTemplate = redisTemplate;
    }

    
    public AdminOverride approve(String requestId, String userId, String adminId,
                                  String originalAction, double originalRiskScore, double originalConfidence,
                                  String overriddenAction, String reason, boolean allowBaselineUpdate,
                                  SecurityEvent originalEvent) {

        
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("관리자 승인 시 사유는 필수입니다.");
        }

        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId는 필수입니다.");
        }

        AdminOverride override = AdminOverride.builder()
            .overrideId(UUID.randomUUID().toString())
            .requestId(requestId)
            .userId(userId)
            .adminId(adminId)
            .timestamp(Instant.now())
            .originalAction(originalAction)
            .overriddenAction(overriddenAction)
            .reason(reason)
            .approved(true)
            .baselineUpdateAllowed(allowBaselineUpdate)
            .originalRiskScore(originalRiskScore)
            .originalConfidence(originalConfidence)
            .build();

        
        repository.save(override);

        
        repository.deletePending(requestId);

        
        if (override.canUpdateBaseline() && originalEvent != null) {
            triggerBaselineUpdate(userId, originalEvent, override);
        }

        
        
        if ("ALLOW".equalsIgnoreCase(overriddenAction) && userId != null) {
            updateAnalysisAction(userId, "ALLOW");
        }

        log.info("[AdminOverrideService][AI Native] 관리자 승인 완료: " +
                "requestId={}, userId={}, adminId={}, originalAction={} -> overriddenAction={}, " +
                "baselineUpdateAllowed={}, canUpdateBaseline={}",
            requestId, userId, adminId, originalAction, overriddenAction,
            allowBaselineUpdate, override.canUpdateBaseline());

        return override;
    }

    
    public AdminOverride reject(String requestId, String userId, String adminId,
                                 String originalAction, double originalRiskScore, double originalConfidence,
                                 String reason) {

        
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("관리자 거부 시 사유는 필수입니다.");
        }

        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId는 필수입니다.");
        }

        AdminOverride override = AdminOverride.builder()
            .overrideId(UUID.randomUUID().toString())
            .requestId(requestId)
            .userId(userId)
            .adminId(adminId)
            .timestamp(Instant.now())
            .originalAction(originalAction)
            .overriddenAction(originalAction) 
            .reason(reason)
            .approved(false)
            .baselineUpdateAllowed(false) 
            .originalRiskScore(originalRiskScore)
            .originalConfidence(originalConfidence)
            .build();

        
        repository.save(override);

        
        repository.deletePending(requestId);

        log.info("[AdminOverrideService][AI Native] 관리자 거부: " +
                "requestId={}, userId={}, adminId={}, originalAction={}, reason={}",
            requestId, userId, adminId, originalAction, reason);

        return override;
    }

    
    private void triggerBaselineUpdate(String userId, SecurityEvent event, AdminOverride override) {
        try {
            
            SecurityDecision adminApprovedDecision = SecurityDecision.builder()
                .action(SecurityDecision.Action.ALLOW)
                .riskScore(0.0) 
                .confidence(1.0) 
                .reasoning("Admin approved: " + override.getReason())
                .analysisTime(System.currentTimeMillis())
                .build();

            boolean learned = baselineLearningService.learnIfNormal(userId, adminApprovedDecision, event);

            if (learned) {
                log.info("[AdminOverrideService][AI Native] 관리자 승인에 의한 기준선 업데이트 완료: " +
                        "userId={}, adminId={}, reason={}, overrideId={}",
                    userId, override.getAdminId(), override.getReason(), override.getOverrideId());
            } else {
                log.warn("[AdminOverrideService] 기준선 업데이트 실패 (learnIfNormal returned false): " +
                        "userId={}, overrideId={}",
                    userId, override.getOverrideId());
            }

        } catch (Exception e) {
            log.error("[AdminOverrideService] 기준선 업데이트 중 예외 발생: userId={}, overrideId={}",
                userId, override.getOverrideId(), e);
        }
    }

    
    private void updateAnalysisAction(String userId, String action) {
        if (userId == null || userId.isBlank() || redisTemplate == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            
            redisTemplate.opsForHash().put(analysisKey, "action", action);

            
            redisTemplate.expire(analysisKey, Duration.ofSeconds(30));

            log.info("[AdminOverrideService][AI Native v3.5.0] Redis analysis 키 업데이트: " +
                    "userId={}, action={}, TTL=30초", userId, action);

        } catch (Exception e) {
            log.error("[AdminOverrideService] Redis analysis 키 업데이트 실패: userId={}", userId, e);
            
        }
    }

    
    public Optional<AdminOverride> findByRequestId(String requestId) {
        return repository.findByRequestId(requestId);
    }

    
    public boolean isPendingReview(String requestId) {
        return repository.findPending(requestId).isPresent();
    }

    
    public void addToPendingReview(String requestId, String userId,
                                    double riskScore, double confidence, String reasoning) {
        addToPendingReview(requestId, userId, riskScore, confidence, reasoning, null);
    }

    
    public void addToPendingReview(String requestId, String userId,
                                    double riskScore, double confidence, String reasoning,
                                    SecurityEvent event) {
        java.util.Map<String, Object> analysisData = new java.util.HashMap<>();
        analysisData.put("riskScore", riskScore);
        analysisData.put("confidence", confidence);
        analysisData.put("reasoning", reasoning);
        analysisData.put("originalAction", "BLOCK");

        repository.savePending(requestId, userId, analysisData);

        
        if (event != null) {
            repository.saveSecurityEvent(requestId, event);
            log.debug("[AdminOverrideService][AI Native] SecurityEvent 저장 완료: requestId={}, eventId={}",
                requestId, event.getEventId());
        }

        log.debug("[AdminOverrideService] BLOCK 요청을 대기 목록에 추가: requestId={}, userId={}",
            requestId, userId);
    }

    
    public Optional<java.util.Map<Object, Object>> getPendingReview(String requestId) {
        return repository.findPending(requestId);
    }

    
    public Optional<SecurityEvent> getSecurityEvent(String requestId) {
        return repository.findSecurityEvent(requestId);
    }
}
