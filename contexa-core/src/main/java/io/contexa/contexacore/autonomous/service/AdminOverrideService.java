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

/**
 * 관리자 개입 서비스 (AI Native v3.4.0)
 *
 * AI Native 원칙:
 * - LLM 판정은 최종 결정이 아님 (관리자 개입 가능)
 * - 그러나 관리자 개입은 명시적 승인 + 기준선 업데이트 허용이 별도로 필요
 * - 모든 개입은 감사 로그로 기록됨
 *
 * 기준선 오염 방지 메커니즘:
 * - 관리자 승인만으로는 기준선 업데이트되지 않음
 * - baselineUpdateAllowed=true를 명시적으로 설정해야 함
 * - 이는 "이 요청이 향후 정상 패턴으로 학습되어도 좋다"는 의미
 *
 * 사용 시나리오:
 * 1. LLM이 BLOCK 판정
 * 2. 관리자가 검토하여 오탐으로 판단
 * 3. 관리자가 ALLOW로 전환 + baselineUpdateAllowed=true 설정
 * 4. 해당 패턴이 사용자 기준선에 학습됨
 *
 * Bean 등록: CoreAutonomousAutoConfiguration에서 @Bean으로 등록
 *
 * @author contexa
 * @since 3.4.0
 */
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

    /**
     * 관리자 승인 처리
     *
     * BLOCK/CHALLENGE/ESCALATE로 판정된 요청을 관리자가 검토 후 ALLOW/CHALLENGE로 전환합니다.
     *
     * AI Native 원칙:
     * - 승인만으로는 기준선 업데이트되지 않음
     * - allowBaselineUpdate=true를 명시적으로 설정해야 기준선에 학습됨
     * - 이는 "향후 이 패턴이 정상으로 인식되어도 좋다"는 명시적 승인
     *
     * @param requestId 원본 요청 ID
     * @param userId 대상 사용자 ID
     * @param adminId 관리자 ID
     * @param originalAction 원래 LLM 판정 (BLOCK/CHALLENGE/ESCALATE)
     * @param originalRiskScore 원래 LLM riskScore
     * @param originalConfidence 원래 LLM confidence
     * @param overriddenAction 전환할 Action (ALLOW/CHALLENGE)
     * @param reason 승인 사유 (필수)
     * @param allowBaselineUpdate 기준선 업데이트 허용 여부
     * @param originalEvent 원본 SecurityEvent (기준선 업데이트용)
     * @return 생성된 AdminOverride
     * @throws IllegalArgumentException 사유가 없는 경우
     */
    public AdminOverride approve(String requestId, String userId, String adminId,
                                  String originalAction, double originalRiskScore, double originalConfidence,
                                  String overriddenAction, String reason, boolean allowBaselineUpdate,
                                  SecurityEvent originalEvent) {

        // 필수값 검증
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

        // Redis에 저장
        repository.save(override);

        // 대기 중인 요청 삭제
        repository.deletePending(requestId);

        // 기준선 업데이트 트리거 (조건 충족 시)
        if (override.canUpdateBaseline() && originalEvent != null) {
            triggerBaselineUpdate(userId, originalEvent, override);
        }

        // AI Native v3.5.0: Redis analysis 키 업데이트
        // MFA 성공 케이스와 동일하게 action을 ALLOW로 변경하고 TTL 갱신
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

    /**
     * 관리자 거부 처리
     *
     * BLOCK 판정이 정당하다고 판단하여 거부합니다.
     *
     * 거부 시:
     * - 기준선 업데이트 발생하지 않음
     * - BLOCK 상태 유지
     * - 감사 로그 기록
     *
     * @param requestId 원본 요청 ID
     * @param userId 대상 사용자 ID
     * @param adminId 관리자 ID
     * @param originalAction 원래 LLM 판정
     * @param originalRiskScore 원래 LLM riskScore
     * @param originalConfidence 원래 LLM confidence
     * @param reason 거부 사유 (필수)
     * @return 생성된 AdminOverride
     * @throws IllegalArgumentException 사유가 없는 경우
     */
    public AdminOverride reject(String requestId, String userId, String adminId,
                                 String originalAction, double originalRiskScore, double originalConfidence,
                                 String reason) {

        // 필수값 검증
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
            .overriddenAction(originalAction) // 원래 Action 유지
            .reason(reason)
            .approved(false)
            .baselineUpdateAllowed(false) // 거부 시 기준선 업데이트 불가
            .originalRiskScore(originalRiskScore)
            .originalConfidence(originalConfidence)
            .build();

        // Redis에 저장
        repository.save(override);

        // 대기 중인 요청 삭제
        repository.deletePending(requestId);

        log.info("[AdminOverrideService][AI Native] 관리자 거부: " +
                "requestId={}, userId={}, adminId={}, originalAction={}, reason={}",
            requestId, userId, adminId, originalAction, reason);

        return override;
    }

    /**
     * 기준선 업데이트 트리거
     *
     * 관리자가 명시적으로 기준선 업데이트를 허용한 경우에만 호출됩니다.
     *
     * AI Native 원칙:
     * - 관리자 승인은 LLM 판단을 재정의
     * - baselineUpdateAllowed=true는 "이 패턴을 정상으로 학습해도 좋다"는 의미
     * - 학습 시 riskScore=0, confidence=1.0으로 설정 (관리자 승인이므로)
     *
     * @param userId 사용자 ID
     * @param event 원본 SecurityEvent
     * @param override 관리자 개입 객체
     */
    private void triggerBaselineUpdate(String userId, SecurityEvent event, AdminOverride override) {
        try {
            // 관리자 승인에 의한 학습임을 명시하는 SecurityDecision 생성
            SecurityDecision adminApprovedDecision = SecurityDecision.builder()
                .action(SecurityDecision.Action.ALLOW)
                .riskScore(0.0) // 관리자 승인이므로 riskScore 0
                .confidence(1.0) // 관리자 승인이므로 confidence 최대
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

    /**
     * Redis analysis 키 업데이트
     *
     * AI Native v3.5.0: 관리자 승인 시 Redis analysis 키의 action을 변경하고 TTL 갱신
     * MFA 성공 케이스와 동일한 패턴 적용
     *
     * 목적:
     * - tryAcquireAnalysisLock()에서 BLOCK 감지로 인한 Kafka 차단 방지
     * - 다음 요청부터 정상적인 ALLOW 처리 가능
     *
     * @param userId 사용자 ID
     * @param action 변경할 action (ALLOW)
     */
    private void updateAnalysisAction(String userId, String action) {
        if (userId == null || userId.isBlank() || redisTemplate == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            // 1. action 필드 업데이트
            redisTemplate.opsForHash().put(analysisKey, "action", action);

            // 2. TTL을 ALLOW의 TTL(1시간)로 갱신
            redisTemplate.expire(analysisKey, Duration.ofHours(1));

            log.info("[AdminOverrideService][AI Native v3.5.0] Redis analysis 키 업데이트: " +
                    "userId={}, action={}, TTL=1시간", userId, action);

        } catch (Exception e) {
            log.error("[AdminOverrideService] Redis analysis 키 업데이트 실패: userId={}", userId, e);
            // 업데이트 실패해도 승인 처리는 계속 진행
        }
    }

    /**
     * 관리자 개입 조회
     *
     * @param requestId 요청 ID
     * @return 관리자 개입 객체 (없으면 Optional.empty())
     */
    public Optional<AdminOverride> findByRequestId(String requestId) {
        return repository.findByRequestId(requestId);
    }

    /**
     * 대기 중인 BLOCK 요청인지 확인
     *
     * @param requestId 요청 ID
     * @return 대기 중이면 true
     */
    public boolean isPendingReview(String requestId) {
        return repository.findPending(requestId).isPresent();
    }

    /**
     * BLOCK 판정된 요청을 대기 목록에 추가
     *
     * LLM이 BLOCK 판정을 내리면 호출하여 관리자 검토 대기열에 추가합니다.
     *
     * @param requestId 요청 ID
     * @param userId 사용자 ID
     * @param riskScore LLM riskScore
     * @param confidence LLM confidence
     * @param reasoning LLM 판단 근거
     */
    public void addToPendingReview(String requestId, String userId,
                                    double riskScore, double confidence, String reasoning) {
        addToPendingReview(requestId, userId, riskScore, confidence, reasoning, null);
    }

    /**
     * BLOCK 판정된 요청을 대기 목록에 추가 (SecurityEvent 포함)
     *
     * AI Native v3.5.0: SecurityEvent를 함께 저장하여 관리자 승인 시 Baseline 학습에 활용
     *
     * @param requestId 요청 ID
     * @param userId 사용자 ID
     * @param riskScore LLM riskScore
     * @param confidence LLM confidence
     * @param reasoning LLM 판단 근거
     * @param event 원본 SecurityEvent (Baseline 학습용)
     */
    public void addToPendingReview(String requestId, String userId,
                                    double riskScore, double confidence, String reasoning,
                                    SecurityEvent event) {
        java.util.Map<String, Object> analysisData = new java.util.HashMap<>();
        analysisData.put("riskScore", riskScore);
        analysisData.put("confidence", confidence);
        analysisData.put("reasoning", reasoning);
        analysisData.put("originalAction", "BLOCK");

        repository.savePending(requestId, userId, analysisData);

        // AI Native v3.5.0: SecurityEvent 저장 (Baseline 학습용)
        if (event != null) {
            repository.saveSecurityEvent(requestId, event);
            log.debug("[AdminOverrideService][AI Native] SecurityEvent 저장 완료: requestId={}, eventId={}",
                requestId, event.getEventId());
        }

        log.debug("[AdminOverrideService] BLOCK 요청을 대기 목록에 추가: requestId={}, userId={}",
            requestId, userId);
    }

    /**
     * 대기 중인 요청 정보 조회 (관리자 UI용)
     *
     * AI Native v3.5.0: 관리자 UI에서 대기 중인 요청 목록 표시
     *
     * @param requestId 요청 ID
     * @return 대기 중인 요청 데이터 (없으면 Optional.empty())
     */
    public Optional<java.util.Map<Object, Object>> getPendingReview(String requestId) {
        return repository.findPending(requestId);
    }

    /**
     * 저장된 SecurityEvent 조회 (관리자 승인 시 사용)
     *
     * AI Native v3.5.0: 관리자 승인 시 Baseline 학습을 위해 SecurityEvent 조회
     *
     * @param requestId 요청 ID
     * @return SecurityEvent 객체 (없으면 Optional.empty())
     */
    public Optional<SecurityEvent> getSecurityEvent(String requestId) {
        return repository.findSecurityEvent(requestId);
    }
}
