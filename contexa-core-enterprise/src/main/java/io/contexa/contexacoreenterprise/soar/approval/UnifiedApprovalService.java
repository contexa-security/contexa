package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.*;
import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacore.repository.ApprovalPolicyRepository;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacore.autonomous.notification.SoarApprovalNotifier;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEvent;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * 통합 승인 서비스
 *
 * SOAR 시스템의 모든 승인 처리를 담당하는 단일 서비스입니다.
 * CompletableFuture를 사용하여 비동기 승인 처리를 단순하고 효율적으로 구현합니다.
 *
 * 설계 원칙:
 * - Single Responsibility: 승인 처리만 담당
 * - Open/Closed: 확장 가능하나 핵심 로직 수정 불필요
 * - KISS: 단순한 CompletableFuture 기반 처리
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UnifiedApprovalService implements ApprovalService {

    private final SoarApprovalRequestRepository repository;
    private final ApprovalRequestFactory approvalRequestFactory;
    private final ToolExecutionContextRepository executionContextRepository;
    private final ApprovalPolicyRepository policyRepository;
    private final SoarApprovalNotifier soarNotifier;
    private final ApplicationEventPublisher eventPublisher;
    private final StringRedisTemplate redisTemplate;

    // 대기 중인 승인 요청들 (requestId -> CompletableFuture)
    private final Map<String, CompletableFuture<Boolean>> pendingApprovals = new ConcurrentHashMap<>();

    // Reactor Sinks 지원 (레거시 호환)
    private final Map<String, Sinks.One<Boolean>> pendingSinks = new ConcurrentHashMap<>();

    // 타임아웃 관리를 위한 스케줄러
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    // 타임아웃 설정 (위험도별)
    private static final Duration TIMEOUT_CRITICAL = Duration.ofSeconds(30);
    private static final Duration TIMEOUT_HIGH = Duration.ofMinutes(1);
    private static final Duration TIMEOUT_MEDIUM = Duration.ofMinutes(2);
    private static final Duration TIMEOUT_LOW = Duration.ofMinutes(3);
    private static final Duration TIMEOUT_DEFAULT = Duration.ofMinutes(2);

    /**
     * 승인 요청 제출
     *
     * @param request 승인 요청
     * @return 승인 결과를 담은 CompletableFuture (true: 승인, false: 거부)
     */
    @Override
    @Transactional
    public CompletableFuture<Boolean> requestApproval(ApprovalRequest request) {
        // 1. requestId 확인 및 생성
        if (request.getRequestId() == null || request.getRequestId().isEmpty()) {
            request.setRequestId(UUID.randomUUID().toString());
        }

        String requestId = request.getRequestId();
        log.info("승인 요청 제출: {} - {} (위험도: {})",
                requestId, request.getToolName(), request.getRiskLevel());

        // 2. 중복 요청 확인
        if (pendingApprovals.containsKey(requestId)) {
            log.warn("중복 승인 요청: {}", requestId);
            return pendingApprovals.get(requestId);
        }

        // 3. 승인 요청 저장
        saveApprovalRequest(request);  // request에 ID가 설정됨
        log.debug("승인 요청 저장 완료: RequestId={}", requestId);

        // 4. CompletableFuture 생성
        CompletableFuture<Boolean> future = new CompletableFuture<>();
        pendingApprovals.put(requestId, future);

        // 5. 알림 전송 (이벤트 발행)
        try {
            // 이벤트 발행을 통해 알림 전송 (McpApprovalNotificationService가 수신)
            eventPublisher.publishEvent(ApprovalEvent.requested(this, request));
            log.debug("알림 이벤트 발행 완료: {}", requestId);
        } catch (Exception e) {
            log.error("알림 이벤트 발행 실패 (승인 프로세스는 계속됨): {}", requestId, e);
        }

        // 6. 타임아웃 설정
        Duration timeout = getTimeout(request.getRiskLevel());
        scheduleTimeout(requestId, future, timeout);
        log.debug("타임아웃 설정: {} - {}초", requestId, timeout.getSeconds());

        // 7. Future 완료 시 정리 작업
        future.whenComplete((result, error) -> {
            pendingApprovals.remove(requestId);

            if (error != null) {
                log.error("승인 처리 오류: {}", requestId, error);
                updateApprovalStatus(requestId, ApprovalRequest.ApprovalStatus.EXPIRED, null, "타임아웃 또는 오류");
            } else {
                log.info("승인 처리 완료: {} -> {}", requestId, result ? "승인" : "거부");
            }
        });

        return future;
    }

    /**
     * 인터페이스 구현: handleApprovalResponse
     *
     * @param approvalId 승인 요청 ID
     * @param isApproved 승인 여부
     * @param comment 코멘트
     * @param reviewer 검토자
     */
    @Override
    @Transactional
    public void handleApprovalResponse(String approvalId, boolean isApproved, String comment, String reviewer) {
        // processApprovalResponse로 위임
        processApprovalResponse(approvalId, isApproved, reviewer, comment);
    }

    /**
     * 승인 응답 처리
     *
     * @param requestId 승인 요청 ID
     * @param approved 승인 여부
     * @param reviewer 검토자
     * @param comment 코멘트
     */
    @Override
    @Transactional
    public void processApprovalResponse(String requestId, boolean approved, String reviewer, String comment) {
        log.info("승인 응답 처리: {} - {} by {}",
                requestId, approved ? "APPROVED" : "REJECTED", reviewer);

        log.info("========================================");
        log.info("pendingApprovals 크기: {}", pendingApprovals.size());
        log.info("pendingApprovals 키 목록: {}", pendingApprovals.keySet());
        log.info("요청된 requestId: {}", requestId);
        log.info("========================================");

        // 1. CompletableFuture 완료
        CompletableFuture<Boolean> future = pendingApprovals.remove(requestId);
        if (future != null && !future.isDone()) {
            future.complete(approved);
            log.info("CompletableFuture 완료: {} -> {}", requestId, approved);
        } else if (future != null && future.isDone()) {
            log.warn("이미 완료된 승인 요청: {}", requestId);
            return;
        } else {
            log.warn("대기 중인 승인 요청을 찾을 수 없음: {}", requestId);
            // 대기 중이 아니어도 DB는 업데이트
        }

        // 2. DB 업데이트
        ApprovalRequest.ApprovalStatus status = approved ?
                ApprovalRequest.ApprovalStatus.APPROVED :
                ApprovalRequest.ApprovalStatus.REJECTED;
        updateApprovalStatus(requestId, status, reviewer, comment);

        // 3. 완료 알림 전송
        try {
            // 이벤트 발행을 통해 알림 전송
            if (approved) {
                eventPublisher.publishEvent(ApprovalEvent.granted(this, requestId, reviewer));
            } else {
                eventPublisher.publishEvent(ApprovalEvent.denied(this, requestId, reviewer, "User rejected"));
            }
        } catch (Exception e) {
            log.error("완료 알림 전송 실패: {}", requestId, e);
        }

        // 4. Redis Pub/Sub 발행
        publishApprovalResult(requestId, approved);

        // 5. 파이프라인 재개 이벤트 발행
        publishResumeEvent(requestId, approved, comment, reviewer);

        // 6. Sink 완료 (레거시 호환)
        Sinks.One<Boolean> sink = pendingSinks.remove(requestId);
        if (sink != null) {
            Sinks.EmitResult result = sink.tryEmitValue(approved);
            if (result.isSuccess()) {
                log.debug("Sink 완료: {} -> {}", requestId, approved);
            }
        }
    }

    /**
     * 동기식 승인 대기 (블로킹)
     *
     * @param request 승인 요청
     * @return 승인 여부 (true: 승인, false: 거부 또는 타임아웃)
     */
    @Override
    public boolean waitForApprovalSync(ApprovalRequest request) {
        try {
            CompletableFuture<Boolean> future = requestApproval(request);
            Duration timeout = getTimeout(request.getRiskLevel());

            // 타임아웃과 함께 대기
            return future.get(timeout.toSeconds(), TimeUnit.SECONDS);

        } catch (TimeoutException e) {
            log.warn("승인 타임아웃: {}", request.getRequestId());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("승인 대기 중단: {}", request.getRequestId(), e);
            return false;
        } catch (ExecutionException e) {
            log.error("승인 처리 실패: {}", request.getRequestId(), e);
            return false;
        }
    }

    /**
     * 승인 요청 저장
     */
    @Override
    public ApprovalRequest saveApprovalRequest(ApprovalRequest request) {
        SoarApprovalRequest entity = saveApprovalRequestEntity(request);
        // ID와 requestId 설정 후 반환
        request.setId(entity.getId());
        request.setRequestId(entity.getRequestId());
        return request;
    }

    /**
     * 승인 요청 엔티티 저장 (내부 메서드)
     */
    private SoarApprovalRequest saveApprovalRequestEntity(ApprovalRequest request) {
        // Factory를 사용하여 완전한 ApprovalRequest 생성
        ApprovalRequest completeRequest = approvalRequestFactory.completeFromEvent(request);

        // Entity 생성
        SoarApprovalRequest entity = new SoarApprovalRequest();

        // 필수 필드 설정
        entity.setRequestId(completeRequest.getRequestId());
        entity.setPlaybookInstanceId(completeRequest.getIncidentId());
        entity.setIncidentId(completeRequest.getIncidentId());
        entity.setSessionId(completeRequest.getSessionId());
        entity.setToolName(completeRequest.getToolName());
        entity.setActionName(completeRequest.getToolName()); // actionName은 toolName과 동일 (레거시 호환)
        entity.setDescription(completeRequest.getToolDescription());
        entity.setParameters(completeRequest.getParameters());
        entity.setStatus(ApprovalRequest.ApprovalStatus.PENDING.name());
        entity.setRiskLevel(completeRequest.getRiskLevel() != null ?
                completeRequest.getRiskLevel().name() : "MEDIUM");
        // requestedAt 필드가 없으므로 생략 (JPA @CreatedDate 사용)
        entity.setRequestedBy(completeRequest.getRequestedBy() != null ?
                completeRequest.getRequestedBy() : "system");
        entity.setOrganizationId(completeRequest.getOrganizationId() != null ?
                completeRequest.getOrganizationId() : "default-org");

        // 선택적 필드 설정
        if (completeRequest.getRequiredApprovers() != null) {
            entity.setRequiredApprovers(completeRequest.getRequiredApprovers());
        }
        if (completeRequest.getRequiredRoles() != null && !completeRequest.getRequiredRoles().isEmpty()) {
            entity.setRequiredRoles(new java.util.ArrayList<>(completeRequest.getRequiredRoles()));
        }

        return repository.save(entity);
    }

    /**
     * 승인 상태 업데이트
     */
    @Transactional
    public void updateApprovalStatus(String requestId, ApprovalRequest.ApprovalStatus status,
                                     String reviewer, String comment) {
        try {
            // requestId로 먼저 검색
            SoarApprovalRequest entity = repository.findByRequestId(requestId);

            if (entity == null) {
                // 숫자 ID로 재시도
                if (requestId.matches("\\d+")) {
                    entity = repository.findById(Long.parseLong(requestId)).orElse(null);
                }
            }

            if (entity == null) {
                log.error("승인 요청을 찾을 수 없음: {}", requestId);
                return;
            }

            // 상태 업데이트
            entity.setStatus(status.name());
            entity.setReviewerId(reviewer);
            entity.setReviewerComment(comment);
            // reviewedAt 필드가 없으므로 approvedAt 사용
            entity.setApprovedAt(LocalDateTime.now());

            repository.save(entity);
            log.info("승인 상태 업데이트 완료: {} -> {}", requestId, status);

        } catch (Exception e) {
            log.error("승인 상태 업데이트 실패: {}", requestId, e);
        }
    }

    /**
     * 타임아웃 스케줄링
     */
    private void scheduleTimeout(String requestId, CompletableFuture<Boolean> future, Duration timeout) {
        scheduler.schedule(() -> {
            if (!future.isDone()) {
                log.warn("승인 타임아웃 발생: {} ({}초)", requestId, timeout.getSeconds());

                // Future를 false로 완료 (타임아웃 = 거부로 처리)
                future.complete(false);

                // 알림 전송
                try {
                    eventPublisher.publishEvent(ApprovalEvent.timeout(this, requestId));
                } catch (Exception e) {
                    log.error("타임아웃 알림 전송 실패: {}", requestId, e);
                }
            }
        }, timeout.getSeconds(), TimeUnit.SECONDS);
    }

    /**
     * 위험도에 따른 타임아웃 결정
     */
    private Duration getTimeout(ApprovalRequest.RiskLevel riskLevel) {
        if (riskLevel == null) {
            return TIMEOUT_DEFAULT;
        }

        return switch (riskLevel) {
            case CRITICAL -> TIMEOUT_CRITICAL;
            case HIGH -> TIMEOUT_HIGH;
            case MEDIUM -> TIMEOUT_MEDIUM;
            case LOW -> TIMEOUT_LOW;
            default -> TIMEOUT_DEFAULT;
        };
    }

    /**
     * 현재 대기 중인 승인 요청 수
     */
    public int getPendingApprovalCount() {
        return pendingApprovals.size();
    }

    /**
     * 승인 상태 조회
     *
     * @param approvalId 승인 요청 ID
     * @return 승인 상태
     */
    @Override
    public ApprovalRequest.ApprovalStatus getApprovalStatus(String approvalId) {
        try {
            // requestId로 먼저 검색
            SoarApprovalRequest entity = repository.findByRequestId(approvalId);

            if (entity == null) {
                // 숫자 ID로 재시도
                if (approvalId.matches("\\d+")) {
                    entity = repository.findById(Long.parseLong(approvalId)).orElse(null);
                }
            }

            if (entity == null) {
                log.warn("승인 요청을 찾을 수 없음: {}", approvalId);
                return ApprovalRequest.ApprovalStatus.PENDING; // 기본값 반환
            }

            // String 상태를 Enum으로 변환
            return ApprovalRequest.ApprovalStatus.valueOf(entity.getStatus());

        } catch (Exception e) {
            log.error("승인 상태 조회 실패: {}", approvalId, e);
            return ApprovalRequest.ApprovalStatus.PENDING; // 오류 시 기본값 반환
        }
    }

    /**
     * 레거시 메서드 - SoarContext 지원
     * PlaybookContext/SoarContext를 사용하는 기존 호출자를 위한 호환성 메서드
     */
    @Override
    @Transactional
    public String requestApproval(SoarContext soarContext, ApprovalRequestDetails requestDetails) {
        log.info("레거시 승인 요청: {} - {}", requestDetails.actionName(), requestDetails.description());

        // SoarContext를 ApprovalRequest로 변환
        ApprovalRequest approvalRequest = convertToApprovalRequest(soarContext, requestDetails);

        // CompletableFuture 생성 및 저장
        CompletableFuture<Boolean> future = requestApproval(approvalRequest);

        // Sink도 생성 (레거시 호환)
        if (soarContext != null) {
            Sinks.One<Boolean> sink = Sinks.one();
            pendingSinks.put(approvalRequest.getRequestId(), sink);

            // CompletableFuture 완료 시 Sink도 완료
            future.whenComplete((result, error) -> {
                Sinks.One<Boolean> pendingSink = pendingSinks.remove(approvalRequest.getRequestId());
                if (pendingSink != null) {
                    if (error != null) {
                        pendingSink.tryEmitError(error);
                    } else {
                        pendingSink.tryEmitValue(result);
                    }
                }
            });
        }

        return approvalRequest.getRequestId();
    }

    /**
     * SoarContext를 ApprovalRequest로 변환
     */
    private ApprovalRequest convertToApprovalRequest(SoarContext soarContext, ApprovalRequestDetails requestDetails) {
        ApprovalRequest request = new ApprovalRequest();

        // 기본 정보 설정
        request.setRequestId(UUID.randomUUID().toString());
        request.setToolName(requestDetails.actionName());
        request.setToolDescription(requestDetails.description());
        request.setParameters(requestDetails.parameters());
        request.setActionDescription(requestDetails.description());

        // SoarContext 정보 매핑
        if (soarContext != null) {
            request.setIncidentId(soarContext.getIncidentId() != null ?
                    soarContext.getIncidentId() : "INC-" + UUID.randomUUID());
            request.setOrganizationId(soarContext.getOrganizationId() != null ?
                    soarContext.getOrganizationId() : "default-org");
            request.setSessionId(soarContext.getIncidentId()); // incidentId를 sessionId로 사용

            // 위험도 설정
            String severity = soarContext.getSeverity() != null ? soarContext.getSeverity() : "MEDIUM";
            request.setRiskLevel(mapSeverityToRiskLevel(severity));
        }

        // 정책 기반 승인자 설정 (선택적)
        if (policyRepository != null) {
            String severity = soarContext != null && soarContext.getSeverity() != null ?
                    soarContext.getSeverity() : "LOW";
            ApprovalPolicy policy = policyRepository.findPolicyFor(requestDetails.actionName(), severity);

            if (policy != null) {
                request.setRequiredApprovers(policy.requiredApprovers());
                request.setRequiredRoles(new HashSet<>(policy.requiredRoles()));
            }
        }

        request.setRequestedBy("system");
        request.setRequestedAt(LocalDateTime.now());
        request.setStatus(ApprovalRequest.ApprovalStatus.PENDING);

        return request;
    }

    /**
     * Severity를 RiskLevel로 매핑
     */
    private ApprovalRequest.RiskLevel mapSeverityToRiskLevel(String severity) {
        if (severity == null) {
            return ApprovalRequest.RiskLevel.MEDIUM;
        }

        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> ApprovalRequest.RiskLevel.CRITICAL;
            case "HIGH" -> ApprovalRequest.RiskLevel.HIGH;
            case "MEDIUM" -> ApprovalRequest.RiskLevel.MEDIUM;
            case "LOW" -> ApprovalRequest.RiskLevel.LOW;
            default -> ApprovalRequest.RiskLevel.MEDIUM;
        };
    }

    /**
     * 레거시 Mono<Boolean> 반환 메서드
     */
    public Mono<Boolean> waitForApproval(String approvalId) {
        Sinks.One<Boolean> sink = pendingSinks.get(approvalId);
        if (sink != null) {
            return sink.asMono();
        }

        // Sink가 없으면 CompletableFuture에서 생성
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        if (future != null) {
            return Mono.fromFuture(future);
        }

        // 둘 다 없으면 실패
        return Mono.error(new IllegalArgumentException("No pending approval found: " + approvalId));
    }

    /**
     * Redis Pub/Sub 지원
     */
    private void publishApprovalResult(String approvalId, boolean approved) {
        if (redisTemplate != null) {
            try {
                String channel = "approval:" + approvalId;
                String message = approved ? "APPROVED" : "REJECTED";
                redisTemplate.convertAndSend(channel, message);
                log.debug("Redis Pub/Sub 발행: {} -> {}", channel, message);
            } catch (Exception e) {
                log.error("Redis Pub/Sub 발행 실패: {}", approvalId, e);
            }
        }
    }

    /**
     * 파이프라인 재개 이벤트 발행
     */
    private void publishResumeEvent(String approvalId, boolean approved, String comment, String reviewer) {
        try {
            // 승인 요청 조회
            SoarApprovalRequest entity = repository.findByRequestId(approvalId);
            if (entity == null) {
                log.warn("승인 요청을 찾을 수 없어 재개 이벤트를 발행할 수 없음: {}", approvalId);
                return;
            }

            // SoarContext 재구성 (9개 파라미터 생성자 사용)
            SoarContext soarContext = new SoarContext(
                    entity.getPlaybookInstanceId(),  // incidentId
                    "SOAR_APPROVAL",                 // threatType
                    "MEDIUM",                        // severity
                    "Approval context recreation",   // description
                    entity.getStatus(),              // currentStatus
                    LocalDateTime.now(),             // detectedAt
                    List.of("approval-system"),      // affectedSystems
                    Map.of("approval_id", entity.getId()), // additionalInfo
                    entity.getOrganizationId() != null ? entity.getOrganizationId() : "default-org" // organizationId
            );
            soarContext.setHumanApprovalNeeded(false);
            soarContext.setHumanApprovalMessage(comment);

            // SoarRequest 생성
            SoarRequest soarRequest = new SoarRequest(
                    soarContext,
                    "resumeSoar",
                    "Approval response received: " + entity.getStatus()
            );
            soarRequest.setApprovalId(entity.getId().toString());

            // ApprovalResumeEvent 발행
            ApprovalResumeEvent resumeEvent = new ApprovalResumeEvent(
                    soarRequest, approvalId, approved, comment, reviewer
            );
            eventPublisher.publishEvent(resumeEvent);

            log.info("ApprovalResumeEvent 발행: {} - {}", approvalId, approved ? "APPROVED" : "REJECTED");

        } catch (Exception e) {
            log.error("파이프라인 재개 이벤트 발행 실패: {}", approvalId, e);
        }
    }

    /**
     * 승인 요청이 대기 중인지 확인
     */
    public boolean isPending(String approvalId) {
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        return future != null && !future.isDone();
    }

    /**
     * 승인 요청이 완료되었는지 확인
     */
    public boolean isCompleted(String approvalId) {
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        if (future != null && future.isDone() && !future.isCancelled()) {
            return true;
        }

        // DB에서도 확인
        SoarApprovalRequest entity = repository.findByRequestId(approvalId);
        if (entity != null) {
            String status = entity.getStatus();
            return "APPROVED".equals(status) || "REJECTED".equals(status);
        }

        return false;
    }

    /**
     * 승인 요청이 취소되었는지 확인
     */
    public boolean isCancelled(String approvalId) {
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        if (future != null && future.isCancelled()) {
            return true;
        }

        // DB에서도 확인
        SoarApprovalRequest entity = repository.findByRequestId(approvalId);
        if (entity != null) {
            String status = entity.getStatus();
            return "CANCELLED".equals(status) || "EXPIRED".equals(status);
        }

        return false;
    }

    /**
     * 대기 중인 승인 요청 ID 목록
     */
    public java.util.Set<String> getPendingApprovalIds() {
        java.util.Set<String> pendingIds = new HashSet<>();

        // 메모리에서 대기 중인 요청들
        pendingApprovals.forEach((id, future) -> {
            if (!future.isDone()) {
                pendingIds.add(id);
            }
        });

        return pendingIds;
    }

    /**
     * 대기 중인 승인 요청 수
     */
    public int getPendingCount() {
        return (int) pendingApprovals.entrySet().stream()
                .filter(entry -> !entry.getValue().isDone())
                .count();
    }

    /**
     * 승인 요청 취소
     */
    public void cancelApproval(String approvalId, String reason) {
        log.info("🚫 승인 요청 취소: {} - {}", approvalId, reason);

        // CompletableFuture 취소
        CompletableFuture<Boolean> future = pendingApprovals.remove(approvalId);
        if (future != null && !future.isDone()) {
            future.cancel(true);
        }

        // DB 업데이트
        updateApprovalStatus(approvalId, ApprovalRequest.ApprovalStatus.CANCELLED, "system", reason);

        // 알림 전송 (이벤트 발행)
        try {
            eventPublisher.publishEvent(ApprovalEvent.timeout(this, approvalId));
        } catch (Exception e) {
            log.error("취소 알림 이벤트 발행 실패: {}", approvalId, e);
        }
    }

    /**
     * 통계 정보 조회
     */
    public Map<String, Object> getStatistics() {
        int pendingCount = getPendingCount();
        int totalCount = pendingApprovals.size() + pendingSinks.size();

        // DB에서 추가 통계
        long approvedCount = 0;
        long rejectedCount = 0;
        long expiredCount = 0;

        try {
            // 최근 24시간 통계 (필요시 repository 메서드 추가)
            LocalDateTime since = LocalDateTime.now().minusDays(1);
            // approvedCount = repository.countByStatusAndRequestedAtAfter(ApprovalRequest.ApprovalStatus.APPROVED, since);
            // rejectedCount = repository.countByStatusAndRequestedAtAfter(ApprovalRequest.ApprovalStatus.REJECTED, since);
            // expiredCount = repository.countByStatusAndRequestedAtAfter(ApprovalRequest.ApprovalStatus.EXPIRED, since);
        } catch (Exception e) {
            log.error("통계 조회 실패", e);
        }

        return Map.of(
                "pending", pendingCount,
                "total", totalCount,
                "approved24h", approvedCount,
                "rejected24h", rejectedCount,
                "expired24h", expiredCount,
                "timestamp", LocalDateTime.now()
        );
    }

    /**
     * 비동기 승인 등록
     * Agent 모드에서 사용 - DB에 저장하고 나중에 처리
     */
    @Transactional
    public void registerAsyncApproval(ApprovalRequest request, ToolExecutionContext executionContext) {
        log.info("비동기 승인 등록: {} - {}", request.getRequestId(), request.getToolName());

        try {
            // 1. 승인 요청 엔티티 저장 (이미 완료된 경우도 있음)
            if (request.getId() == null) {
                saveApprovalRequest(request);
            }

            // 2. 실행 컨텍스트 상태 업데이트
            if (executionContext != null && executionContextRepository != null) {
                executionContext.setStatus("PENDING_APPROVAL");
                executionContextRepository.save(executionContext);
                log.debug("도구 실행 컨텍스트 상태 업데이트: {} -> PENDING_APPROVAL",
                        executionContext.getRequestId());
            }

            // 3. CompletableFuture 생성 및 저장
            // 비동기 모드에서도 나중에 승인 처리를 위해 Future 생성
            CompletableFuture<Boolean> future = new CompletableFuture<>();
            pendingApprovals.put(request.getRequestId(), future);

            // 4. 타임아웃 설정 (비동기 모드에서도 타임아웃 필요)
            Duration timeout = getTimeout(request.getRiskLevel());
            scheduleAsyncTimeout(request.getRequestId(), future, timeout, executionContext);

            log.info("비동기 승인 등록 완료: {} (타임아웃: {}분)",
                    request.getRequestId(), timeout.toMinutes());

        } catch (Exception e) {
            log.error("비동기 승인 등록 실패: {}", request.getRequestId(), e);

            // 실패 시 컨텍스트 상태 업데이트
            if (executionContext != null && executionContextRepository != null) {
                executionContext.setStatus("FAILED");
                executionContext.setExecutionError("승인 등록 실패: " + e.getMessage());
                executionContextRepository.save(executionContext);
            }
        }
    }

    /**
     * 비동기 모드 타임아웃 스케줄링
     * 타임아웃 시 도구 실행 컨텍스트도 업데이트
     */
    private void scheduleAsyncTimeout(String requestId, CompletableFuture<Boolean> future,
                                      Duration timeout, ToolExecutionContext executionContext) {
        scheduler.schedule(() -> {
            if (!future.isDone()) {
                log.warn("비동기 승인 타임아웃 발생: {} ({}분)", requestId, timeout.toMinutes());

                // Future를 false로 완료
                future.complete(false);

                // 도구 실행 컨텍스트 업데이트
                if (executionContext != null && executionContextRepository != null) {
                    executionContext.setStatus("TIMEOUT");
                    executionContext.setExecutionError("승인 타임아웃");
                    executionContextRepository.save(executionContext);
                }

                // DB 승인 상태 업데이트
                updateApprovalStatus(requestId, ApprovalRequest.ApprovalStatus.EXPIRED,
                        "system", "타임아웃");

                // 알림 전송
                try {
                    // 이벤트 발행을 통해 타임아웃 알림
                    eventPublisher.publishEvent(ApprovalEvent.timeout(this, requestId));
                } catch (Exception e) {
                    log.error("타임아웃 알림 전송 실패: {}", requestId, e);
                }
            }
        }, timeout.getSeconds(), TimeUnit.SECONDS);
    }

    /**
     * 비동기 승인 처리
     * Agent나 스케줄러가 승인된 도구를 실행할 때 호출
     */
    @Transactional
    public void processAsyncApproval(String requestId, boolean approved, String reviewer) {
        log.info("비동기 승인 처리: {} - {} by {}",
                requestId, approved ? "APPROVED" : "REJECTED", reviewer);

        try {
            // 1. 도구 실행 컨텍스트 조회 및 업데이트
            if (executionContextRepository != null) {
                ToolExecutionContext context = executionContextRepository
                        .findByRequestId(requestId)
                        .orElse(null);

                if (context != null) {
                    if (approved) {
                        context.setStatus("APPROVED");
                        log.info("도구 실행 컨텍스트 승인됨: {}", requestId);
                    } else {
                        context.setStatus("REJECTED");
                        context.setExecutionError("승인 거부됨");
                        log.info("도구 실행 컨텍스트 거부됨: {}", requestId);
                    }
                    executionContextRepository.save(context);
                }
            }

            // 2. 기존 승인 응답 처리 로직 호출
            processApprovalResponse(requestId, approved, reviewer,
                    approved ? "비동기 승인" : "비동기 거부");

            // 3. 비동기 결과 알림 전송 (이벤트 발행)
            if (approved) {
                eventPublisher.publishEvent(ApprovalEvent.granted(this, requestId, reviewer));
            } else {
                eventPublisher.publishEvent(ApprovalEvent.denied(this, requestId, reviewer, "Agent mode rejection"));
            }

        } catch (Exception e) {
            log.error("비동기 승인 처리 실패: {}", requestId, e);
        }
    }

    /**
     * 서비스 종료 시 정리
     */
    @PreDestroy
    public void shutdown() {
        log.info("UnifiedApprovalService 종료 중...");

        // 모든 대기 중인 승인 취소
        pendingApprovals.forEach((id, future) -> {
            if (!future.isDone()) {
                future.cancel(true);
            }
        });
        pendingApprovals.clear();

        // Sinks 정리
        pendingSinks.forEach((id, sink) -> {
            sink.tryEmitError(new InterruptedException("Service shutting down"));
        });
        pendingSinks.clear();

        // 스케줄러 종료
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}