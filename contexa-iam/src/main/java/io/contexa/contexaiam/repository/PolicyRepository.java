package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.util.AntPathMatcher;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface PolicyRepository extends JpaRepository<Policy, Long> {

    Optional<Policy> findByName(String name);

    @Query("SELECT DISTINCT p FROM Policy p " +
            "LEFT JOIN FETCH p.targets t " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions c")
    List<Policy> findAllWithDetails();

    @Query("SELECT DISTINCT p FROM Policy p " +
            "LEFT JOIN FETCH p.targets t " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions c " +
            "WHERE t.targetType = :targetType " +
            "ORDER BY p.priority ASC")
    List<Policy> findByTargetTypeWithDetails(@Param("targetType") String targetType);

    @Query("SELECT p FROM Policy p JOIN p.targets t " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions c " +
            "WHERE t.targetType = 'METHOD' AND t.targetIdentifier = :methodIdentifier " +
            "ORDER BY p.priority ASC")
    List<Policy> findByMethodIdentifier(@Param("methodIdentifier") String methodIdentifier);

    @Query("SELECT p FROM Policy p " +
            "LEFT JOIN FETCH p.targets t " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions c " +
            "WHERE p.id = :id")
    Optional<Policy> findByIdWithDetails(@Param("id") Long id);

    @Query("SELECT p FROM Policy p JOIN FETCH p.targets t WHERE t.targetType = 'URL'")
    List<Policy> findAllUrlPoliciesWithDetails();

    @Query("SELECT p FROM Policy p JOIN p.targets t " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions c " +
            "WHERE t.targetType = 'METHOD' AND t.targetIdentifier = :methodIdentifier " +
            "AND c.authorizationPhase = :phase " + // [신규] phase 조건 추가
            "ORDER BY p.priority ASC")
    List<Policy> findByMethodIdentifierAndPhase(@Param("methodIdentifier") String methodIdentifier,
                                                @Param("phase") PolicyCondition.AuthorizationPhase phase);


    @Query("SELECT DISTINCT p FROM Policy p " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions " +
            "ORDER BY p.id DESC")
    List<Policy> findTop5ByOrderByIdDesc();

    @Query("SELECT DISTINCT p FROM Policy p " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions " +
            "WHERE p.friendlyDescription IS NULL")
    List<Policy> findByFriendlyDescriptionIsNull();

    /**
     * Ant-style 경로 매칭을 지원하는 편의 메서드.
     * DB에서 모든 URL 정책을 가져온 후, 메모리에서 AntPathMatcher를 사용해 필터링합니다.
     * @param requestUrl 매칭할 요청 URL (e.g., /admin/users/1)
     * @return 매칭되는 모든 정책 리스트
     */
    default List<Policy> findPoliciesMatchingUrl(String requestUrl) {
        AntPathMatcher pathMatcher = new AntPathMatcher();
        return findAllUrlPoliciesWithDetails().stream()
                .filter(policy -> policy.getTargets().stream()
                        .anyMatch(target -> pathMatcher.match(target.getTargetIdentifier(), requestUrl)))
                .toList();
    }

    // ==================== AI Policy Methods ====================

    /**
     * 출처와 승인 상태로 정책 조회
     */
    Page<Policy> findBySourceAndApprovalStatus(
        Policy.PolicySource source,
        Policy.ApprovalStatus status,
        Pageable pageable
    );

    /**
     * 여러 출처와 승인 상태로 정책 조회
     */
    Page<Policy> findBySourceInAndApprovalStatus(
        List<Policy.PolicySource> sources,
        Policy.ApprovalStatus status,
        Pageable pageable
    );

    /**
     * 출처로 정책 조회
     */
    Page<Policy> findBySource(Policy.PolicySource source, Pageable pageable);

    /**
     * 여러 출처로 정책 조회
     */
    Page<Policy> findBySourceIn(List<Policy.PolicySource> sources, Pageable pageable);

    /**
     * 출처별 정책 수 계산
     */
    long countBySource(Policy.PolicySource source);

    /**
     * 여러 출처의 정책 수 계산
     */
    long countBySourceIn(List<Policy.PolicySource> sources);

    /**
     * 출처와 승인 상태별 정책 수 계산
     */
    long countBySourceInAndApprovalStatus(
        List<Policy.PolicySource> sources,
        Policy.ApprovalStatus status
    );

    /**
     * 특정 기간 이후 처리된 정책 수 계산
     */
    long countBySourceInAndApprovalStatusInAndUpdatedAtAfter(
        List<Policy.PolicySource> sources,
        List<Policy.ApprovalStatus> statuses,
        LocalDateTime since
    );

    /**
     * 특정 기간 이후 승인된 정책 수 계산
     */
    long countBySourceInAndApprovalStatusAndUpdatedAtAfter(
        List<Policy.PolicySource> sources,
        Policy.ApprovalStatus status,
        LocalDateTime since
    );

    /**
     * AI 정책의 평균 신뢰도 점수 계산
     */
    @Query("SELECT AVG(p.confidenceScore) FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') AND p.confidenceScore IS NOT NULL")
    Double calculateAverageConfidenceScoreForAIPolicies();

    /**
     * 활성화된 AI 정책 조회
     */
    @Query("SELECT p FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') " +
           "AND p.isActive = true AND p.approvalStatus = 'APPROVED'")
    List<Policy> findActiveAIPolicies();

    /**
     * 특정 신뢰도 이상의 AI 정책 조회
     */
    @Query("SELECT p FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') " +
           "AND p.confidenceScore >= :minScore")
    List<Policy> findAIPoliciesWithMinConfidence(@Param("minScore") double minScore);

    /**
     * 최근 생성된 AI 정책 조회
     */
    @Query("SELECT p FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') " +
           "AND p.createdAt >= :since " +
           "ORDER BY p.createdAt DESC")
    Page<Policy> findRecentAIPolicies(@Param("since") LocalDateTime since, Pageable pageable);
}