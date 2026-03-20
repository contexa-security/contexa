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

    @Query(value = "SELECT * FROM policy p " +
            "WHERE CAST(:keyword AS TEXT) IS NULL OR LOWER(CAST(p.name AS TEXT)) LIKE LOWER(CONCAT('%', CAST(:keyword AS TEXT), '%'))",
            nativeQuery = true)
    Page<Policy> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);

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

    default List<Policy> findPoliciesMatchingUrl(String requestUrl) {
        AntPathMatcher pathMatcher = new AntPathMatcher();
        return findAllUrlPoliciesWithDetails().stream()
                .filter(policy -> policy.getTargets().stream()
                        .anyMatch(target -> pathMatcher.match(target.getTargetIdentifier(), requestUrl)))
                .toList();
    }

    Page<Policy> findBySourceAndApprovalStatus(
        Policy.PolicySource source,
        Policy.ApprovalStatus status,
        Pageable pageable
    );

    Page<Policy> findBySourceInAndApprovalStatus(
        List<Policy.PolicySource> sources,
        Policy.ApprovalStatus status,
        Pageable pageable
    );

    Page<Policy> findBySource(Policy.PolicySource source, Pageable pageable);

    Page<Policy> findBySourceIn(List<Policy.PolicySource> sources, Pageable pageable);

    long countBySource(Policy.PolicySource source);

    long countBySourceIn(List<Policy.PolicySource> sources);

    long countBySourceInAndApprovalStatus(
        List<Policy.PolicySource> sources,
        Policy.ApprovalStatus status
    );

    long countBySourceInAndApprovalStatusInAndUpdatedAtAfter(
        List<Policy.PolicySource> sources,
        List<Policy.ApprovalStatus> statuses,
        LocalDateTime since
    );

    long countBySourceInAndApprovalStatusAndUpdatedAtAfter(
        List<Policy.PolicySource> sources,
        Policy.ApprovalStatus status,
        LocalDateTime since
    );

    @Query("SELECT AVG(p.confidenceScore) FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') AND p.confidenceScore IS NOT NULL")
    Double calculateAverageConfidenceScoreForAIPolicies();

    @Query("SELECT p FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') " +
           "AND p.isActive = true AND p.approvalStatus = 'APPROVED'")
    List<Policy> findActiveAIPolicies();

    @Query("SELECT p FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') " +
           "AND p.confidenceScore >= :minScore")
    List<Policy> findAIPoliciesWithMinConfidence(@Param("minScore") double minScore);

    @Query("SELECT p FROM Policy p " +
           "WHERE p.source IN ('AI_GENERATED', 'AI_EVOLVED') " +
           "AND p.createdAt >= :since " +
           "ORDER BY p.createdAt DESC")
    Page<Policy> findRecentAIPolicies(@Param("since") LocalDateTime since, Pageable pageable);

    long countByIsActiveTrue();

    List<Policy> findTop5ByOrderByCreatedAtDesc();
}