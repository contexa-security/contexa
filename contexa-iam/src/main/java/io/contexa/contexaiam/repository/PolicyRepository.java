/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.SpelLiteral;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.util.AntPathMatcher;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;

public interface PolicyRepository extends JpaRepository<Policy, Long> {

    @Query(value = "SELECT p.id FROM Policy p " +
            "WHERE (:pattern IS NULL OR LOWER(p.name) LIKE :pattern)" +
            " AND (:approvalStatus IS NULL OR p.approvalStatus = :approvalStatus)" +
            " AND (:activeFilter IS NULL OR p.isActive = :activeFilter)",
            countQuery = "SELECT COUNT(p) FROM Policy p " +
            "WHERE (:pattern IS NULL OR LOWER(p.name) LIKE :pattern)" +
            " AND (:approvalStatus IS NULL OR p.approvalStatus = :approvalStatus)" +
            " AND (:activeFilter IS NULL OR p.isActive = :activeFilter)")
    Page<Long> searchIdsByFilters(@Param("pattern") String pattern,
                                  @Param("approvalStatus") Policy.ApprovalStatus approvalStatus,
                                  @Param("activeFilter") Boolean activeFilter,
                                  Pageable pageable);

    @Query(value = "SELECT p.id FROM Policy p WHERE :pattern IS NULL OR LOWER(p.name) LIKE :pattern",
            countQuery = "SELECT COUNT(p) FROM Policy p WHERE :pattern IS NULL OR LOWER(p.name) LIKE :pattern")
    Page<Long> searchIdsByKeyword(@Param("pattern") String pattern, Pageable pageable);

    @Query("SELECT DISTINCT p FROM Policy p LEFT JOIN FETCH p.targets WHERE p.id IN :ids")
    List<Policy> findAllWithTargetsByIdIn(@Param("ids") Collection<Long> ids);

    default Page<Policy> searchByFilters(String pattern, Policy.ApprovalStatus approvalStatus, Boolean activeFilter,
                                         Pageable pageable) {
        return withTargets(searchIdsByFilters(pattern, approvalStatus, activeFilter, pageable));
    }

    default Page<Policy> searchByKeyword(String pattern, Pageable pageable) {
        return withTargets(searchIdsByKeyword(pattern, pageable));
    }

    /**
     * PR-4: a page and a fetched collection in one query cannot be cut in the database, so Hibernate read every policy into
     * memory for each page. The page is cut on the ids, and the targets are read for those policies only.
     */
    private Page<Policy> withTargets(Page<Long> ids) {
        if (ids.isEmpty()) {
            return new PageImpl<>(List.of(), ids.getPageable(), ids.getTotalElements());
        }
        Map<Long, Policy> policies = findAllWithTargetsByIdIn(ids.getContent()).stream()
                .collect(Collectors.toMap(Policy::getId, Function.identity()));
        List<Policy> page = ids.getContent().stream().map(policies::get).filter(Objects::nonNull).toList();
        return new PageImpl<>(page, ids.getPageable(), ids.getTotalElements());
    }

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
            "ORDER BY t.targetOrder ASC, p.priority ASC")
    List<Policy> findByTargetTypeWithDetails(@Param("targetType") String targetType);

    @Query("SELECT p FROM Policy p JOIN FETCH p.targets t " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions c " +
            "WHERE t.targetType = 'METHOD' AND t.targetIdentifier = :methodIdentifier " +
            "ORDER BY t.targetOrder ASC, p.priority ASC")
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
            "LEFT JOIN FETCH p.targets " +
            "LEFT JOIN FETCH p.rules r " +
            "LEFT JOIN FETCH r.conditions " +
            "ORDER BY p.id DESC")
    List<Policy> findTop5ByOrderByIdDesc();

    @Query("SELECT DISTINCT p FROM Policy p " +
            "LEFT JOIN FETCH p.targets " +
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

    @Query("SELECT COUNT(p) FROM Policy p JOIN p.targets t " +
           "WHERE t.targetType = :targetType AND t.targetIdentifier = :targetIdentifier " +
           "AND p.id <> :excludePolicyId")
    long countOtherPoliciesForTarget(
            @Param("targetType") String targetType,
            @Param("targetIdentifier") String targetIdentifier,
            @Param("excludePolicyId") Long excludePolicyId);

    @Query("SELECT p.source, COUNT(p) FROM Policy p GROUP BY p.source")
    List<Object[]> countGroupBySource();

    @Query("SELECT p.approvalStatus, COUNT(p) FROM Policy p WHERE p.source IN :sources GROUP BY p.approvalStatus")
    List<Object[]> countAIApprovalGroupByStatus(@Param("sources") List<Policy.PolicySource> sources);

    @Query("SELECT p.approvalStatus, COUNT(p) FROM Policy p GROUP BY p.approvalStatus")
    List<Object[]> countGroupByApprovalStatus();

    /**
     * The id and expression of each condition of an active policy whose text contains the given text. A plain search of
     * the text: a {@code %} or {@code _} in it is a character, not a wildcard. A text that contains the name is not yet
     * a condition that names it, which {@link #findActivePoliciesReferencing} decides.
     */
    @Query("SELECT p.id, c.expression FROM Policy p " +
           "JOIN p.rules r JOIN r.conditions c " +
           "WHERE p.isActive = true AND LOCATE(:text, c.expression) > 0")
    List<Object[]> findActiveConditionsContainingText(@Param("text") String text);

    /**
     * The active policies with a condition that has a SpEL literal exactly equal to one of the names: the policies a
     * role or permission is named in. A name that is only a part of a longer literal does not count, so the policies
     * of {@code ROLE_O} are not the policies of {@code ROLE_OTHER}, and a name with a quote is found as the literal
     * that doubles the quote.
     */
    default List<Policy> findActivePoliciesReferencing(Collection<String> names) {
        Set<Long> ids = new TreeSet<>();
        for (String name : new LinkedHashSet<>(names)) {
            if (name == null || name.isEmpty()) {
                continue;
            }
            for (Object[] condition : findActiveConditionsContainingText(SpelLiteral.quote(name))) {
                if (SpelLiteral.holds((String) condition[1], name)) {
                    ids.add((Long) condition[0]);
                }
            }
        }
        if (ids.isEmpty()) {
            return List.of();
        }
        return findAllById(ids).stream().sorted(Comparator.comparing(Policy::getId)).toList();
    }
}