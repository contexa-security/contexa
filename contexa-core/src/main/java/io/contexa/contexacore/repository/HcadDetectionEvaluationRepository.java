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
package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.HcadDetectionEvaluation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface HcadDetectionEvaluationRepository extends JpaRepository<HcadDetectionEvaluation, String> {

    List<HcadDetectionEvaluation> findTop50ByCreatedAtBetweenOrderByCreatedAtDesc(
            LocalDateTime from,
            LocalDateTime to);

    List<HcadDetectionEvaluation> findTop25ByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc(
            String outcomeClass,
            LocalDateTime from,
            LocalDateTime to);

    long countByCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    long countByTriggeredLlmTrueAndCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    long countByDuplicateSuppressedTrueAndCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    long countByOutcomeClassAndCreatedAtBetween(String outcomeClass, LocalDateTime from, LocalDateTime to);

    List<HcadDetectionEvaluation> findByActorSessionKeyAndWindowId(String actorSessionKey, String windowId);

    @Query("""
            select coalesce(sum(e.requestCount), 0)
              from HcadDetectionEvaluation e
             where e.createdAt between :from and :to
            """)
    Long sumRequestCountBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query("""
            select coalesce(sum(e.duplicateSuppressedCount), 0)
              from HcadDetectionEvaluation e
             where e.createdAt between :from and :to
            """)
    Long sumDuplicateSuppressedCountBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query("""
            select avg(e.llmLatencyMs)
              from HcadDetectionEvaluation e
             where e.createdAt between :from and :to
               and e.llmLatencyMs is not null
            """)
    Double averageLlmLatencyMsBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query("""
            select e.mode, count(e)
              from HcadDetectionEvaluation e
             where e.createdAt between :from and :to
             group by e.mode
             order by count(e) desc
            """)
    List<Object[]> countByModeBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select signal.value as signal,
                   count(*) as candidate_count,
                   sum(case when e.outcome_class = 'TP' then 1 else 0 end) as tp_count,
                   sum(case when e.outcome_class = 'FP' then 1 else 0 end) as fp_count,
                   sum(case when e.outcome_class = 'UNKNOWN' then 1 else 0 end) as unknown_count
              from hcad_detection_evaluation e
              join lateral jsonb_array_elements_text(
                   case
                     when e.reason_codes is null or trim(e.reason_codes) = '' or trim(e.reason_codes) = 'null' then '[]'::jsonb
                     else e.reason_codes::jsonb
                   end
              ) as signal(value) on true
             where e.created_at between :from and :to
             group by signal.value
             order by count(*) desc, signal.value asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateBySignalBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            @Param("limit") int limit);

    @Query(value = """
            select resource.value as resource_family,
                   'WINDOW' as http_method,
                   count(*) as candidate_count,
                   sum(case when e.outcome_class = 'TP' then 1 else 0 end) as tp_count,
                   sum(case when e.outcome_class = 'FP' then 1 else 0 end) as fp_count,
                   sum(coalesce(e.duplicate_suppressed_count, case when e.duplicate_suppressed = true then 1 else 0 end)) as duplicate_count
              from hcad_detection_evaluation e
              join lateral jsonb_array_elements_text(
                   case
                     when e.resource_families is null or trim(e.resource_families) = '' or trim(e.resource_families) = 'null' then jsonb_build_array(coalesce(e.request_path, 'unknown'))
                     else e.resource_families::jsonb
                   end
              ) as resource(value) on true
             where e.created_at between :from and :to
             group by resource.value
             order by count(*) desc, resource.value asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateByResourceBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            @Param("limit") int limit);

    @Query(value = """
            select coalesce(e.user_id, 'unknown') as user_id,
                   coalesce(e.actor_session_key, e.context_binding_hash, 'unknown') as actor_session_key,
                   count(*) as candidate_count,
                   sum(case when e.triggered_llm = true then 1 else 0 end) as triggered_count,
                   sum(coalesce(e.duplicate_suppressed_count, case when e.duplicate_suppressed = true then 1 else 0 end)) as duplicate_count,
                   sum(case when e.outcome_class = 'TP' then 1 else 0 end) as tp_count,
                   sum(case when e.outcome_class = 'FP' then 1 else 0 end) as fp_count,
                   sum(case when e.outcome_class = 'UNKNOWN' then 1 else 0 end) as unknown_count
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
             group by coalesce(e.user_id, 'unknown'), coalesce(e.actor_session_key, e.context_binding_hash, 'unknown')
             order by count(*) desc, coalesce(e.user_id, 'unknown') asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateByUserSessionBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            @Param("limit") int limit);
}
