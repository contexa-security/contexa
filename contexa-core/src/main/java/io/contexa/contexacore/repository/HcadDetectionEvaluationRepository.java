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

    String MONITORABLE_REQUEST_CONDITION = """
               and not (
                   lower(coalesce(e.request_path, '')) in ('/favicon.ico', '/manifest.json', '/manifest.webmanifest', '/robots.txt')
                   or lower(coalesce(e.request_path, '')) like '/assets/%'
                   or lower(coalesce(e.request_path, '')) like '/css/%'
                   or lower(coalesce(e.request_path, '')) like '/fonts/%'
                   or lower(coalesce(e.request_path, '')) like '/img/%'
                   or lower(coalesce(e.request_path, '')) like '/images/%'
                   or lower(coalesce(e.request_path, '')) like '/static/%'
                   or lower(coalesce(e.request_path, '')) like '/webjars/%'
                   or lower(coalesce(e.request_path, '')) like '/.well-known/appspecific/%'
                   or lower(coalesce(e.request_path, '')) like '%.avif'
                   or lower(coalesce(e.request_path, '')) like '%.css'
                   or lower(coalesce(e.request_path, '')) like '%.eot'
                   or lower(coalesce(e.request_path, '')) like '%.gif'
                   or lower(coalesce(e.request_path, '')) like '%.ico'
                   or lower(coalesce(e.request_path, '')) like '%.jpeg'
                   or lower(coalesce(e.request_path, '')) like '%.jpg'
                   or lower(coalesce(e.request_path, '')) like '%.js'
                   or lower(coalesce(e.request_path, '')) like '%.map'
                   or lower(coalesce(e.request_path, '')) like '%.mjs'
                   or lower(coalesce(e.request_path, '')) like '%.otf'
                   or lower(coalesce(e.request_path, '')) like '%.png'
                   or lower(coalesce(e.request_path, '')) like '%.svg'
                   or lower(coalesce(e.request_path, '')) like '%.ttf'
                   or lower(coalesce(e.request_path, '')) like '%.webp'
                   or lower(coalesce(e.request_path, '')) like '%.woff'
                   or lower(coalesce(e.request_path, '')) like '%.woff2'
               )
            """;

    String MONITORABLE_RESOURCE_VALUE_CONDITION = """
               and not (
                   lower(coalesce(resource.value, '')) in ('/favicon.ico', '/manifest.json', '/manifest.webmanifest', '/robots.txt')
                   or lower(coalesce(resource.value, '')) like '/assets/%'
                   or lower(coalesce(resource.value, '')) like '/css/%'
                   or lower(coalesce(resource.value, '')) like '/fonts/%'
                   or lower(coalesce(resource.value, '')) like '/img/%'
                   or lower(coalesce(resource.value, '')) like '/images/%'
                   or lower(coalesce(resource.value, '')) like '/static/%'
                   or lower(coalesce(resource.value, '')) like '/webjars/%'
                   or lower(coalesce(resource.value, '')) like '/.well-known/appspecific/%'
                   or lower(coalesce(resource.value, '')) like '%.avif'
                   or lower(coalesce(resource.value, '')) like '%.css'
                   or lower(coalesce(resource.value, '')) like '%.eot'
                   or lower(coalesce(resource.value, '')) like '%.gif'
                   or lower(coalesce(resource.value, '')) like '%.ico'
                   or lower(coalesce(resource.value, '')) like '%.jpeg'
                   or lower(coalesce(resource.value, '')) like '%.jpg'
                   or lower(coalesce(resource.value, '')) like '%.js'
                   or lower(coalesce(resource.value, '')) like '%.map'
                   or lower(coalesce(resource.value, '')) like '%.mjs'
                   or lower(coalesce(resource.value, '')) like '%.otf'
                   or lower(coalesce(resource.value, '')) like '%.png'
                   or lower(coalesce(resource.value, '')) like '%.svg'
                   or lower(coalesce(resource.value, '')) like '%.ttf'
                   or lower(coalesce(resource.value, '')) like '%.webp'
                   or lower(coalesce(resource.value, '')) like '%.woff'
                   or lower(coalesce(resource.value, '')) like '%.woff2'
               )
            """;

    List<HcadDetectionEvaluation> findTop50ByCreatedAtBetweenOrderByCreatedAtDesc(
            LocalDateTime from,
            LocalDateTime to);

    List<HcadDetectionEvaluation> findTop25ByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc(
            String outcomeClass,
            LocalDateTime from,
            LocalDateTime to);

    @Query(value = """
            select *
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             order by e.created_at desc
             limit 50
            """, nativeQuery = true)
    List<HcadDetectionEvaluation> findTop50MonitorableByCreatedAtBetweenOrderByCreatedAtDesc(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select *
              from hcad_detection_evaluation e
             where e.outcome_class = :outcomeClass
               and e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             order by e.created_at desc
             limit 25
            """, nativeQuery = true)
    List<HcadDetectionEvaluation> findTop25MonitorableByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc(
            @Param("outcomeClass") String outcomeClass,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    long countByCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableByCreatedAtBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    long countByTriggeredLlmTrueAndCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.triggered_llm = true
               and e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableByTriggeredLlmTrueAndCreatedAtBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    long countByDuplicateSuppressedTrueAndCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    long countByEligibleTrueAndCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.eligible = true
               and e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableByEligibleTrueAndCreatedAtBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    long countByEligibleFalseAndCreatedAtBetween(LocalDateTime from, LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.eligible = false
               and e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableByEligibleFalseAndCreatedAtBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    long countByOutcomeClassAndCreatedAtBetween(String outcomeClass, LocalDateTime from, LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.outcome_class = :outcomeClass
               and e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableByOutcomeClassAndCreatedAtBetween(
            @Param("outcomeClass") String outcomeClass,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.outcome_class = :outcomeClass
               and e.created_at between :from and :to
               and (
                    e.decided_at is not null
                 or e.triggered_llm = true
                 or e.llm_action is not null
                 or e.llm_risk_score is not null
                 or e.llm_parser_failure = true
                 or e.llm_technical_fallback = true
               )
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableComparableByOutcomeClassAndCreatedAtBetween(
            @Param("outcomeClass") String outcomeClass,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    List<HcadDetectionEvaluation> findByActorSessionKeyAndWindowId(String actorSessionKey, String windowId);

    @Query("""
            select coalesce(sum(e.requestCount), 0)
              from HcadDetectionEvaluation e
             where e.createdAt between :from and :to
            """)
    Long sumRequestCountBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select coalesce(sum(e.request_count), 0)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    Long sumMonitorableRequestCountBetween(
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

    @Query(value = """
            select coalesce(sum(e.duplicate_suppressed_count), 0)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    Long sumMonitorableDuplicateSuppressedCountBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query("""
            select coalesce(sum(e.negativeCacheHitCount), 0)
              from HcadDetectionEvaluation e
             where e.createdAt between :from and :to
            """)
    Long sumNegativeCacheHitCountBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select coalesce(sum(e.negative_cache_hit_count), 0)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    Long sumMonitorableNegativeCacheHitCountBetween(
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

    @Query(value = """
            select avg(e.llm_latency_ms)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
               and e.llm_latency_ms is not null
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    Double averageMonitorableLlmLatencyMsBetween(
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
            select coalesce(e.mode, 'UNKNOWN') as mode,
                   count(*) as count
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by e.mode
             order by count(*) desc
            """, nativeQuery = true)
    List<Object[]> countMonitorableByModeBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select coalesce(e.early_analysis_score::text, 'UNKNOWN') as score,
                   count(*) as count
             from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by e.early_analysis_score
             order by count(*) desc, score asc
            """, nativeQuery = true)
    List<Object[]> countByScoreBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select coalesce(e.band, 'UNKNOWN') as band,
                   count(*) as count
             from hcad_detection_evaluation e
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by e.band
             order by count(*) desc, band asc
            """, nativeQuery = true)
    List<Object[]> countByBandBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select score_bucket,
                   sum(case when normalized_band = 'LOW' then bucket_count else 0 end) as low_count,
                   sum(case when normalized_band = 'MEDIUM' then bucket_count else 0 end) as medium_count,
                   sum(case when normalized_band = 'HIGH' then bucket_count else 0 end) as high_count,
                   sum(case when normalized_band = 'REDLINE' then bucket_count else 0 end) as redline_count,
                   sum(case when normalized_band not in ('LOW', 'MEDIUM', 'HIGH', 'REDLINE') then bucket_count else 0 end) as unknown_count,
                   sum(bucket_count) as total_count
              from (
                    select case
                             when e.early_analysis_score is null then 'UNKNOWN'
                             when e.early_analysis_score < 20 then '0-19'
                             when e.early_analysis_score < 40 then '20-39'
                             when e.early_analysis_score < 60 then '40-59'
                             when e.early_analysis_score < 80 then '60-79'
                             else '80-100'
                           end as score_bucket,
                           upper(coalesce(e.band, 'UNKNOWN')) as normalized_band,
                           count(*) as bucket_count
                      from hcad_detection_evaluation e
                     where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
                     group by 1, 2
              ) buckets
             group by score_bucket
             order by case score_bucket
                        when '0-19' then 1
                        when '20-39' then 2
                        when '40-59' then 3
                        when '60-79' then 4
                        when '80-100' then 5
                        else 6
                      end
            """, nativeQuery = true)
    List<Object[]> countByScoreBandBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
               and e.anchor_signals is not null
               and trim(e.anchor_signals) not in ('', '[]', 'null')
            """, nativeQuery = true)
    long countEscalationBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            select count(*)
              from hcad_detection_evaluation e
             where e.created_at between :from and :to
               and e.anchor_signals is not null
               and trim(e.anchor_signals) not in ('', '[]', 'null')
            """ + MONITORABLE_REQUEST_CONDITION, nativeQuery = true)
    long countMonitorableEscalationBetween(
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
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by signal.value
             order by count(*) desc, signal.value asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateBySignalBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            @Param("limit") int limit);

    @Query(value = """
            select signal.value as signal,
                   count(*) as candidate_count,
                   sum(case when e.outcome_class = 'TP' then 1 else 0 end) as tp_count,
                   sum(case when e.outcome_class = 'FP' then 1 else 0 end) as fp_count,
                   sum(case when e.outcome_class = 'UNKNOWN' then 1 else 0 end) as unknown_count
              from hcad_detection_evaluation e
              join lateral jsonb_array_elements_text(
                   case
                     when e.anchor_signals is null or trim(e.anchor_signals) = '' or trim(e.anchor_signals) = 'null' then '[]'::jsonb
                     else e.anchor_signals::jsonb
                   end
             ) as signal(value) on true
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by signal.value
             order by count(*) desc, signal.value asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateByAnchorSignalBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            @Param("limit") int limit);

    @Query(value = """
            select signal.value as signal,
                   count(*) as candidate_count,
                   sum(case when e.outcome_class = 'TP' then 1 else 0 end) as tp_count,
                   sum(case when e.outcome_class = 'FP' then 1 else 0 end) as fp_count,
                   sum(case when e.outcome_class = 'UNKNOWN' then 1 else 0 end) as unknown_count
              from hcad_detection_evaluation e
              join lateral jsonb_array_elements_text(
                   case
                     when e.corroborating_signals is null or trim(e.corroborating_signals) = '' or trim(e.corroborating_signals) = 'null' then '[]'::jsonb
                     else e.corroborating_signals::jsonb
                   end
             ) as signal(value) on true
             where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by signal.value
             order by count(*) desc, signal.value asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateByCorroboratingSignalBetween(
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
            """ + MONITORABLE_REQUEST_CONDITION + """
            """ + MONITORABLE_RESOURCE_VALUE_CONDITION + """
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
            """ + MONITORABLE_REQUEST_CONDITION + """
             group by coalesce(e.user_id, 'unknown'), coalesce(e.actor_session_key, e.context_binding_hash, 'unknown')
             order by count(*) desc, coalesce(e.user_id, 'unknown') asc
             limit :limit
            """, nativeQuery = true)
    List<Object[]> aggregateByUserSessionBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            @Param("limit") int limit);

    @Query(value = """
            select reason_key, count(*) as count
              from (
                    select coalesce(
                             nullif(e.non_trigger_reason, ''),
                             case
                               when e.triggered_llm = true then 'TRIGGERED_LLM'
                               when coalesce(e.duplicate_suppressed, false) = true
                                 or coalesce(e.duplicate_suppressed_count, 0) > 0
                                 then 'DUPLICATE_SUPPRESSED'
                               when upper(coalesce(e.mode, '')) in ('OBSERVE', 'DISABLED')
                                 then 'POLICY_OBSERVE_ONLY'
                               when e.reason_codes is not null
                                 and upper(e.reason_codes) like '%RATE_LIMIT%'
                                 then 'RATE_LIMITED'
                               when e.eligible = true then 'ELIGIBLE_BUT_NOT_PUBLISHED'
                               when (e.anchor_signals is null or trim(e.anchor_signals) in ('', '[]', 'null'))
                                 and e.corroborating_signals is not null
                                 and trim(e.corroborating_signals) not in ('', '[]', 'null')
                                 then 'SUPPORTING_SIGNAL_ONLY'
                               when e.anchor_signals is null or trim(e.anchor_signals) in ('', '[]', 'null')
                                 then 'NO_TRUSTED_RISK_SIGNAL'
                               else 'NOT_TRIGGERED'
                             end
                           ) as reason_key
                      from hcad_detection_evaluation e
                     where e.created_at between :from and :to
                       and coalesce(e.triggered_llm, false) = false
                       and e.decided_at is null
            """ + MONITORABLE_REQUEST_CONDITION + """
              ) reasons
             group by reason_key
             order by count(*) desc, reason_key asc
            """, nativeQuery = true)
    List<Object[]> countMonitorableNonTriggerReasonsBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    @Query(value = """
            with monitorable_rows as (
                select e.anchor_signals,
                       e.corroborating_signals,
                       e.baseline_available,
                       e.evidence_gap_codes,
                       case
                         when e.signal_snapshot_json is null
                           or trim(e.signal_snapshot_json) = ''
                           or trim(e.signal_snapshot_json) = 'null'
                           then '{}'::jsonb
                         else e.signal_snapshot_json::jsonb
                       end as snapshot
                  from hcad_detection_evaluation e
                 where e.created_at between :from and :to
            """ + MONITORABLE_REQUEST_CONDITION + """
            )
            select coverage_key, count(*) as count
              from (
                    select case
                             when coalesce(baseline_available, false) = true
                               or snapshot #>> '{baselineComparison,available}' = 'true'
                               then 'PERSONAL_BASELINE_AVAILABLE'
                             when evidence_gap_codes is not null
                               and evidence_gap_codes like '%PERSONAL_BASELINE_INSUFFICIENT%'
                               then 'PERSONAL_BASELINE_INSUFFICIENT'
                             when snapshot #>> '{baselineComparison,missingDimensions}' like '%personalBaselineInsufficientSamples%'
                               then 'PERSONAL_BASELINE_INSUFFICIENT'
                             else 'PERSONAL_BASELINE_UNAVAILABLE'
                           end as coverage_key
                      from monitorable_rows
                    union all
                    select case
                             when anchor_signals is not null and trim(anchor_signals) not in ('', '[]', 'null')
                               then 'TRUSTED_ANCHOR_PRESENT'
                             else 'TRUSTED_ANCHOR_ABSENT'
                           end
                      from monitorable_rows
                    union all
                    select case
                             when corroborating_signals is not null and trim(corroborating_signals) not in ('', '[]', 'null')
                               then 'SUPPORTING_SIGNAL_PRESENT'
                             else 'SUPPORTING_SIGNAL_ABSENT'
                           end
                      from monitorable_rows
                    union all
                    select case
                             when jsonb_exists(snapshot, 'authorizationPrivileged')
                               and snapshot ->> 'authorizationPrivileged' is not null
                               then 'AUTHORIZATION_CONTEXT_PRESENT'
                             when jsonb_exists(snapshot, 'verificationRequired')
                               and snapshot ->> 'verificationRequired' is not null
                               then 'AUTHORIZATION_CONTEXT_PRESENT'
                             when jsonb_exists(snapshot, 'authorizationPolicyId')
                               and snapshot ->> 'authorizationPolicyId' is not null
                               then 'AUTHORIZATION_CONTEXT_PRESENT'
                             else 'AUTHORIZATION_CONTEXT_ABSENT'
                           end
                      from monitorable_rows
                    union all
                    select case
                             when jsonb_exists(snapshot, 'impossibleTravel')
                               and snapshot ->> 'impossibleTravel' is not null
                               then 'LOCATION_RISK_OBSERVED'
                             else 'LOCATION_RISK_NOT_OBSERVED'
                           end
                      from monitorable_rows
                    union all
                    select case
                             when coalesce((snapshot ->> 'failedLoginAttempts')::int, 0) > 0
                               then 'FAILED_LOGIN_HISTORY_PRESENT'
                             else 'FAILED_LOGIN_HISTORY_ABSENT'
                           end
                      from monitorable_rows
                    union all
                    select case
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%CACHE_MISS_SOURCE_AVAILABLE%'
                               then 'SEMANTIC_EVIDENCE_SOURCE_AVAILABLE'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceAvailable}' = 'true'
                               and snapshot #>> '{semanticEvidence,semanticEvidenceFreshHit}' = 'true'
                               then 'SEMANTIC_EVIDENCE_AVAILABLE'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceAvailable}' = 'true'
                               and snapshot #>> '{semanticEvidence,semanticEvidenceStaleHit}' = 'true'
                               then 'SEMANTIC_EVIDENCE_STALE'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%DIMENSION_MISMATCH%'
                               then 'SEMANTIC_EVIDENCE_DIMENSION_MISMATCH'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%VERSION_MISMATCH%'
                               then 'SEMANTIC_EVIDENCE_VERSION_MISMATCH'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%SEMANTIC_EVIDENCE_LOOKUP_TIMEOUT%'
                               then 'SEMANTIC_EVIDENCE_LOOKUP_TIMEOUT'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%SEMANTIC_EVIDENCE_LOOKUP_FAILED%'
                               then 'SEMANTIC_EVIDENCE_LOOKUP_FAILED'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%WARMUP_FAILED%'
                               then 'SEMANTIC_EVIDENCE_WARMUP_FAILED'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%WARMUP_QUEUED%'
                               then 'SEMANTIC_EVIDENCE_WARMUP_QUEUED'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%SEMANTIC_EVIDENCE_CACHE_MISS%'
                               then 'SEMANTIC_EVIDENCE_CACHE_MISS'
                             when snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%SOURCE_ABSENT%'
                               or snapshot #>> '{semanticEvidence,semanticEvidenceGapCodes}' like '%NEGATIVE_CACHE_HIT%'
                               then 'SEMANTIC_EVIDENCE_SOURCE_ABSENT'
                             when jsonb_exists(snapshot, 'semanticEvidence')
                               then 'SEMANTIC_EVIDENCE_MISSING'
                             else 'SEMANTIC_EVIDENCE_NOT_REQUESTED'
                           end
                      from monitorable_rows
              ) coverage
             group by coverage_key
             order by coverage_key asc
            """, nativeQuery = true)
    List<Object[]> countMonitorableEvidenceCoverageBetween(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);
}
