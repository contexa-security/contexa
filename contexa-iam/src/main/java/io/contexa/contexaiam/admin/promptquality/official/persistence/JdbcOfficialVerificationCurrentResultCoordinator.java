package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCurrentResultCoordinator;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.Locale;

public final class JdbcOfficialVerificationCurrentResultCoordinator
        implements OfficialVerificationCurrentResultCoordinator {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationCurrentResultCoordinator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void acquireWriteLock(
            String packageId,
            String tenantId,
            String requestPath,
            String resourceId,
            String httpMethod) {
        String normalizedTenantId = requiredTenantId(tenantId);
        String resourceRef = firstNonBlank(requestPath, resourceId, packageId);
        String lockKey = normalize(normalizedTenantId) + "|" + normalize(httpMethod) + "|" + normalize(resourceRef);
        jdbcTemplate.queryForObject("""
                        select true
                          from (
                                select pg_advisory_xact_lock(hashtextextended(?, 0))
                               ) snapshot_write_lock
                        """,
                Boolean.class,
                lockKey);
    }

    @Override
    public void supersedeCurrent(
            String aggregateRunId,
            String tenantId,
            String requestPath,
            String resourceId,
            String httpMethod) {
        String normalizedTenantId = requiredTenantId(tenantId);
        String resourceRef = firstNonBlank(requestPath, resourceId);
        if (!StringUtils.hasText(aggregateRunId)
                || !StringUtils.hasText(resourceRef)
                || !StringUtils.hasText(httpMethod)) {
            return;
        }
        jdbcTemplate.update("""
                        update official_verification_run_batch run
                           set current_result = false
                         where run.current_result = true
                           and run.aggregate_run_id <> ?
                           and run.tenant_id = ?
                           and upper(coalesce(run.http_method, '')) = upper(?)
                           and lower(coalesce(nullif(run.actual_request_path, ''),
                                              nullif(run.resource_url_template, ''),
                                              nullif(run.actual_resource_id, ''),
                                              '')) = lower(?)
                        """,
                aggregateRunId,
                normalizedTenantId,
                httpMethod.trim(),
                resourceRef);
        deactivateMetricRows(tenantId, httpMethod, resourceRef);
        deactivateFindingRows(tenantId, httpMethod, resourceRef);
        deactivateProblemRows(tenantId, httpMethod, resourceRef);
    }

    private void deactivateMetricRows(String normalizedTenantId, String httpMethod, String resourceRef) {
        jdbcTemplate.update("""
                        update official_verification_metric_snapshot metric
                           set current_result = false
                         where metric.current_result = true
                           and exists (
                               select 1
                                 from official_verification_run_batch run
                                where run.package_id = metric.package_id
                                  and run.aggregate_run_id = metric.aggregate_run_id
                                  and run.current_result = false
                                  and run.tenant_id = ?
                                  and upper(coalesce(run.http_method, '')) = upper(?)
                                  and lower(coalesce(nullif(run.actual_request_path, ''),
                                                     nullif(run.resource_url_template, ''),
                                                     nullif(run.actual_resource_id, ''),
                                                     '')) = lower(?)
                           )
                        """,
                normalizedTenantId,
                httpMethod.trim(),
                resourceRef);
    }

    private void deactivateFindingRows(String normalizedTenantId, String httpMethod, String resourceRef) {
        jdbcTemplate.update("""
                        update official_verification_operator_finding finding
                           set current_result = false
                         where finding.current_result = true
                           and exists (
                               select 1
                                 from official_verification_run_batch run
                                where run.package_id = finding.package_id
                                  and run.aggregate_run_id = finding.aggregate_run_id
                                  and run.current_result = false
                                  and run.tenant_id = ?
                                  and upper(coalesce(run.http_method, '')) = upper(?)
                                  and lower(coalesce(nullif(run.actual_request_path, ''),
                                                     nullif(run.resource_url_template, ''),
                                                     nullif(run.actual_resource_id, ''),
                                                     '')) = lower(?)
                           )
                        """,
                normalizedTenantId,
                httpMethod.trim(),
                resourceRef);
    }

    private void deactivateProblemRows(String normalizedTenantId, String httpMethod, String resourceRef) {
        jdbcTemplate.update("""
                        update official_actual_prompt_problem_ledger problem
                           set current_result = false
                         where problem.current_result = true
                           and exists (
                               select 1
                                 from official_verification_run_batch run
                                where run.package_id = problem.package_id
                                  and run.aggregate_run_id = problem.aggregate_run_id
                                  and run.current_result = false
                                  and run.tenant_id = ?
                                  and upper(coalesce(run.http_method, '')) = upper(?)
                                  and lower(coalesce(nullif(run.actual_request_path, ''),
                                                     nullif(run.resource_url_template, ''),
                                                     nullif(run.actual_resource_id, ''),
                                                     '')) = lower(?)
                           )
                        """,
                normalizedTenantId,
                httpMethod.trim(),
                resourceRef);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String requiredTenantId(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            throw new IllegalArgumentException("tenantId is required for official verification current-result mutation.");
        }
        return tenantId.trim();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}