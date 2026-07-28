package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCustomerDisplayIntegrityRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class JdbcOfficialVerificationCustomerDisplayIntegrityRepository
        implements OfficialVerificationCustomerDisplayIntegrityRepository {

    private static final List<String> SUPPORTED_ROLES = List.of(
            "TITLE", "PASS_EVIDENCE", "FAIL_EVIDENCE", "WHY_IT_MATTERS", "RESOLUTION_ACTION", "REVERIFY_CONDITION");

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationCustomerDisplayIntegrityRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void assertPayloadComplete(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return;
        }
        int expected = count("""
                select coalesce(sum(case when purpose_result = 'PURPOSE_FAILED' then 5 else 3 end), 0)
                  from official_metric_purpose_evaluation_ledger
                 where aggregate_run_id = ?
                   and customer_visible = true
                   and purpose_result <> 'INPUT_NOT_READY'
                """, aggregateRunId);
        int actual = count("""
                select count(*) from official_metric_customer_display_payload where aggregate_run_id = ?
                """, aggregateRunId);
        if (expected != actual) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload row count mismatch."
                    + " aggregateRunId=" + aggregateRunId + ", expectedRows=" + expected + ", actualRows=" + actual);
        }
        int emptyContextItems = count("""
                select count(*) from official_metric_customer_display_payload
                 where aggregate_run_id = ? and coalesce(context_items_json::text, '[]') = '[]'
                """, aggregateRunId);
        if (emptyContextItems > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload is missing contract context items."
                    + " aggregateRunId=" + aggregateRunId + ", emptyContextItemRows=" + emptyContextItems);
        }
    }

    @Override
    public void assertContractRole(String purposeVersion, String metricCode, String checkCode, String displayRole) {
        if (!SUPPORTED_ROLES.contains(displayRole)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload role is not supported."
                    + " metric=" + safe(metricCode) + ", check=" + safe(checkCode) + ", displayRole=" + safe(displayRole));
        }
        int count = count("""
                select count(*) from official_metric_customer_display_contract
                 where contract_version = ? and upper(metric_code) = ? and check_code = ? and display_role = ?
                """, purposeVersion, normalize(metricCode), checkCode, displayRole);
        if (count < 1) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload role is not contract-backed."
                    + " metric=" + safe(metricCode) + ", check=" + safe(checkCode)
                    + ", displayRole=" + safe(displayRole) + ", contractVersion=" + safe(purposeVersion));
        }
    }

    @Override
    public boolean contractedPromptSignal(String item) {
        if (!StringUtils.hasText(item)) {
            return false;
        }
        try {
            return count("""
                    select count(*) from official_prompt_signal_contract
                     where lower(signal_key) in (lower(?), lower(concat('label:', ?)), lower(concat('section:', ?)))
                       and coalesce(prompt_location, '') <> ''
                    """, item.trim(), item.trim(), item.trim()) > 0;
        }
        catch (DataAccessException ignored) {
            return false;
        }
    }

    private int count(String sql, Object... arguments) {
        Integer value = jdbcTemplate.queryForObject(sql, Integer.class, arguments);
        return value == null ? 0 : value;
    }

    private String normalize(String value) {
        return safe(value).trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}
