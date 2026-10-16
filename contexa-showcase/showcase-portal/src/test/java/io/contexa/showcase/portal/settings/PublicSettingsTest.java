package io.contexa.showcase.portal.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.anatomy.CoreAdverseLabels;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The settings the G3 window and the adoption screen show are copied from the workloads' published values; a value a
 * source does not state stays null (7.4 of docs/showcase/화면설계서-v2-구현계획.md).
 */
class PublicSettingsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void everyValueIsTheSourcesOwn() throws Exception {
        JsonNode rules = JSON.readTree("""
                {"c1":{"nightStart":"22:00","nightEnd":"06:00","volumeLimit":500,"dormantWindowDays":30},
                 "c2":{"exportApprovalPolicy":{"policyKey":"EXPORT_APPROVAL","assignedExportLimit":500,
                                                "ticketAndOncallExempt":true},
                       "accessApprovalPolicies":[{"policyKey":"CUSTOMER_ACCESS","accountManagerExempt":true,
                                                  "assignedExempt":false,"recentWorkDays":14}],
                       "historyWindowDays":90,"exportHistoryWindowDays":30},
                 "rbac":["GET /api/customers/* [ROLE_SUPPORT]"],
                 "sha256":"abc"}""");
        JsonNode engine = JSON.readTree("""
                {"chatModel":"gpt-5-nano","effectiveMode":"ENFORCE","behaviorRetentionDays":400}""");

        PublicSettings.View view = PublicSettings.of(rules, engine,
                new PublicSettings.Waf("coraza-crs:caddy-alpine", "OWASP Core Rule Set, defaults"), 90);

        assertThat(view.threshold()).isEqualTo(new PublicSettings.Threshold("22:00", "06:00", 500, 30));
        assertThat(view.businessRecord().exportPolicyKey()).isEqualTo("EXPORT_APPROVAL");
        assertThat(view.businessRecord().ticketAndOncallExempt()).isTrue();
        assertThat(view.businessRecord().accessPolicies()).singleElement()
                .isEqualTo(new PublicSettings.AccessPolicy("CUSTOMER_ACCESS", true, false, 14));
        assertThat(view.permission().roleRules()).containsExactly("GET /api/customers/* [ROLE_SUPPORT]");
        assertThat(view.engine()).isEqualTo(new PublicSettings.Engine("gpt-5-nano", "ENFORCE",
                CoreAdverseLabels.RULES.size()));
        assertThat(view.retention()).isEqualTo(new PublicSettings.Retention(400, 90));
        assertThat(view.ruleVersion()).isEqualTo("abc");
    }

    /** W7-13: the adoption screen's sealed inputs line is the engine's own capture share and clean period. */
    @Test
    void theSealedEvidenceIsTheEnginesOwn() throws Exception {
        PublicSettings.Waf waf = new PublicSettings.Waf(null, null);
        PublicSettings.View stated = PublicSettings.of(JSON.readTree("{}"), JSON.readTree("""
                {"sealedEvidence":{"samplePercent":100,"cleanPeriodDays":90}}"""), waf, 90);
        PublicSettings.View partly = PublicSettings.of(JSON.readTree("{}"), JSON.readTree("""
                {"sealedEvidence":{"samplePercent":100,"cleanPeriodDays":null}}"""), waf, 90);
        PublicSettings.View unstated = PublicSettings.of(JSON.readTree("{}"), JSON.readTree("""
                {"sealedEvidence":null}"""), waf, 90);

        assertThat(stated.sealedEvidence()).isEqualTo(new PublicSettings.SealedEvidence(100, 90));
        assertThat(partly.sealedEvidence()).isEqualTo(new PublicSettings.SealedEvidence(100, null));
        assertThat(unstated.sealedEvidence()).as("the engine states no capture").isNull();
        assertThat(PublicSettings.of(JSON.readTree("{}"), JSON.readTree("{}"), waf, 90).sealedEvidence()).isNull();
    }

    @Test
    void aValueTheSourceDoesNotStateStaysNull() throws Exception {
        PublicSettings.View view = PublicSettings.of(JSON.readTree("{}"), JSON.readTree("{}"),
                new PublicSettings.Waf(null, null), 90);

        assertThat(view.retention().behaviorDays()).as("the engine leaves the core's default in place").isNull();
        assertThat(view.threshold().volumeLimit()).isNull();
        assertThat(view.businessRecord().ticketAndOncallExempt()).isNull();
        assertThat(view.waf().image()).isNull();
    }
}
