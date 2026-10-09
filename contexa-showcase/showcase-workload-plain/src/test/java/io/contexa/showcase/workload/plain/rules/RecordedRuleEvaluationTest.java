package io.contexa.showcase.workload.plain.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * H-10: the rule classes decide a recorded request again under other settings, from the facts each control recorded.
 * The facts below are those control C1 and C2 recorded for the approved GB-500 transfer (A3ST, 2026-10-06).
 */
class RecordedRuleEvaluationTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    private static final String C1 = """
            {"companyTime": "2026-09-30T03:17:00Z", "night": true, "items": 4831, "projectKey": "GB-500",
             "accessDaysLast30": 0, "lastAccessDate": null}""";

    private static final String C2 = """
            {"items": 4831, "oncall": {"team": null, "endsAt": null, "onCall": false, "startsAt": null,
             "rosterKey": null}, "policy": {"policyKey": "EXPORT_APPROVAL", "description": "export policy",
             "assignedExportLimit": 500, "ticketAndOncallExempt": true}, "ticket": {"covered": false, "purpose": null,
             "approver": null, "ticketKey": null, "validFrom": null, "mismatches": ["NO_TICKET"], "validUntil": null},
             "network": {"city": null, "kind": "OFFICE", "country": null, "network": "10.40.12.0/24",
             "planKey": null, "clientIp": "10.40.12.135"}, "approval": {"covered": true,
             "purpose": "PROJECT_TRANSFER", "approver": "pm-11", "maxItems": 5000,
             "validFrom": "2026-09-29T03:17:00Z", "approvedAt": null, "mismatches": [],
             "validUntil": "2026-10-01T03:17:00Z", "approvalKey": "APR-fff995ae1d17-1"},
             "assigned": {"assigned": false, "responsibility": null}, "projectKey": "GB-500",
             "accessDaysLast30": 0}""";

    private final RecordedRuleEvaluation.Step step = new RecordedRuleEvaluation.Step("EXPORT_STREAM",
            "vfff995ae1d17-adm-a", Instant.parse("2026-09-30T03:17:00Z"), C1, C2);

    private RuleSettings with(LocalTime start, LocalTime end, int volume, boolean dormant, boolean approval,
                              Integer assignedLimit) {
        RuleSettings frozen = RuleSettings.FROZEN;
        return new RuleSettings(start, end, volume, dormant, frozen.external(), frozen.falseClaim(), approval,
                frozen.ticket(), frozen.assigned(), assignedLimit, frozen.history());
    }

    @Test
    void theFrozenSettingsGiveTheRecordedDecisions() {
        RecordedRuleEvaluation.Result result = RecordedRuleEvaluation.evaluate(step, RuleSettings.FROZEN, json);
        assertThat(result.c1().ruleId()).isEqualTo("C1-NIGHT");
        assertThat(result.c1().allowed()).isFalse();
        assertThat(result.c2().ruleId()).as("as control C2 recorded it").isEqualTo("C2-APPROVAL");
        assertThat(result.c2().allowed()).isTrue();
    }

    @Test
    void eachThresholdSettingIsTheRuleClassOwn() {
        LocalTime noon = LocalTime.NOON;
        assertThat(RecordedRuleEvaluation.evaluate(step, with(noon, noon, 500, true, true, null), json).c1().ruleId())
                .as("no night window: the volume limit decides").isEqualTo("C1-VOLUME");
        assertThat(RecordedRuleEvaluation.evaluate(step, with(noon, noon, 10_000, true, true, null), json).c1()
                .ruleId()).as("no recent access to GB-500").isEqualTo("C1-DORMANT");
        assertThat(RecordedRuleEvaluation.evaluate(step, with(noon, noon, 10_000, false, true, null), json).c1()
                .ruleId()).isEqualTo("C1-PASS");
        assertThat(RecordedRuleEvaluation.evaluate(step,
                with(LocalTime.of(1, 0), LocalTime.of(5, 0), 10_000, false, true, null), json).c1().ruleId())
                .as("a window that does not wrap past midnight").isEqualTo("C1-NIGHT");
    }

    @Test
    void aRecordSettingThatIsOffRemovesOnlyItsOwnReason() {
        RecordedRuleEvaluation.Result withoutApproval = RecordedRuleEvaluation.evaluate(step,
                with(ThresholdRules.NIGHT_START, ThresholdRules.NIGHT_END, 500, true, false, null), json);
        assertThat(withoutApproval.c2().ruleId()).as("not assigned, no ticket: the company policy refuses it")
                .isEqualTo("C2-NO-CONTEXT");
        assertThat(withoutApproval.c2().allowed()).isFalse();
    }

    @Test
    void aFactTheControlDidNotRecordIsNotGuessed() {
        RecordedRuleEvaluation.Step withoutNetwork = new RecordedRuleEvaluation.Step("EXPORT_STREAM",
                step.username(), step.companyTime(), C1, C2.replace("\"network\"", "\"elsewhere\""));
        RecordedRuleEvaluation.Result result = RecordedRuleEvaluation.evaluate(withoutNetwork, RuleSettings.FROZEN,
                json);
        assertThat(result.c2().notRecorded()).isEqualTo("network");
        assertThat(result.c2().ruleId()).isNull();
        assertThat(result.c1().ruleId()).as("control C1 recorded its own facts").isEqualTo("C1-NIGHT");
    }
}
