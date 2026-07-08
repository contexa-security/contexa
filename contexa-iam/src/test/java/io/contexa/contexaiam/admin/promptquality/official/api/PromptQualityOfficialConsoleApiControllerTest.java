package io.contexa.contexaiam.admin.promptquality.official.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.TestingAuthenticationToken;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PromptQualityOfficialConsoleApiControllerTest {

    private final PromptQualityRuntimeVerificationService verificationService = mock(PromptQualityRuntimeVerificationService.class);
    private final PromptQualityOfficialRunDetailService runDetailService = mock(PromptQualityOfficialRunDetailService.class);
    private final PromptQualityOfficialConsoleApiController controller = new PromptQualityOfficialConsoleApiController(
            mock(SealedEvidencePackageLookupService.class),
            verificationService,
            runDetailService,
            mock(OfficialVerificationRunStore.class),
            new ObjectMapper(),
            mock(JdbcOperations.class),
            mock(RuntimeEvidencePromptConsistencyGate.class),
            mock(PromptQualityMessageResolver.class)
    );

    @Test
    void metricFamiliesSeparatePromptTwelveAndLlmDecisionOfficialInspection() {
        when(runDetailService.findPackageDetail("pkg-001", "agg-001")).thenReturn(packageDetail());

        Map<String, Object> payload = controller.packageMetricFamilies("pkg-001", "agg-001");

        Map<?, ?> prompt = (Map<?, ?>) payload.get("prompt");
        Map<?, ?> decision = (Map<?, ?>) payload.get("decision");
        Map<?, ?> other = (Map<?, ?>) payload.get("other");
        assertThat(prompt.get("label")).isEqualTo("\uD504\uB86C\uD504\uD2B8 12\uC9C0\uD45C");
        assertThat(decision.get("label")).isEqualTo("LLM \uD310\uC815 \uACF5\uC2DD\uAC80\uC0AC");
        assertThat(other.get("label")).isEqualTo("\uAE30\uD0C0 \uACF5\uC2DD\uAC80\uC0AC");
        assertThat(prompt.get("totalRunCount")).isEqualTo(2);
        assertThat(decision.get("totalRunCount")).isEqualTo(2);
        assertThat(other.get("totalRunCount")).isEqualTo(1);
        assertThat(decision.get("failedRunCount")).isEqualTo(1);
        assertThat(prompt.get("expectedMetricCount")).isEqualTo(12);
        assertThat(prompt.get("executedMetricCount")).isEqualTo(2);
        assertThat(prompt.get("notAppliedMetricCount")).isEqualTo(10L);
        assertThat(decision.get("expectedMetricCount")).isEqualTo(28);
        assertThat(decision.get("executedMetricCount")).isEqualTo(2);
        assertThat(decision.get("notAppliedMetricCount")).isEqualTo(26L);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> expectedDecisionMetrics =
                (List<Map<String, Object>>) decision.get("expectedMetrics");
        assertThat(expectedDecisionMetrics).hasSize(28);
        assertThat(expectedDecisionMetrics).extracting(metric -> metric.get("metricCode"))
                .contains("G01", "M01", "M04", "M24")
                .doesNotContain("CDC", "ERA", "SUHR", "OCR", "DSS", "ARR");
        assertThat(expectedDecisionMetrics)
                .filteredOn(metric -> "G01".equals(metric.get("metricCode")))
                .singleElement()
                .satisfies(metric -> {
                    assertThat(metric.get("executed")).isEqualTo(true);
                    assertThat(metric.get("status")).isEqualTo("EXECUTED");
                });
        assertThat(expectedDecisionMetrics)
                .filteredOn(metric -> "M01".equals(metric.get("metricCode")))
                .singleElement()
                .satisfies(metric -> {
                    assertThat(metric.get("executed")).isEqualTo(false);
                    assertThat(metric.get("status")).isEqualTo("NOT_APPLIED_TO_THIS_EVIDENCE");
                });
    }

    @Test
    void metricFailureDetailsFiltersByRequestedMetricOnly() {
        when(runDetailService.findFailureDetails("pkg-001", "agg-001")).thenReturn(packageDetail().failureCauses());

        List<OfficialRunFailureCause> failures = controller.packageMetricFailureDetails("pkg-001", "m04", "agg-001");

        assertThat(failures).extracting(OfficialRunFailureCause::metricCode).containsExactly("M04");
    }

    @Test
    void reverifyMapsPackageAggregateOperatorAndFindingScope() {
        RuntimeEvidenceReverifyResult result = new RuntimeEvidenceReverifyResult("pkg-001", null, "queued");
        when(verificationService.reverify(any())).thenReturn(result);

        RuntimeEvidenceReverifyResult actual = controller.reverifyPackage(
                "pkg-001",
                "agg-001",
                Map.of("reason", "\uACF5\uC2DD\uAC80\uC0AC \uC7AC\uAC80\uC99D", "findingIds", List.of("finding-1"), "issueIds", List.of("issue-1")),
                new TestingAuthenticationToken("admin", "n/a")
        );

        assertThat(actual.packageId()).isEqualTo("pkg-001");
        verify(verificationService).reverify(argThat(request ->
                "pkg-001".equals(request.packageId())
                        && "admin".equals(request.operatorId())
                        && "\uACF5\uC2DD\uAC80\uC0AC \uC7AC\uAC80\uC99D".equals(request.reason())
                        && "agg-001".equals(request.sourceAggregateRunId())
                        && request.findingIds().contains("finding-1")
                        && request.issueIds().contains("issue-1")));
    }

    private OfficialRunPackageDetail packageDetail() {
        List<OfficialVerificationMetricTrace> runs = List.of(
                metric("EIR", "IMPLEMENTATION_ALIGNMENT", "SUCCESS"),
                metric("PRE", "RESOURCE_ELIGIBILITY", "SUCCESS"),
                metric("G01", "LLM_DECISION_GATE", "SUCCESS"),
                metric("M04", "LLM_DECISION", "ERROR"),
                metric("CUSTOM", "CUSTOM_GROUP", "ERROR")
        );
        List<OfficialRunFailureCause> failures = List.of(
                failure("EIR"),
                failure("G01"),
                failure("M04"),
                failure("CUSTOM")
        );
        return new OfficialRunPackageDetail(
                "pkg-001",
                "agg-001",
                true,
                runs.size(),
                3,
                2,
                null,
                null,
                runs,
                List.of(),
                failures,
                List.of()
        );
    }

    private OfficialVerificationMetricTrace metric(String code, String group, String state) {
        return new OfficialVerificationMetricTrace(
                code,
                code + " metric",
                group,
                "run-" + code,
                "req-" + code,
                "/contexa/test/" + code.toLowerCase(),
                state,
                state,
                "SUCCESS".equals(state) ? 100.0d : 50.0d,
                "SUCCESS".equals(state) ? 1 : 0,
                1,
                10L,
                "2026-07-03 10:00:00",
                "2026-07-03 10:00:01",
                List.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of(),
                Map.of(),
                List.of(),
                List.of()
        );
    }

    private OfficialRunFailureCause failure(String metricCode) {
        return new OfficialRunFailureCause(
                metricCode,
                metricCode + " metric",
                "run-" + metricCode,
                "check-" + metricCode,
                "expected",
                "actual",
                "source",
                "owner",
                "root cause",
                "fix",
                "reverify"
        );
    }
}