package io.contexa.contexaiam.admin.promptquality.official.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeEvidenceService;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.common.DefaultPromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.authentication.TestingAuthenticationToken;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PromptQualityOfficialConsoleApiControllerTest {

    private final PromptQualityRuntimeVerificationService verificationService =
            mock(PromptQualityRuntimeVerificationService.class);
    private final PromptQualityRuntimeEvidenceService runtimeEvidenceService =
            mock(PromptQualityRuntimeEvidenceService.class);
    private final PromptQualityOfficialRunDetailService runDetailService =
            mock(PromptQualityOfficialRunDetailService.class);
    private final PromptQualityOfficialConsoleViewAssembler views =
            new PromptQualityOfficialConsoleViewAssembler(
                    mock(SealedEvidencePackageLookupService.class),
                    runDetailService,
                    mock(OfficialVerificationRunStore.class),
                    new ObjectMapper(),
                    mock(RuntimeEvidencePromptConsistencyGate.class),
                    koreanMessageResolver());
    private final PromptQualityOfficialRuntimeEvidenceApiController runtimeEvidenceController =
            new PromptQualityOfficialRuntimeEvidenceApiController(runtimeEvidenceService, views);
    private final PromptQualityOfficialMetricApiController metricController =
            new PromptQualityOfficialMetricApiController(runDetailService, views);
    private final PromptQualityOfficialVerificationRunApiController verificationRunController =
            new PromptQualityOfficialVerificationRunApiController(
                    verificationService, runDetailService, views);
    private static PromptQualityMessageResolver koreanMessageResolver() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("i18n.messages");
        source.setDefaultEncoding("UTF-8");
        return new DefaultPromptQualityMessageResolver(source) {
            @Override
            public Locale currentLocale() {
                return Locale.KOREAN;
            }
        };
    }

    @Test
    void runtimeEvidenceSearchUsesOssServiceAndTypedResponse() {
        RuntimeEvidencePackageSummary summary = mock(RuntimeEvidencePackageSummary.class);
        when(runtimeEvidenceService.search(any())).thenReturn(List.of(summary));

        List<RuntimeEvidencePackageSummary> result = runtimeEvidenceController.searchRuntimeEvidence(
                "pkg-001", "tenant-a", "user-a", "/orders/1", "orders.read", "GET",
                null, null, 2, 30);

        assertThat(result).containsExactly(summary);
        verify(runtimeEvidenceService).search(argThat(criteria ->
                criteria.packageId().equals("pkg-001")
                        && criteria.tenantId().equals("tenant-a")
                        && criteria.page() == 2
                        && criteria.size() == 30));
    }
    @Test
    void metricFamiliesSeparatePromptTwelveAndLlmDecisionOfficialInspection() {
        OfficialRunPackageDetail detail = packageDetail();
        when(runDetailService.findPackageDetail("pkg-001", "agg-001")).thenReturn(detail);
        when(runDetailService.findPackageSummary("pkg-001", "agg-001"))
                .thenReturn(OfficialRunPackageSummary.fromDetail(detail, koreanMessageResolver()));

        Map<String, Object> payload = metricController.packageMetricFamilies("pkg-001", "agg-001");

        Map<?, ?> prompt = (Map<?, ?>) payload.get("prompt");
        Map<?, ?> decision = (Map<?, ?>) payload.get("decision");
        Map<?, ?> other = (Map<?, ?>) payload.get("other");
        assertThat(prompt.get("label")).isEqualTo("프롬프트 12지표");
        assertThat(decision.get("label")).isEqualTo("LLM 판정 공식검사");
        assertThat(other.get("label")).isEqualTo("기타 공식검사");
        assertThat(prompt.get("totalRunCount")).isEqualTo(2);
        assertThat(decision.get("totalRunCount")).isEqualTo(3);
        assertThat(other.get("totalRunCount")).isEqualTo(1);
        assertThat(decision.get("failedRunCount")).isEqualTo(1);
        assertThat(decision.get("notEvaluatedRunCount")).isEqualTo(0);
        assertThat(decision.get("notApplicableRunCount")).isEqualTo(1);
        Map<?, ?> decisionReverify = (Map<?, ?>) metricController
                .packageReverifyOptions("pkg-001", "agg-001")
                .get("decision");
        assertThat(decisionReverify.get("totalRunCount")).isEqualTo(3);
        assertThat(decisionReverify.get("passedRunCount")).isEqualTo(1);
        assertThat(decisionReverify.get("failedRunCount")).isEqualTo(1);
        assertThat(prompt.get("expectedMetricCount")).isEqualTo(12);
        assertThat(prompt.get("executedMetricCount")).isEqualTo(2);
        assertThat(prompt.get("notAppliedMetricCount")).isEqualTo(10L);
        assertThat(decision.get("expectedMetricCount")).isEqualTo(5);
        assertThat(decision.get("executedMetricCount")).isEqualTo(3);
        assertThat(decision.get("notAppliedMetricCount")).isEqualTo(2L);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> expectedDecisionMetrics =
                (List<Map<String, Object>>) decision.get("expectedMetrics");
        assertThat(expectedDecisionMetrics).hasSize(5);
        assertThat(expectedDecisionMetrics).extracting(metric -> metric.get("metricCode"))
                .containsExactlyInAnyOrder("D01", "D02", "D03", "D04", "D05");
        assertThat(expectedDecisionMetrics)
                .filteredOn(metric -> "D01".equals(metric.get("metricCode")))
                .singleElement()
                .satisfies(metric -> {
                    assertThat(metric.get("executed")).isEqualTo(true);
                    assertThat(metric.get("status")).isEqualTo("EXECUTED");
                });
        assertThat(expectedDecisionMetrics)
                .filteredOn(metric -> "D04".equals(metric.get("metricCode")))
                .singleElement()
                .satisfies(metric -> {
                    assertThat(metric.get("executed")).isEqualTo(false);
                    assertThat(metric.get("status")).isEqualTo("NOT_APPLIED_TO_THIS_EVIDENCE");
                });
    }

    @Test
    void metricFailureDetailsFiltersByRequestedMetricOnly() {
        when(runDetailService.findFailureDetails("pkg-001", "agg-001")).thenReturn(packageDetail().failureCauses());

        List<OfficialRunFailureCause> failures = metricController.packageMetricFailureDetails("pkg-001", "d03", "agg-001");

        assertThat(failures).extracting(OfficialRunFailureCause::metricCode).containsExactly("D03");
    }

    @Test
    void reverifyMapsPackageAggregateOperatorAndFindingScope() {
        RuntimeEvidenceReverifyResult result = new RuntimeEvidenceReverifyResult("pkg-001", null, "queued");
        when(verificationService.reverify(any())).thenReturn(result);

        RuntimeEvidenceReverifyResult actual = verificationRunController.reverifyPackage(
                "pkg-001",
                "agg-001",
                Map.of("reason", "공식검사 재검증", "findingIds", List.of("finding-1"), "issueIds", List.of("issue-1")),
                new TestingAuthenticationToken("admin", "n/a")
        );

        assertThat(actual.packageId()).isEqualTo("pkg-001");
        verify(verificationService).reverify(argThat(request ->
                "pkg-001".equals(request.packageId())
                        && "admin".equals(request.operatorId())
                        && "공식검사 재검증".equals(request.reason())
                        && "agg-001".equals(request.sourceAggregateRunId())
                        && request.findingIds().contains("finding-1")
                        && request.issueIds().contains("issue-1")));
    }

    private OfficialRunPackageDetail packageDetail() {
        List<OfficialVerificationMetricTrace> runs = List.of(
                metric("EIR", "IMPLEMENTATION_ALIGNMENT", "SUCCESS"),
                metric("PRE", "RESOURCE_ELIGIBILITY", "SUCCESS"),
                metric("D01", "LLM_DECISION", "SUCCESS"),
                metric("D02", "LLM_DECISION", "NOT_APPLICABLE"),
                metric("D03", "LLM_DECISION", "ERROR"),
                metric("CUSTOM", "CUSTOM_GROUP", "ERROR")
        );
        List<OfficialRunFailureCause> failures = List.of(
                failure("EIR"),
                failure("D01"),
                failure("D03"),
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
