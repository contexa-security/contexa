package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionBand;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestProjector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PendingAnomalyEvidenceCheckServiceTest {

    private PendingAnomalyEvidenceCheckService service;

    @BeforeEach
    void setUp() {
        service = new PendingAnomalyEvidenceCheckService();
    }

    @Test
    @DisplayName("HCAD redline assessment should trigger a pre-protectable event")
    void evaluate_redlineAssessment_shouldTrigger() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/export/reports");
        request.setRequestedSessionId("session-1");
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("User-Agent", "JUnit");
        HcadPreProtectablePromotionRequestProjector.project(
                request,
                new HcadPreProtectablePromotionAssessment(
                        70,
                        HcadPreProtectablePromotionBand.REDLINE,
                        true,
                        List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE"),
                        List.of("SENSITIVE_SURFACE"),
                        List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE", "SENSITIVE_SURFACE"),
                        "promotion triggered",
                        "hcad-promotion-v1",
                        Map.of("promotionScore", 70, "promotionEligible", true)));

        PendingAnomalyEvidenceReport report = service.evaluate(
                request,
                new PendingAnomalyEligibility("alice", "ctx-1", "base-1"));

        assertThat(report.shouldTrigger()).isTrue();
        assertThat(report.anchorSignals()).contains("IMPOSSIBLE_TRAVEL", "NEW_DEVICE");
        assertThat(report.escalationScore()).isEqualTo(70);
        assertThat(report.escalationBand()).isEqualTo("REDLINE");
        assertThat(report.reasonSummary()).contains("promotion triggered");
    }

    @Test
    @DisplayName("non-eligible HCAD assessment should not trigger a pre-protectable event")
    void evaluate_nonEligibleAssessment_shouldNotTrigger() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/profile");
        request.setRequestedSessionId("session-2");
        request.setRemoteAddr("203.0.113.20");
        request.addHeader("User-Agent", "JUnit");
        HcadPreProtectablePromotionRequestProjector.project(
                request,
                new HcadPreProtectablePromotionAssessment(
                        25,
                        HcadPreProtectablePromotionBand.LOW,
                        false,
                        List.of(),
                        List.of("REQUEST_BURST"),
                        List.of("REQUEST_BURST"),
                        "not eligible",
                        "hcad-promotion-v1",
                        Map.of("promotionScore", 25, "promotionEligible", false)));

        PendingAnomalyEvidenceReport report = service.evaluate(
                request,
                new PendingAnomalyEligibility("bob", "ctx-2", "base-2"));

        assertThat(report.shouldTrigger()).isFalse();
        assertThat(report.escalationEligible()).isFalse();
        assertThat(report.reasonCodes()).containsExactly("REQUEST_BURST");
    }
}