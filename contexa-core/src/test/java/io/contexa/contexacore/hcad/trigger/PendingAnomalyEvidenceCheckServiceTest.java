package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class PendingAnomalyEvidenceCheckServiceTest {

    private PendingAnomalyEvidenceCheckService service;

    @BeforeEach
    void setUp() {
        service = new PendingAnomalyEvidenceCheckService(new HcadProperties());
    }

    @Test
    @DisplayName("strong anchor combination should trigger a pre-protectable event")
    void evaluate_strongAnchorCombination_shouldTrigger() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/export/reports");
        request.setRequestedSessionId("session-1");
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("hcad.is_new_device", true);
        request.setAttribute("hcad.impossibleTravel", true);
        request.setAttribute("hcad.resource_sensitivity", "CRITICAL");

        PendingAnomalyEvidenceReport report = service.evaluate(
                request,
                new PendingAnomalyEligibility("alice", "ctx-1", "base-1"));

        assertThat(report.shouldTrigger()).isTrue();
        assertThat(report.anchorSignals()).contains("IMPOSSIBLE_TRAVEL", "NEW_DEVICE");
        assertThat(report.reasonCodes()).contains("SENSITIVE_SURFACE");
        assertThat(report.reasonSummary()).contains("PENDING_ANALYSIS");
    }

    @Test
    @DisplayName("single weak signal should not trigger a pre-protectable event")
    void evaluate_singleWeakSignal_shouldNotTrigger() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/profile");
        request.setRequestedSessionId("session-2");
        request.setRemoteAddr("203.0.113.20");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("hcad.recent_request_count", 2);

        PendingAnomalyEvidenceReport report = service.evaluate(
                request,
                new PendingAnomalyEligibility("bob", "ctx-2", "base-2"));

        assertThat(report.shouldTrigger()).isFalse();
        assertThat(report.anchorSignals()).isEmpty();
        assertThat(report.reasonCodes()).isEmpty();
    }
}
