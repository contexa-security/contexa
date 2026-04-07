package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PendingAnomalyEligibilityGateTest {

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private AnalysisTriggerStateRepository analysisTriggerStateRepository;

    private PendingAnomalyEligibilityGate eligibilityGate;

    @BeforeEach
    void setUp() {
        eligibilityGate = new PendingAnomalyEligibilityGate(
                actionRepository,
                analysisTriggerStateRepository,
                new HcadProperties());
    }

    @Test
    @DisplayName("pending-analysis users should be eligible when no negative cache is present")
    void evaluate_pendingAnalysis_shouldReturnEligibility() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/reports");
        request.setRequestedSessionId("session-1");
        request.setRemoteAddr("203.0.113.30");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("contexa.userId", "alice");

        when(actionRepository.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(analysisTriggerStateRepository.isNegativeCached(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isCoolingDown(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isInFlight(anyString())).thenReturn(false);

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(
                request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        assertThat(eligibility).isNotNull();
        assertThat(eligibility.userId()).isEqualTo("alice");
    }

    @Test
    @DisplayName("non-pending users should be ignored by the eligibility gate")
    void evaluate_nonPending_shouldReturnNull() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/reports");
        request.setRequestedSessionId("session-2");
        request.setRemoteAddr("203.0.113.31");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("contexa.userId", "bob");

        when(actionRepository.getCurrentAction(eq("bob"), any())).thenReturn(ZeroTrustAction.ALLOW);

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(
                request,
                new UsernamePasswordAuthenticationToken("bob", "n/a", List.of()));

        assertThat(eligibility).isNull();
    }
    @Test
    @DisplayName("cooling-down pending users should be ignored before anomaly evaluation")
    void evaluate_coolingDown_shouldReturnNull() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/reports");
        request.setRequestedSessionId("session-3");
        request.setRemoteAddr("203.0.113.32");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("contexa.userId", "carol");
        when(actionRepository.getCurrentAction(eq("carol"), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(analysisTriggerStateRepository.isNegativeCached(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isCoolingDown(anyString())).thenReturn(true);
        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(
                request,
                new UsernamePasswordAuthenticationToken("carol", "n/a", List.of()));
        assertThat(eligibility).isNull();
    }
    @Test
    @DisplayName("state changes should produce a different trigger key for the same path")
    void evaluate_stateChange_shouldProduceDifferentTriggerKey() {
        MockHttpServletRequest first = new MockHttpServletRequest("GET", "/admin/export/reports");
        first.setRequestedSessionId("session-4");
        first.setRemoteAddr("203.0.113.33");
        first.addHeader("User-Agent", "JUnit");
        first.setAttribute("contexa.userId", "dave");
        first.setAttribute("hcad.recent_request_count", 1);
        MockHttpServletRequest second = new MockHttpServletRequest("GET", "/admin/export/reports");
        second.setRequestedSessionId("session-4");
        second.setRemoteAddr("203.0.113.33");
        second.addHeader("User-Agent", "JUnit");
        second.setAttribute("contexa.userId", "dave");
        second.setAttribute("hcad.recent_request_count", 20);
        second.setAttribute("hcad.is_new_device", true);
        when(actionRepository.getCurrentAction(eq("dave"), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(analysisTriggerStateRepository.isNegativeCached(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isCoolingDown(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isInFlight(anyString())).thenReturn(false);
        PendingAnomalyEligibility firstEligibility = eligibilityGate.evaluate(
                first,
                new UsernamePasswordAuthenticationToken("dave", "n/a", List.of()));
        PendingAnomalyEligibility secondEligibility = eligibilityGate.evaluate(
                second,
                new UsernamePasswordAuthenticationToken("dave", "n/a", List.of()));
        assertThat(firstEligibility).isNotNull();
        assertThat(secondEligibility).isNotNull();
        assertThat(firstEligibility.baseKey()).isNotEqualTo(secondEligibility.baseKey());
    }
}

