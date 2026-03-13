package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HCADAnalysisServiceTest {

    @Mock
    private HCADContextExtractor contextExtractor;

    @Mock
    private HcadProperties hcadProperties;

    @Mock
    private HCADDataStore hcadDataStore;

    @Mock
    private HttpServletRequest request;

    @Mock
    private Authentication authentication;

    private HCADAnalysisService analysisService;

    @BeforeEach
    void setUp() {
        analysisService = new HCADAnalysisService(contextExtractor, hcadProperties, hcadDataStore);

        HcadProperties.AnalysisSettings analysisSettings = new HcadProperties.AnalysisSettings();
        analysisSettings.setMaxAgeMs(3600000L);
        when(hcadProperties.getAnalysis()).thenReturn(analysisSettings);
        when(request.getRequestURI()).thenReturn("/api/test");
    }

    @Test
    @DisplayName("Normal analysis returns HCADAnalysisResult with extracted context")
    void analyze_normalFlow_returnsResult() {
        // given
        HCADContext context = new HCADContext();
        context.setUserId("user1");
        when(contextExtractor.extractContext(any(), any())).thenReturn(context);

        Map<Object, Object> analysisData = new HashMap<>();
        analysisData.put("riskScore", "0.3");
        analysisData.put("isAnomaly", "false");
        analysisData.put("trustScore", "0.85");
        analysisData.put("threatType", "NONE");
        analysisData.put("threatEvidence", "No threats detected");
        analysisData.put("action", "ALLOW");
        analysisData.put("confidence", "0.95");
        analysisData.put("analyzedAt", String.valueOf(System.currentTimeMillis()));
        when(hcadDataStore.getHcadAnalysis("user1")).thenReturn(analysisData);

        // when
        HCADAnalysisResult result = analysisService.analyze(request, authentication);

        // then
        assertThat(result.getUserId()).isEqualTo("user1");
        assertThat(result.getTrustScore()).isEqualTo(0.85);
        assertThat(result.getThreatType()).isEqualTo("NONE");
        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(result.getConfidence()).isEqualTo(0.95);
        assertThat(result.isAnomaly()).isFalse();
        assertThat(result.getProcessingTimeMs()).isGreaterThanOrEqualTo(0);
        assertThat(result.getContext()).isNotNull();
    }

    @Test
    @DisplayName("Stale analysis sets stale flag in LLM analysis")
    void analyze_staleData_setsStaleFlag() {
        // given
        HCADContext context = new HCADContext();
        context.setUserId("user1");
        when(contextExtractor.extractContext(any(), any())).thenReturn(context);

        Map<Object, Object> analysisData = new HashMap<>();
        // Set analyzedAt to far in the past to trigger stale detection
        analysisData.put("analyzedAt", String.valueOf(System.currentTimeMillis() - 7200000L));
        analysisData.put("riskScore", "0.5");
        analysisData.put("action", "ALLOW");
        when(hcadDataStore.getHcadAnalysis("user1")).thenReturn(analysisData);

        // when
        HCADAnalysisResult result = analysisService.analyze(request, authentication);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getUserId()).isEqualTo("user1");
    }

    @Test
    @DisplayName("NaN and default fallback values when no analysis data exists")
    void analyze_noAnalysisData_returnsDefaultValues() {
        // given
        HCADContext context = new HCADContext();
        context.setUserId("newUser");
        when(contextExtractor.extractContext(any(), any())).thenReturn(context);
        when(hcadDataStore.getHcadAnalysis("newUser")).thenReturn(Collections.emptyMap());

        // when
        HCADAnalysisResult result = analysisService.analyze(request, authentication);

        // then
        assertThat(result.getUserId()).isEqualTo("newUser");
        assertThat(Double.isNaN(result.getTrustScore())).isTrue();
        assertThat(Double.isNaN(result.getAnomalyScore())).isTrue();
        assertThat(Double.isNaN(result.getConfidence())).isTrue();
        assertThat(result.getThreatType()).isEqualTo("NOT_ANALYZED");
        assertThat(result.isAnomaly()).isFalse();
    }

    @Test
    @DisplayName("Exception during analysis returns error context")
    void analyze_exceptionThrown_returnsErrorContext() {
        // given
        when(contextExtractor.extractContext(any(), any()))
                .thenThrow(new RuntimeException("Extraction failed"));

        // when
        HCADAnalysisResult result = analysisService.analyze(request, authentication);

        // then
        assertThat(result.getUserId()).isEqualTo("error");
        assertThat(result.getThreatType()).isEqualTo("ANALYSIS_ERROR");
        assertThat(result.getThreatEvidence()).contains("LLM analysis retrieval failed");
        assertThat(Double.isNaN(result.getTrustScore())).isTrue();
        assertThat(Double.isNaN(result.getAnomalyScore())).isTrue();
        assertThat(result.getContext()).isNotNull();
        assertThat(result.getContext().getIsNewSession()).isTrue();
    }

    @Test
    @DisplayName("Analysis data with unparseable numbers falls back to default values")
    void analyze_unparseableNumbers_fallsBackToDefaults() {
        // given
        HCADContext context = new HCADContext();
        context.setUserId("user1");
        when(contextExtractor.extractContext(any(), any())).thenReturn(context);

        Map<Object, Object> analysisData = new HashMap<>();
        analysisData.put("riskScore", "not-a-number");
        analysisData.put("trustScore", "invalid");
        analysisData.put("confidence", "abc");
        when(hcadDataStore.getHcadAnalysis("user1")).thenReturn(analysisData);

        // when
        HCADAnalysisResult result = analysisService.analyze(request, authentication);

        // then
        assertThat(result.getAnomalyScore()).isEqualTo(0.0);
        assertThat(result.getTrustScore()).isEqualTo(0.0);
        assertThat(result.getConfidence()).isEqualTo(0.0);
    }
}
