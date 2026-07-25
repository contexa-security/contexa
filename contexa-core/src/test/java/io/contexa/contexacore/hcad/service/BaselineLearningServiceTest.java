/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.hcad.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import java.time.LocalDateTime;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.quality.Strictness;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BaselineLearningServiceTest {

    @Mock
    private BaselineDataStore baselineDataStore;

    @Mock
    private HcadProperties hcadProperties;

    private BaselineLearningService service;

    private static final String CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    @BeforeEach
    void setUp() {
        // Configure nested properties for learning
        HcadProperties.BaselineSettings baselineSettings = new HcadProperties.BaselineSettings();
        HcadProperties.BaselineSettings.LearningSettings learningSettings = new HcadProperties.BaselineSettings.LearningSettings();
        learningSettings.setEnabled(true);
        learningSettings.setAlpha(0.1);
        baselineSettings.setLearning(learningSettings);
        when(hcadProperties.getBaseline()).thenReturn(baselineSettings);

        service = new BaselineLearningService(baselineDataStore, hcadProperties);
    }

    @Test
    @DisplayName("Only final ALLOW decisions should trigger learning")
    void shouldOnlyLearnFromAllowDecisions() {
        // given
        SecurityDecision blockDecision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.BLOCK)
                .riskScore(0.9)
                .confidence(0.8)
                .build();

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now())
                .build();

        // when
        boolean result = service.learnIfNormal("org1_user1", blockDecision, event);

        // then
        assertThat(result).isFalse();
        verify(baselineDataStore, never()).saveUserBaseline(anyString(), any());
    }

    @Test
    @DisplayName("EMA calculation should apply alpha weighting correctly")
    void shouldCalculateEmaCorrectly() {
        // given
        double alpha = 0.1;
        double existingTrust = 0.8;
        double newRiskScore = 0.2;

        BaselineVector existing = BaselineVector.builder()
                .userId("org1_user1")
                .avgTrustScore(existingTrust)
                .avgRequestCount(5L)
                .updateCount(5L)
                .normalIpRanges(new String[]{"10.0.0"})
                .normalUserAgents(new String[]{"Chrome/120"})
                .normalOperatingSystems(new String[]{"Windows"})
                .build();

        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(existing);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.BLOCK)
                .autonomousAction(ZeroTrustAction.ALLOW)
                .riskScore(newRiskScore)
                .confidence(1.0)
                .build();

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now())
                .build();

        // when
        boolean result = service.learnIfNormal("org1_user1", decision, event);

        // then
        assertThat(result).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());

        BaselineVector saved = captor.getValue();
        // The baseline learner uses verified action semantics for trust, so ALLOW contributes 1.0.
        double expectedTrust = alpha * 1.0 + (1 - alpha) * existingTrust;
        assertThat(saved.getAvgTrustScore()).isCloseTo(expectedTrust, Assertions.within(0.001));
    }

    @Test
    @DisplayName("IPv4 IP range should be normalized to /24 subnet")
    void shouldNormalizeIpRangeToSlash24() {
        // given
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("192.168.1.100")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now())
                .build();

        // when
        service.learnIfNormal("org1_user1", decision, event);

        // then
        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());

        BaselineVector saved = captor.getValue();
        assertThat(saved.getNormalIpRanges()).containsExactly("192.168.1");
    }

    @Test
    @DisplayName("LFU eviction should remove least frequent IP when exceeding 5 limit")
    void shouldEvictLeastFrequentIpWhenExceedingLimit() {
        // given
        BaselineVector existing = BaselineVector.builder()
                .userId("org1_user1")
                .avgTrustScore(0.8)
                .avgRequestCount(10L)
                .updateCount(10L)
                .normalIpRanges(new String[]{"10.0.0", "10.0.1", "10.0.2", "10.0.3", "10.0.4"})
                .normalUserAgents(new String[]{"Chrome/120"})
                .normalOperatingSystems(new String[]{"Windows"})
                .build();

        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(existing);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("172.16.0.50")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now())
                .build();

        // when
        service.learnIfNormal("org1_user1", decision, event);

        // then
        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());

        BaselineVector saved = captor.getValue();
        // IP array size should not exceed 5
        assertThat(saved.getNormalIpRanges()).hasSize(5);
        // New IP range should be present
        assertThat(saved.getNormalIpRanges()).contains("172.16.0");
    }

    @Test
    @DisplayName("Organization baseline should not use tenantId as an organization fallback")
    void shouldNotUseTenantIdAsOrganizationBaselineScope() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now())
                .build();
        event.addMetadata("tenantId", "tenant-a");

        service.learnIfNormal("org1_user1", decision, event);

        verify(baselineDataStore, never()).getOrganizationBaseline("tenant-a");
        verify(baselineDataStore, never()).saveOrganizationBaseline(eq("tenant-a"), any());
    }

    @Test
    @DisplayName("Organization baseline should be used as fallback when user baseline is null")
    void shouldFallbackToOrganizationBaseline() {
        // given
        BaselineVector orgBaseline = BaselineVector.builder()
                .userId("org:org1")
                .avgTrustScore(0.75)
                .avgRequestCount(100L)
                .updateCount(50L)
                .normalIpRanges(new String[]{"10.0.0"})
                .build();

        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);
        when(baselineDataStore.getOrganizationBaseline("org1")).thenReturn(orgBaseline);

        // when
        BaselineVector result = service.getBaseline("org1_user1");

        // then
        assertThat(result).isNotNull();
        assertThat(result.getUserId()).isEqualTo("org1_user1");
        assertThat(result.getAvgTrustScore()).isEqualTo(0.75);
        assertThat(result.getUpdateCount()).isEqualTo(0L);
    }

    @Test
    @DisplayName("Learning should return false when disabled")
    void shouldReturnFalseWhenLearningDisabled() {
        // given
        HcadProperties.BaselineSettings baselineSettings = new HcadProperties.BaselineSettings();
        HcadProperties.BaselineSettings.LearningSettings learningSettings = new HcadProperties.BaselineSettings.LearningSettings();
        learningSettings.setEnabled(false);
        baselineSettings.setLearning(learningSettings);
        when(hcadProperties.getBaseline()).thenReturn(baselineSettings);

        service = new BaselineLearningService(baselineDataStore, hcadProperties);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .build();

        // when
        boolean result = service.learnIfNormal("org1_user1", decision, event);

        // then
        assertThat(result).isFalse();
        verify(baselineDataStore, never()).saveUserBaseline(anyString(), any());
    }

    @Test
    @DisplayName("New user warning should preserve the full current IP and avoid broken guidance text")
    void shouldBuildReadableNewUserWarning() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);
        when(baselineDataStore.getOrganizationBaseline("org1")).thenReturn(null);

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("192.168.1.100")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.of(2026, 3, 30, 2, 10))
                .build();

        String warning = service.buildBaselinePromptContext("org1_user1", event);

        assertThat(warning).contains("IP: 192.168.1.100 (range 192.168.1)");
        assertThat(warning).contains("PersonalBaselineStatus: NOT_ESTABLISHED");
        assertThat(warning).contains("BaselineInterpretation: Missing personal history is uncertainty, not proof of compromise or legitimacy.");
        assertThat(warning).doesNotContain("This could be a first-time attacker");
        assertThat(warning).doesNotContain("Never Trust, Always Verify");
        assertThat(warning).doesNotContain("You CANNOT determine if this behavior is normal");
        assertThat(warning).contains("UA: Chrome/120");
        assertThat(warning).doesNotContain("??");
    }
}
