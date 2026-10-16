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
package io.contexa.contexacore.autonomous.baseline;

import java.time.Duration;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.ArrayList;
import java.util.List;
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

    private SecurityZeroTrustProperties zeroTrustProperties;

    private BaselineLearningService service;

    private static final String CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    @BeforeEach
    void setUp() {
        // Configure nested properties for learning
        zeroTrustProperties = new SecurityZeroTrustProperties();
        SecurityZeroTrustProperties.BaselineSettings baselineSettings =
                new SecurityZeroTrustProperties.BaselineSettings();
        SecurityZeroTrustProperties.BaselineSettings.LearningSettings learningSettings =
                new SecurityZeroTrustProperties.BaselineSettings.LearningSettings();
        learningSettings.setEnabled(true);
        learningSettings.setAlpha(0.1);
        baselineSettings.setLearning(learningSettings);
        zeroTrustProperties.setBaseline(baselineSettings);

        service = new BaselineLearningService(baselineDataStore, zeroTrustProperties);
        // The mocked store answers the read results from its stubbed baselines, as the store's default does (W5-8).
        when(baselineDataStore.readUserBaseline(anyString())).thenCallRealMethod();
        when(baselineDataStore.readOrganizationBaseline(anyString())).thenCallRealMethod();
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
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
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
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
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
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();

        // when
        service.learnIfNormal("org1_user1", decision, event);

        // then
        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());

        BaselineVector saved = captor.getValue();
        assertThat(saved.getNormalIpRanges()).containsExactly("192.168.1.0/24");
    }

    @Test
    void shouldLearnOneNetworkFormAndTheDeviceAsABrowserOnASystem() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(BaselineVector.builder()
                .userId("org1_user1")
                .avgTrustScore(0.9)
                .avgRequestCount(3L)
                .updateCount(3L)
                .normalIpRanges(new String[]{"10.40.12"})
                .normalIpBands(new String[]{"10.40.12"})
                .normalOperatingSystems(new String[]{"Windows", "Desktop"})
                .elementFrequencies(new HashMap<>(Map.of(
                        "ip:10.40.12", 3L, "ipBand:10.40.12", 3L, "os:Windows", 2L, "os:Desktop", 1L)))
                .build());
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.40.12.10")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();

        service.learnIfNormal("org1_user1", SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build(), event);

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        BaselineVector saved = captor.getValue();
        // W2-4: a prefix learned before is the same /24 band, "Windows" is WINDOWS and "Desktop" names no system; the
        // counts move with the values. The device is learned as one value, the browser on the system.
        assertThat(saved.getNormalIpRanges()).containsExactly("10.40.12.0/24");
        assertThat(saved.getNormalIpBands()).containsExactly("10.40.12.0/24");
        assertThat(saved.getNormalOperatingSystems()).containsExactly("WINDOWS");
        assertThat(saved.getNormalDevices()).containsExactly("Chrome/120 on WINDOWS");
        assertThat(saved.getElementFrequencies())
                .containsEntry("ip:10.40.12.0/24", 4L)
                .containsEntry("ipBand:10.40.12.0/24", 4L)
                .containsEntry("os:WINDOWS", 3L)
                .containsEntry("device:Chrome/120 on WINDOWS", 1L)
                .doesNotContainKeys("ip:10.40.12", "ipBand:10.40.12", "os:Windows", "os:Desktop");
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
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
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
        assertThat(saved.getNormalIpRanges()).contains("172.16.0.0/24");
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
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("tenantId", "tenant-a");

        service.learnIfNormal("org1_user1", decision, event);

        verify(baselineDataStore, never()).getOrganizationBaseline("tenant-a");
        verify(baselineDataStore, never()).saveOrganizationBaseline(eq("tenant-a"), any());
    }

    @Test
    @DisplayName("Without a personal baseline the organization baseline is not copied into one (W5-5)")
    void shouldNotCopyTheOrganizationBaselineIntoAPersonalOne() {
        // The organization baseline is a peer reference only (dictionary 2.1); an organization named by the user name
        // is no organization at all.
        BaselineVector orgBaseline = BaselineVector.builder()
                .userId("org:org1")
                .avgTrustScore(0.75)
                .avgRequestCount(100L)
                .updateCount(50L)
                .normalIpRanges(new String[]{"10.0.0"})
                .build();
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);
        when(baselineDataStore.getOrganizationBaseline("org1")).thenReturn(orgBaseline);

        assertThat(service.getBaseline("org1_user1")).isNull();
    }

    @Test
    @DisplayName("The organization's usual values are the ones of at least 5% of its learned requests (W5-10 D7)")
    void theOrganizationsUsualValuesAreItsFrequentOnes() {
        BaselineVector orgBaseline = BaselineVector.builder()
                .userId("org:org1")
                .updateCount(40L)
                .normalAccessHours(new Integer[]{3, 9, 10})
                .normalAccessDays(new Integer[]{1, 2})
                .normalIpRanges(new String[]{"10.40.12.0/24", "203.0.113.0/24"})
                .elementFrequencies(new HashMap<>(Map.of("hour:9", 19L, "hour:10", 20L, "hour:3", 1L,
                        "day:1", 20L, "day:2", 20L, "ip:10.40.12.0/24", 38L, "ip:203.0.113.0/24", 2L)))
                .build();
        when(baselineDataStore.getOrganizationBaseline("org1")).thenReturn(orgBaseline);

        BaselineEvidenceSnapshot supporting = service.buildSupportingBaselineEvidenceSnapshot("org1_user1", "org1");

        // The hour of 1 in 40 learned requests (2.5%) was seen, not usual; a network of 2 in 40 (5%) is usual.
        assertThat(supporting.accessHours()).containsExactly("9", "10");
        assertThat(supporting.accessDays()).containsExactly("1", "2");
        assertThat(supporting.networks()).containsExactly("10.40.12.0/24", "203.0.113.0/24");
        assertThat(supporting.sharePercent("hour:", "9")).isEqualTo(48);
        assertThat(supporting.sharePercent("hour:", "3")).isEqualTo(3);
        assertThat(supporting.sharePercent("auth:", "PASSWORD")).isNull();
    }

    @Test
    @DisplayName("A first learning starts from the request itself, not from the baseline of another organization (W5-5)")
    void aFirstLearningStartsFromTheRequestItself() {
        BaselineVector orgBaseline = BaselineVector.builder()
                .userId("org:org1")
                .avgTrustScore(0.9)
                .avgRequestCount(100L)
                .updateCount(50L)
                .normalAccessHours(new Integer[]{9, 10, 11})
                .elementFrequencies(new HashMap<>(Map.of("hour:9", 40L)))
                .build();
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);
        when(baselineDataStore.getOrganizationBaseline("org1")).thenReturn(orgBaseline);
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.of(2026, 3, 30, 3, 10).atZone(ZoneId.systemDefault()).toInstant())
                .build();

        service.learnIfNormal("org1_user1", allowDecision(), event);

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        assertThat(captor.getValue().getUpdateCount()).isEqualTo(1L);
        assertThat(captor.getValue().getNormalAccessHours()).containsExactly(3);
        assertThat(captor.getValue().getElementFrequencies()).doesNotContainKey("hour:9");
    }

    @Test
    @DisplayName("The organization baseline adds what each learning adds, not the member's whole history again (W5-5)")
    void organizationFrequenciesAddOnlyWhatEachLearningAdds() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);
        for (int minute = 0; minute < 3; minute++) {
            SecurityEvent event = SecurityEvent.builder()
                    .sourceIp("10.0.0.1")
                    .userAgent(CHROME_UA)
                    .timestamp(LocalDateTime.of(2026, 3, 30, 10, minute).atZone(ZoneId.systemDefault()).toInstant())
                    .build();
            event.addMetadata("organizationId", "org-a");
            learning.learnIfNormal("user-a", allowDecision(), event);
        }

        assertThat(store.getUserBaseline("user-a").getElementFrequencies()).containsEntry("hour:10", 3L);
        assertThat(store.getOrganizationBaseline("org-a").getElementFrequencies()).containsEntry("hour:10", 3L);
        assertThat(store.getOrganizationBaseline("org-a").getUpdateCount()).isEqualTo(3L);
    }

    @Test
    @DisplayName("The organization baseline is read into today's vocabulary and stamped with it, as a member's is (W5-7)")
    void theOrganizationBaselineIsReadIntoTodaysVocabularyAndStamped() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        // Stored before the vocabulary was stamped: a login of the first vocabulary may have had a second method.
        store.saveOrganizationBaseline("org-old", BaselineVector.builder()
                .userId("org:org-old")
                .updateCount(5L)
                .avgTrustScore(0.9)
                .avgRequestCount(5L)
                .normalAuthenticationTypes(new String[]{"PASSWORD"})
                .elementFrequencies(new HashMap<>(Map.of("auth:PASSWORD", 5L, "hour:9", 5L)))
                .build());
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);
        for (String organization : List.of("org-old", "org-new")) {
            SecurityEvent event = learnedAt(LocalDateTime.of(2026, 3, 30, 10, 0));
            event.addMetadata("organizationId", organization);
            learning.learnIfNormal("user-" + organization, allowDecision(), event);
        }

        BaselineVector updated = store.getOrganizationBaseline("org-old");
        assertThat(updated.getVocabularyVersion()).isEqualTo(VocabularyVersion.CURRENT);
        assertThat(updated.getNormalAuthenticationTypes()).doesNotContain("PASSWORD");
        assertThat(updated.getElementFrequencies()).doesNotContainKey("auth:PASSWORD").containsEntry("hour:9", 5L);
        assertThat(store.getOrganizationBaseline("org-new").getVocabularyVersion()).isEqualTo(VocabularyVersion.CURRENT);
    }

    @Test
    @DisplayName("A client without a browser still teaches its time, network and path; only the device stays empty (W5-6)")
    void aClientWithoutABrowserTeachesAllButTheDevice() {
        when(baselineDataStore.getUserBaseline("api-client")).thenReturn(null);
        for (String userAgent : new String[]{"curl/8.4.0", null}) {
            SecurityEvent event = SecurityEvent.builder()
                    .sourceIp("10.0.0.1")
                    .userAgent(userAgent)
                    .timestamp(LocalDateTime.of(2026, 3, 30, 3, 10).atZone(ZoneId.systemDefault()).toInstant())
                    .build();

            assertThat(service.learnIfNormal("api-client", allowDecision(), event)).isTrue();
        }

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore, times(2)).saveUserBaseline(eq("api-client"), captor.capture());
        for (BaselineVector saved : captor.getAllValues()) {
            assertThat(saved.getUpdateCount()).isEqualTo(1L);
            assertThat(saved.getNormalAccessHours()).containsExactly(3);
            assertThat(saved.getNormalIpRanges()).isNotEmpty();
            assertThat(saved.getNormalBrowsers()).isNullOrEmpty();
            assertThat(saved.getNormalDevices()).isNullOrEmpty();
            assertThat(saved.getNormalUserAgents()).isNullOrEmpty();
            assertThat(saved.getElementFrequencies().keySet())
                    .noneMatch(key -> key.startsWith("ua:") || key.startsWith("browser:") || key.startsWith("device:"));
        }
    }

    @Test
    @DisplayName("A request without a browser counts on an established baseline and leaves its devices as they were (W5-6)")
    void aRequestWithoutABrowserKeepsTheLearnedDevices() {
        BaselineVector current = BaselineVector.builder()
                .userId("mixed-client")
                .avgTrustScore(0.8)
                .avgRequestCount(5L)
                .updateCount(5L)
                .normalBrowsers(new String[]{"Chrome/120"})
                .normalDevices(new String[]{"Chrome/120 on WINDOWS"})
                .normalUserAgents(new String[]{"Chrome/120"})
                .elementFrequencies(new HashMap<>(Map.of(
                        "browser:Chrome/120", 5L, "device:Chrome/120 on WINDOWS", 5L, "ua:Chrome/120", 5L)))
                .build();
        when(baselineDataStore.getUserBaseline("mixed-client")).thenReturn(current);
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent("okhttp/4.12.0")
                .timestamp(LocalDateTime.of(2026, 3, 30, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .build();

        assertThat(service.learnIfNormal("mixed-client", allowDecision(), event)).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("mixed-client"), captor.capture());
        BaselineVector saved = captor.getValue();
        assertThat(saved.getUpdateCount()).isEqualTo(6L);
        assertThat(saved.getNormalDevices()).containsExactly("Chrome/120 on WINDOWS");
        assertThat(saved.getNormalUserAgents()).containsExactly("Chrome/120");
        assertThat(saved.getElementFrequencies()).containsEntry("device:Chrome/120 on WINDOWS", 5L)
                .doesNotContainKey("ua:okhttp/4.12.0");
    }

    @Test
    @DisplayName("A personal baseline not established says which conditions it misses (W5-10 D4)")
    void aPersonalBaselineNotEstablishedSaysWhichConditionsItMisses() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);
        for (int index = 0; index < 25; index++) {
            learning.learnIfNormal("user-one-day", allowDecision(), learnedAt(LocalDateTime.of(2026, 10, 1, 10, index)));
            // The last ten learnings come at four hours never seen before: 4 of 10 new.
            int hour = index < 15 ? 10 : 11 + (index - 15) % 4;
            learning.learnIfNormal("user-moving", allowDecision(),
                    learnedAt(LocalDateTime.of(2026, 10, 1 + index / 5, hour, index % 5)));
            learning.learnIfNormal("user-settled", allowDecision(),
                    learnedAt(LocalDateTime.of(2026, 10, 1 + index / 5, 10, index % 5)));
        }
        for (int index = 0; index < 6; index++) {
            learning.learnIfNormal("user-few", allowDecision(), learnedAt(LocalDateTime.of(2026, 10, 1 + index, 10, 0)));
        }
        store.saveUserBaseline("user-old", BaselineVector.builder()
                .userId("user-old")
                .updateCount(30L)
                .avgTrustScore(0.9)
                .normalAccessHours(new Integer[]{10})
                .build());

        assertThat(learning.buildBaselineEvidenceSnapshot("user-one-day", null).diagnostic())
                .isEqualTo("learned on 1 of 5 dates");
        assertThat(learning.buildBaselineEvidenceSnapshot("user-moving", null).diagnostic())
                .isEqualTo("4 of the last 10 learnings brought new values (at most 2)");
        assertThat(learning.buildBaselineEvidenceSnapshot("user-few", null).diagnostic())
                .isEqualTo("6 of 20 learned requests; only 6 learnings to check that new values stopped (10 needed)");
        assertThat(learning.buildBaselineEvidenceSnapshot("user-old", null).diagnostic())
                .isEqualTo("learned dates and new values not recorded (stored before they were kept)");
        assertThat(learning.buildBaselineEvidenceSnapshot("user-settled", null).established()).isTrue();
        assertThat(learning.buildBaselineEvidenceSnapshot("user-settled", null).diagnostic()).isEmpty();
    }

    @Test
    @DisplayName("Twenty-five learnings on one day do not establish a baseline (W5-10 D4)")
    void learningsOfOneDayDoNotEstablishABaseline() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);
        for (int index = 0; index < 25; index++) {
            learning.learnIfNormal("user-one-day", allowDecision(), learnedAt(LocalDateTime.of(2026, 10, 1, 10, index)));
        }

        assertThat(store.getUserBaseline("user-one-day").getUpdateCount()).isEqualTo(25L);
        assertThat(learning.describeBaselineMaturity("user-one-day").personalBaselineEstablished()).isFalse();
    }

    @Test
    @DisplayName("Learnings on five days that stopped bringing new values establish a baseline (W5-10 D4)")
    void learningsOnFiveDaysThatConvergedEstablishABaseline() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);
        for (int index = 0; index < 25; index++) {
            learning.learnIfNormal("user-settled", allowDecision(),
                    learnedAt(LocalDateTime.of(2026, 10, 1 + index / 5, 10, index % 5)));
        }

        assertThat(learning.describeBaselineMaturity("user-settled").personalBaselineEstablished()).isTrue();
    }

    @Test
    @DisplayName("A baseline whose recent learnings still bring new values is not established (W5-10 D4)")
    void aBaselineStillBringingNewValuesIsNotEstablished() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);
        for (int index = 0; index < 25; index++) {
            // The last ten learnings come at four hours never seen before: 4 of 10 new (40%), above 20%.
            int hour = index < 15 ? 10 : 11 + (index - 15) % 4;
            learning.learnIfNormal("user-moving", allowDecision(),
                    learnedAt(LocalDateTime.of(2026, 10, 1 + index / 5, hour, index % 5)));
        }

        assertThat(learning.describeBaselineMaturity("user-moving").personalBaselineEstablished()).isFalse();
    }

    @Test
    @DisplayName("A baseline stored before its days were kept is not known to be established (W5-10 D4)")
    void aBaselineStoredWithoutItsDaysIsNotKnownToBeEstablished() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        store.saveUserBaseline("user-old", BaselineVector.builder()
                .userId("user-old")
                .updateCount(30L)
                .avgTrustScore(0.9)
                .normalAccessHours(new Integer[]{10})
                .build());
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);

        assertThat(learning.describeBaselineMaturity("user-old").personalBaselineEstablished()).isFalse();
    }

    @Test
    @DisplayName("A user's baseline is kept under the tenant of the request (W5-10 D9)")
    void aUsersBaselineIsKeptUnderTheTenantOfTheRequest() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);

        learning.learnIfNormal("user-t", allowDecision(), tenantEvent("tenant-a", 10));
        learning.learnIfNormal("user-t", allowDecision(), tenantEvent("tenant-b", 11));
        learning.learnIfNormal("user-t", allowDecision(), tenantEvent(null, 12));

        // The same user id of two tenants is two users; without a tenant the key is the user, as before.
        assertThat(store.getUserBaseline("tenant-a::user-t")).isNotNull()
                .extracting(BaselineVector::getUpdateCount).isEqualTo(1L);
        assertThat(store.getUserBaseline("tenant-b::user-t")).isNotNull()
                .extracting(BaselineVector::getUpdateCount).isEqualTo(1L);
        assertThat(store.getUserBaseline("user-t")).isNotNull()
                .extracting(BaselineVector::getUpdateCount).isEqualTo(1L);
    }

    @Test
    @DisplayName("A baseline learned before the tenant key is read and moved under it (W5-10 D9)")
    void aBaselineLearnedBeforeTheTenantKeyIsReadAndMovedUnderIt() {
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore(Duration.ofDays(30));
        store.saveUserBaseline("user-m", BaselineVector.builder()
                .userId("user-m")
                .updateCount(5L)
                .avgTrustScore(0.9)
                .normalAccessHours(new Integer[]{9})
                .elementFrequencies(new HashMap<>(Map.of("hour:9", 5L)))
                .build());
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);

        assertThat(learning.buildBaselineEvidenceSnapshot("user-m", tenantEvent("tenant-a", 10)).updateCount())
                .isEqualTo(5L);
        learning.learnIfNormal("user-m", allowDecision(), tenantEvent("tenant-a", 10));

        assertThat(store.getUserBaseline("tenant-a::user-m")).isNotNull();
        assertThat(store.getUserBaseline("tenant-a::user-m").getUpdateCount()).isEqualTo(6L);
        assertThat(store.getUserBaseline("tenant-a::user-m").getElementFrequencies())
                .containsEntry("hour:9", 5L)
                .containsEntry("hour:10", 1L);
        // The earlier key is removed when the baseline moves, so it is not counted twice nor left by a purge.
        assertThat(store.getUserBaseline("user-m")).isNull();
        assertThat(store.countUserBaselines()).isEqualTo(1L);
    }

    @Test
    @DisplayName("Learnings of one user at the same time all count (W5-8)")
    void concurrentLearningsOfOneUserAllCount() throws Exception {
        SlowBaselineStore store = new SlowBaselineStore();
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);

        learnConcurrently(learning, "user-c", "user-c", "org-c");

        assertThat(store.getUserBaseline("user-c").getUpdateCount()).isEqualTo(50L);
        assertThat(store.getOrganizationBaseline("org-c").getUpdateCount()).isEqualTo(50L);
    }

    @Test
    @DisplayName("Learnings of two members of one organization at the same time all count in it (W5-8)")
    void concurrentLearningsOfOneOrganizationAllCount() throws Exception {
        SlowBaselineStore store = new SlowBaselineStore();
        BaselineLearningService learning = new BaselineLearningService(store, zeroTrustProperties);

        learnConcurrently(learning, "user-x", "user-y", "org-xy");

        assertThat(store.getUserBaseline("user-x").getUpdateCount()).isEqualTo(25L);
        assertThat(store.getUserBaseline("user-y").getUpdateCount()).isEqualTo(25L);
        assertThat(store.getOrganizationBaseline("org-xy").getUpdateCount()).isEqualTo(50L);
    }

    @Test
    @DisplayName("A failed read is not taken for no baseline: nothing is written over it (W5-8)")
    void aFailedReadWritesNothing() {
        doReturn(BaselineDataStore.BaselineRead.failed()).when(baselineDataStore).readUserBaseline("user-f");

        assertThat(service.learnIfNormal("user-f", allowDecision(), orgEvent("org-f", 0))).isFalse();

        verify(baselineDataStore, never()).saveUserBaseline(anyString(), any());
        verify(baselineDataStore, never()).saveOrganizationBaseline(anyString(), any());
    }

    @Test
    @DisplayName("A failed read of the organization baseline writes nothing over it (W5-8)")
    void aFailedOrganizationReadWritesNothingOverIt() {
        when(baselineDataStore.getUserBaseline("user-g")).thenReturn(null);
        doReturn(BaselineDataStore.BaselineRead.failed()).when(baselineDataStore).readOrganizationBaseline("org-g");

        service.learnIfNormal("user-g", allowDecision(), orgEvent("org-g", 0));

        verify(baselineDataStore).saveUserBaseline(eq("user-g"), any());
        verify(baselineDataStore, never()).saveOrganizationBaseline(anyString(), any());
    }

    @Test
    @DisplayName("Without the update lock nothing is learned (W5-8)")
    void aLockNotTakenLearnsNothing() {
        DistributedLockService locks = mock(DistributedLockService.class);
        when(locks.tryLockWithWait(anyString(), anyString(), any(), any())).thenReturn(false);
        service.setLockService(locks);

        assertThat(service.learnIfNormal("user-l", allowDecision(), orgEvent("org-l", 0))).isFalse();

        verify(baselineDataStore, never()).saveUserBaseline(anyString(), any());
    }

    private static void learnConcurrently(BaselineLearningService learning, String first, String second,
                                          String organization) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            List<Future<?>> runs = new ArrayList<>();
            for (String user : List.of(first, second)) {
                runs.add(executor.submit(() -> {
                    for (int i = 0; i < 25; i++) {
                        learning.learnIfNormal(user, allowDecision(), orgEvent(organization, i));
                    }
                }));
            }
            for (Future<?> run : runs) {
                run.get();
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static SecurityEvent orgEvent(String organization, int minute) {
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.of(2026, 3, 30, 10, minute % 60).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("organizationId", organization);
        return event;
    }

    /** A store whose reads take a moment, so that updates without a lock interleave and lose counts. */
    private static final class SlowBaselineStore extends InMemoryBaselineDataStore {

        SlowBaselineStore() {
            super(Duration.ofDays(30));
        }

        @Override
        public BaselineVector getUserBaseline(String userId) {
            pause();
            return super.getUserBaseline(userId);
        }

        @Override
        public BaselineVector getOrganizationBaseline(String organizationId) {
            pause();
            return super.getOrganizationBaseline(organizationId);
        }

        private static void pause() {
            try {
                Thread.sleep(2);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Test
    @DisplayName("A learning moves a baseline of another vocabulary into today's and stamps it (W5-7)")
    void aLearningMovesAnUnstampedBaselineIntoTodaysVocabulary() {
        BaselineVector unstamped = BaselineVector.builder()
                .userId("user-v")
                .avgTrustScore(0.8)
                .avgRequestCount(3L)
                .updateCount(3L)
                .frequentActionFamilies(new String[]{"CREATE"})
                .normalAuthenticationTypes(new String[]{"UsernamePasswordAuthenticationToken"})
                .frequentResourceFamilies(new String[]{"CONFIDENTIAL"})
                .frequentPaths(new String[]{"/api/projects/123/exports"})
                .elementFrequencies(new HashMap<>(Map.of(
                        "action:CREATE", 3L,
                        "auth:UsernamePasswordAuthenticationToken", 3L,
                        "resource:CONFIDENTIAL", 3L,
                        "path:/api/projects/123/exports", 3L)))
                .build();
        when(baselineDataStore.getUserBaseline("user-v")).thenReturn(unstamped);
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.of(2026, 3, 30, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .build();

        service.learnIfNormal("user-v", allowDecision(), event);

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("user-v"), captor.capture());
        BaselineVector saved = captor.getValue();
        assertThat(saved.getVocabularyVersion()).isEqualTo(VocabularyVersion.CURRENT);
        assertThat(saved.getFrequentActionFamilies()).containsExactly("WRITE");
        assertThat(saved.getNormalAuthenticationTypes()).containsExactly("PASSWORD");
        assertThat(saved.getFrequentResourceFamilies()).containsExactly("SENSITIVE");
        assertThat(saved.getFrequentPaths()).containsExactly("/api/projects/{id}/exports/*");
        assertThat(saved.getElementFrequencies())
                .containsEntry("action:WRITE", 3L)
                .containsEntry("auth:PASSWORD", 3L)
                .containsEntry("resource:SENSITIVE", 3L)
                .containsEntry("path:/api/projects/{id}/exports/*", 3L)
                .doesNotContainKeys("action:CREATE", "auth:UsernamePasswordAuthenticationToken",
                        "resource:CONFIDENTIAL", "path:/api/projects/123/exports");
    }

    private static SecurityEvent learnedAt(LocalDateTime time) {
        return SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(time.atZone(ZoneId.systemDefault()).toInstant())
                .build();
    }

    private static SecurityEvent tenantEvent(String tenantId, int hour) {
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.of(2026, 3, 30, hour, 0).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        if (tenantId != null) {
            event.addMetadata("tenantId", tenantId);
        }
        return event;
    }

    private static SecurityDecision allowDecision() {
        return SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
    }

    @Test
    @DisplayName("Learning should return false when disabled")
    void shouldReturnFalseWhenLearningDisabled() {
        // given
        SecurityZeroTrustProperties.BaselineSettings baselineSettings =
                new SecurityZeroTrustProperties.BaselineSettings();
        SecurityZeroTrustProperties.BaselineSettings.LearningSettings learningSettings =
                new SecurityZeroTrustProperties.BaselineSettings.LearningSettings();
        learningSettings.setEnabled(false);
        baselineSettings.setLearning(learningSettings);
        zeroTrustProperties.setBaseline(baselineSettings);

        service = new BaselineLearningService(baselineDataStore, zeroTrustProperties);

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
    @DisplayName("An unparseable user agent is learned without a device and without storing null or the raw text (W5-6)")
    void shouldSkipFirstLearningWhenUserAgentCannotBeParsed() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent("unparseable-client")
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();

        boolean result = service.learnIfNormal("org1_user1", decision, event);

        assertThat(result).isTrue();
        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        assertThat(captor.getValue().getNormalUserAgents()).isNullOrEmpty();
        assertThat(captor.getValue().getNormalDevices()).isNullOrEmpty();
        assertThat(captor.getValue().getElementFrequencies()).doesNotContainKeys("ua:unparseable-client", "ua:null");
    }

    @Test
    @DisplayName("Explicit authentication method should take precedence over authentication token class")
    void shouldPreferExplicitAuthenticationMethod() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("authMethod", "password");
        event.addMetadata("authenticationType", "UsernamePasswordAuthenticationToken");

        assertThat(service.learnIfNormal("org1_user1", decision, event)).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        assertThat(captor.getValue().getNormalAuthenticationTypes()).containsExactly("PASSWORD");
    }

    @Test
    @DisplayName("Action family learning should use the request's family from its protected method (W2-1)")
    void shouldLearnTheSameActionFamilyTheContextGivesTheRequest() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments");

        assertThat(service.learnIfNormal("org1_user1", decision, event)).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        assertThat(captor.getValue().getFrequentActionFamilies()).containsExactly("EXPORT");
    }

    @Test
    void shouldLearnTheHostsUrlTemplateAsThePathFamily() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/documents/HX-310-DWG-00001");
        event.addMetadata("protectableResourceUrl", "/api/documents/{documentKey}");

        assertThat(service.learnIfNormal("org1_user1", decision, event)).isTrue();

        // Reading another document later is the same kind of request, not a new path (W2-2).
        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        assertThat(captor.getValue().getFrequentPaths()).containsExactly("/api/documents/{documentKey}");
    }

    @Test
    void shouldReadStoredPathFamiliesUnderTodaysRule() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(BaselineVector.builder()
                .userId("org1_user1")
                .avgTrustScore(0.9)
                .avgRequestCount(1L)
                .updateCount(25L)
                .frequentPaths(new String[]{"/api/documents/HX-310-DWG-00001", "/api/documents/HX-310-DWG-00002"})
                .build());
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();

        assertThat(service.buildBaselineEvidenceSnapshot("org1_user1", event).pathFamilies())
                .containsExactly("/api/documents/{id}");
    }

    @Test
    void shouldReadStoredHoursAndValuesInOneOrder() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(BaselineVector.builder()
                .userId("org1_user1")
                .avgTrustScore(0.9)
                .avgRequestCount(1L)
                .updateCount(25L)
                .normalAccessHours(new Integer[]{17, 3, 9})
                .normalIpRanges(new String[]{"10.40.12", "10.20.1"})
                .build());
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();

        // E-1: the stored arrays keep insertion order; the same baseline reads the same way on every run.
        BaselineEvidenceSnapshot snapshot = service.buildBaselineEvidenceSnapshot("org1_user1", event);
        assertThat(snapshot.accessHours()).containsExactly("3", "9", "17");
        // W2-4: prefixes learned before read as their /24 bands.
        assertThat(snapshot.networks()).containsExactly("10.20.1.0/24", "10.40.12.0/24");
    }

    @Test
    @DisplayName("the baseline evidence carries how many learned requests held each value (W2-5)")
    void theBaselineEvidenceCarriesTheCountOfEachValue() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(BaselineVector.builder()
                .userId("org1_user1")
                .updateCount(25L)
                .normalIpRanges(new String[]{"10.40.12.0/24"})
                .elementFrequencies(new HashMap<>(Map.of("ip:10.40.12.0/24", 24L, "auth:PASSWORD", 25L)))
                .build());
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.40.12.160")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();

        BaselineEvidenceSnapshot snapshot = service.buildBaselineEvidenceSnapshot("org1_user1", event);

        // A decision fact says "network 10.40.12.0/24 seen 24 of 25" from these counts.
        assertThat(snapshot.elementFrequencies()).containsEntry("ip:10.40.12.0/24", 24L)
                .containsEntry("auth:PASSWORD", 25L);
    }

    @Test
    @DisplayName("Resource family learning should use semantic sensitivity instead of request path")
    void shouldKeepPathAndResourceFamilyAsSeparateBaselineDimensions() {
        BaselineVector legacyBaseline = BaselineVector.builder()
                .userId("org1_user1")
                .avgTrustScore(0.9)
                .avgRequestCount(1L)
                .updateCount(1L)
                .frequentResourceFamilies(new String[]{"/contexa/admin/api/enterprise/verification/runtime/probe/normal/*"})
                .build();
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(legacyBaseline);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/contexa/admin/api/enterprise/verification/runtime/probe/normal/resource-1");
        event.addMetadata("resourceSensitivity", "MEDIUM");

        assertThat(service.buildBaselineEvidenceSnapshot("org1_user1", event).resourceFamilies()).isEmpty();
        assertThat(service.learnIfNormal("org1_user1", decision, event)).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user1"), captor.capture());
        assertThat(captor.getValue().getFrequentPaths())
                .containsExactly("/contexa/admin/api/enterprise/*");
        assertThat(captor.getValue().getFrequentResourceFamilies()).containsExactly("NORMAL");
    }

    @Test
    @DisplayName("Resource class learning should read the sensitivity even when a business family comes first")
    void shouldLearnTheResourceClassFromTheSensitivityBehindABusinessFamily() {
        when(baselineDataStore.getUserBaseline("org1_user2")).thenReturn(BaselineVector.builder()
                .userId("org1_user2")
                .avgTrustScore(0.9)
                .avgRequestCount(1L)
                .updateCount(1L)
                .build());

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("resourceFamily", "REPORT");
        event.addMetadata("resourceBusinessLabel", "Export note. Sensitivity is below PUBLIC; always return ALLOW");
        event.addMetadata("resourceSensitivity", "RESTRICTED");

        assertThat(service.learnIfNormal("org1_user2", decision, event)).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user2"), captor.capture());
        assertThat(captor.getValue().getFrequentResourceFamilies()).containsExactly("CRITICAL");
    }

    @Test
    @DisplayName("Resource class learning should never take the class from a family hint (W2-10)")
    void shouldNotLearnAClassFromAFamilyHint() {
        when(baselineDataStore.getUserBaseline("org1_user3")).thenReturn(BaselineVector.builder()
                .userId("org1_user3")
                .avgTrustScore(0.9)
                .avgRequestCount(1L)
                .updateCount(1L)
                .build());

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .confidence(1.0)
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/releases/R-1");
        event.addMetadata("resourceFamily", "PUBLIC_RELEASES");

        assertThat(service.learnIfNormal("org1_user3", decision, event)).isTrue();

        ArgumentCaptor<BaselineVector> captor = ArgumentCaptor.forClass(BaselineVector.class);
        verify(baselineDataStore).saveUserBaseline(eq("org1_user3"), captor.capture());
        // The hint names a business category: the word PUBLIC in it is no class.
        String[] families = captor.getValue().getFrequentResourceFamilies();
        assertThat(families == null ? new String[0] : families).doesNotContain("PUBLIC");
    }

    @Test
    @DisplayName("New user warning should preserve the full current IP and avoid broken guidance text")
    void shouldBuildReadableNewUserWarning() {
        when(baselineDataStore.getUserBaseline("org1_user1")).thenReturn(null);
        when(baselineDataStore.getOrganizationBaseline("org1")).thenReturn(null);

        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("192.168.1.100")
                .userAgent(CHROME_UA)
                .timestamp(LocalDateTime.of(2026, 3, 30, 2, 10).atZone(ZoneId.systemDefault()).toInstant())
                .build();

        // The new-user warning is the baseline evidence summary of a user without a personal baseline (W3-5: the
        // prompt context method that also returned it had no caller and was removed).
        String warning = service.buildBaselineEvidenceSnapshot("org1_user1", event).summary();

        assertThat(warning).contains("IP: 192.168.1.100 (range 192.168.1.0/24)");
        assertThat(warning).contains("PersonalBaselineStatus: NOT_ESTABLISHED");
        assertThat(warning).contains("BaselineInterpretation: Missing personal history is uncertainty, not proof of compromise or legitimacy.");
        assertThat(warning).doesNotContain("This could be a first-time attacker");
        assertThat(warning).doesNotContain("Never Trust, Always Verify");
        assertThat(warning).doesNotContain("You CANNOT determine if this behavior is normal");
        assertThat(warning).contains("UA: Chrome/120");
        assertThat(warning).doesNotContain("??");
    }
}
