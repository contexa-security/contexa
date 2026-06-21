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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class BaselineLearningService {

    private final BaselineDataStore baselineDataStore;
    private final HcadProperties hcadProperties;

    private static final String FREQ_PREFIX_IP = "ip:";
    private static final String FREQ_PREFIX_UA = "ua:";
    private static final String FREQ_PREFIX_OS = "os:";
    private static final String FREQ_PREFIX_PATH = "path:";
    private static final String FREQ_PREFIX_HOUR = "hour:";
    private static final String FREQ_PREFIX_DAY = "day:";
    private static final String FREQ_PREFIX_BROWSER = "browser:";
    private static final String FREQ_PREFIX_IP_BAND = "ipBand:";
    private static final String FREQ_PREFIX_AUTH = "auth:";
    private static final String FREQ_PREFIX_ACTION = "action:";
    private static final String FREQ_PREFIX_RESOURCE = "resource:";
    private static final List<String> COHORT_SUPPORT_DIMENSIONS = List.of(
            "ACCESS_HOURS",
            "ACCESS_DAYS",
            "OPERATING_SYSTEMS");

    public boolean learnIfNormal(String userId, SecurityDecision decision, SecurityEvent event) {
        if (!hcadProperties.getBaseline().getLearning().isEnabled()) {
            return false;
        }

        if (userId == null || decision == null) return false;
        if (!shouldLearnFromSecurityEvent(decision)) return false;

        try {
            BaselineVector currentBaseline = getBaseline(userId);
            BaselineVector newBaseline = updateWithEMAFromSecurityEvent(currentBaseline, userId, decision, event);
            baselineDataStore.saveUserBaseline(userId, newBaseline);
            updateOrganizationBaseline(userId, event, newBaseline);
            return true;

        } catch (Exception e) {
            log.error("[BaselineLearningService] SecurityEvent learning failed: userId={}", userId, e);
            return false;
        }
    }

    private boolean shouldLearnFromSecurityEvent(SecurityDecision decision) {
        return decision.getAction() == ZeroTrustAction.ALLOW;
    }

    private BaselineVector updateWithEMAFromSecurityEvent(BaselineVector current, String userId,
                                                          SecurityDecision decision, SecurityEvent event) {

        double currentTrustScore = resolveVerifiedTrustSignal(decision);

        String currentIp = event != null ? event.getSourceIp() : null;
        Integer currentHour = extractHourFromSecurityEvent(event);
        Integer currentDay = extractDayFromSecurityEvent(event);
        String currentPath = extractPathFamily(event);
        String currentUserAgent = event != null ? event.getUserAgent() : null;
        String currentBrowser = extractBrowser(event);
        String currentIpBand = SecuritySemanticNormalizer.normalizeNetwork(currentIp, extractMetadataText(event, "ipBand"));
        String currentAuthenticationType = SecuritySemanticNormalizer.normalizeAuthenticationType(
                extractMetadataText(event, "authenticationType", "authMethod"));
        String currentActionFamily = extractActionFamily(event);
        String currentResourceFamily = extractResourceFamily(event);

        if (currentUserAgent == null || currentUserAgent.isEmpty()) {
            log.error("[Baseline] UA missing - learning blocked: userId={}", userId);
            return current;
        }
        String uaSignatureForValidation = extractUASignature(currentUserAgent);
        if (!StringUtils.hasText(uaSignatureForValidation)) {
            log.error("[Baseline] UA parsing failed - learning blocked: userId={}, ua={}",
                    userId, currentUserAgent.length() > 50 ? currentUserAgent.substring(0, 50) + "..." : currentUserAgent);
            return current;
        }

        if (current == null) {

            Map<String, Long> frequencies = new HashMap<>();
            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(currentTrustScore)
                    .avgRequestCount(1L)
                    .updateCount(1L)
                    .lastUpdated(Instant.now());

            if (currentIpBand != null) {
                builder.normalIpRanges(new String[]{currentIpBand});
                if (currentIpBand != null) {
                    frequencies.put(FREQ_PREFIX_IP + currentIpBand, 1L);
                }
            }
            if (currentHour != null) {
                builder.normalAccessHours(new Integer[]{currentHour});
                frequencies.put(FREQ_PREFIX_HOUR + currentHour, 1L);
            }
            if (currentDay != null) {
                builder.normalAccessDays(new Integer[]{currentDay});
                frequencies.put(FREQ_PREFIX_DAY + currentDay, 1L);
            }
            if (currentPath != null) {
                builder.frequentPaths(new String[]{currentPath});
                frequencies.put(FREQ_PREFIX_PATH + currentPath, 1L);
            }
            if (currentBrowser != null) {
                builder.normalBrowsers(new String[]{currentBrowser});
                frequencies.put(FREQ_PREFIX_BROWSER + currentBrowser, 1L);
            }
            if (currentIpBand != null) {
                builder.normalIpBands(new String[]{currentIpBand});
                frequencies.put(FREQ_PREFIX_IP_BAND + currentIpBand, 1L);
            }
            if (currentAuthenticationType != null) {
                builder.normalAuthenticationTypes(new String[]{currentAuthenticationType});
                frequencies.put(FREQ_PREFIX_AUTH + currentAuthenticationType, 1L);
            }
            if (currentActionFamily != null) {
                builder.frequentActionFamilies(new String[]{currentActionFamily});
                frequencies.put(FREQ_PREFIX_ACTION + currentActionFamily, 1L);
            }
            if (currentResourceFamily != null) {
                builder.frequentResourceFamilies(new String[]{currentResourceFamily});
                frequencies.put(FREQ_PREFIX_RESOURCE + currentResourceFamily, 1L);
            }

            String uaSignature = extractUASignature(currentUserAgent);
            if (StringUtils.hasText(uaSignature)) {
                builder.normalUserAgents(new String[]{uaSignature});
                frequencies.put(FREQ_PREFIX_UA + uaSignature, 1L);
            } else {

                String truncatedUA = currentUserAgent.length() > 100
                        ? currentUserAgent.substring(0, 100) : currentUserAgent;
                builder.normalUserAgents(new String[]{truncatedUA});
                frequencies.put(FREQ_PREFIX_UA + truncatedUA, 1L);
                log.error("[Baseline] SecurityEvent first learning - UA parsing failed, storing raw: {}", truncatedUA);
            }

            String os = extractOS(currentUserAgent);
            if (StringUtils.hasText(os)) {
                builder.normalOperatingSystems(new String[]{os});
                frequencies.put(FREQ_PREFIX_OS + os, 1L);
            }

            builder.elementFrequencies(frequencies);
            return builder.build();
        }

        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double alpha = hcadProperties.getBaseline().getLearning().getAlpha();
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        Map<String, Long> frequencies = current.getElementFrequencies() != null
                ? new HashMap<>(current.getElementFrequencies())
                : new HashMap<>();

        String[] normalIpRanges = updateNormalIpRanges(current.getNormalIpRanges(), currentIpBand, frequencies);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour, frequencies);
        Integer[] normalAccessDays = updateNormalAccessDays(current.getNormalAccessDays(), currentDay, frequencies);
        String[] frequentPaths = updateFrequentPaths(current.getFrequentPaths(), currentPath, frequencies);
        String[] normalBrowsers = updateNormalBrowsers(current.getNormalBrowsers(), currentBrowser, frequencies);
        String[] normalIpBands = updateNormalIpBands(current.getNormalIpBands(), currentIpBand, frequencies);
        String[] normalAuthenticationTypes = updateNormalAuthenticationTypes(current.getNormalAuthenticationTypes(), currentAuthenticationType, frequencies);
        String[] frequentActionFamilies = updateFrequentActionFamilies(current.getFrequentActionFamilies(), currentActionFamily, frequencies);
        String[] frequentResourceFamilies = updateFrequentResourceFamilies(current.getFrequentResourceFamilies(), currentResourceFamily, frequencies);

        String normalizedUA = extractUASignature(currentUserAgent);
        String uaForUpdate = StringUtils.hasText(normalizedUA)
                ? normalizedUA : currentUserAgent;
        String[] normalUserAgents = updateNormalUserAgents(current.getNormalUserAgents(), uaForUpdate, frequencies);

        String currentOS = extractOS(currentUserAgent);
        String[] normalOperatingSystems = updateNormalOperatingSystems(
                current.getNormalOperatingSystems(), currentOS, frequencies);

        return BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(newTrustScore)
                .avgRequestCount(oldRequestCount + 1)
                .updateCount(oldUpdateCount + 1)
                .lastUpdated(Instant.now())

                .normalIpRanges(normalIpRanges)
                .normalAccessHours(normalAccessHours)
                .normalAccessDays(normalAccessDays)
                .frequentPaths(frequentPaths)
                .normalUserAgents(normalUserAgents)
                .normalOperatingSystems(normalOperatingSystems)
                .normalBrowsers(normalBrowsers)
                .normalIpBands(normalIpBands)
                .normalAuthenticationTypes(normalAuthenticationTypes)
                .frequentActionFamilies(frequentActionFamilies)
                .frequentResourceFamilies(frequentResourceFamilies)
                .elementFrequencies(frequencies)
                .build();
    }

    private Integer extractHourFromSecurityEvent(SecurityEvent event) {
        if (event == null || event.getTimestamp() == null) {
            return null;
        }
        return event.getTimestamp().getHour();
    }

    private double resolveVerifiedTrustSignal(SecurityDecision decision) {
        if (decision == null || decision.getAction() == null) {
            return 0.5d;
        }
        return switch (decision.getAction()) {
            case ALLOW -> 1.0d;
            case CHALLENGE -> 0.5d;
            case ESCALATE, PENDING_ANALYSIS -> 0.25d;
            case BLOCK -> 0.0d;
        };
    }

    private Integer extractDayFromSecurityEvent(SecurityEvent event) {
        if (event == null || event.getTimestamp() == null) {
            return null;
        }
        return event.getTimestamp().getDayOfWeek().getValue();
    }

    private String extractIpRange(String ip) {
        if (!StringUtils.hasText(ip)) {
            return null;
        }
        String trimmed = ip.trim();
        long dots = trimmed.chars().filter(ch -> ch == '.').count();
        if (dots >= 3) {
            return SecuritySemanticNormalizer.normalizeNetwork(trimmed, null);
        }
        return SecuritySemanticNormalizer.normalizeNetwork(null, trimmed);
    }

    private String[] updateNormalIpRanges(String[] current, String newIpBand, Map<String, Long> frequencies) {
        if (newIpBand == null) {
            return current;
        }
        String ipRange = extractIpRange(newIpBand);
        if (ipRange == null) {
            return current;
        }

        frequencies.merge(FREQ_PREFIX_IP + ipRange, 1L, Long::sum);

        if (current == null || current.length == 0) {
            return new String[]{ipRange};
        }

        for (String existing : current) {
            if (ipRange.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 5) {
            int lfuIndex = findLeastFrequentIndex(current, FREQ_PREFIX_IP, frequencies);
            frequencies.remove(FREQ_PREFIX_IP + current[lfuIndex]);
            String[] updated = Arrays.copyOf(current, current.length);
            updated[lfuIndex] = ipRange;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = ipRange;
        return updated;
    }

    private Integer[] updateNormalAccessHours(Integer[] current, Integer newHour, Map<String, Long> frequencies) {
        if (newHour == null || newHour < 0 || newHour > 23) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_HOUR + newHour, 1L, Long::sum);
        return mergeAccessDimension(current, newHour, 24);
    }

    private Integer[] updateNormalAccessDays(Integer[] current, Integer newDay, Map<String, Long> frequencies) {
        if (newDay == null || newDay < 1 || newDay > 7) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_DAY + newDay, 1L, Long::sum);
        return mergeAccessDimension(current, newDay, 7);
    }

    private Integer[] mergeAccessDimension(Integer[] current, Integer newValue, int maxSize) {
        if (newValue == null) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new Integer[]{newValue};
        }

        for (Integer existing : current) {
            if (newValue.equals(existing)) {
                return current;
            }
        }

        if (current.length >= maxSize) {
            return current;
        }

        Integer[] updated = new Integer[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newValue;
        return updated;
    }

    private String[] updateFrequentPaths(String[] current, String newPath, Map<String, Long> frequencies) {
        if (newPath == null || newPath.isEmpty()) {
            return current;
        }

        frequencies.merge(FREQ_PREFIX_PATH + newPath, 1L, Long::sum);

        if (current == null || current.length == 0) {
            return new String[]{newPath};
        }

        for (String existing : current) {
            if (newPath.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 10) {
            int lfuIndex = findLeastFrequentIndex(current, FREQ_PREFIX_PATH, frequencies);
            frequencies.remove(FREQ_PREFIX_PATH + current[lfuIndex]);
            String[] updated = Arrays.copyOf(current, current.length);
            updated[lfuIndex] = newPath;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newPath;
        return updated;
    }

    private String[] updateNormalUserAgents(String[] current, String newUserAgent, Map<String, Long> frequencies) {
        if (newUserAgent == null || newUserAgent.isEmpty()) {
            return current;
        }

        if (newUserAgent.length() > 100) {
            newUserAgent = newUserAgent.substring(0, 100);
        }

        frequencies.merge(FREQ_PREFIX_UA + newUserAgent, 1L, Long::sum);

        if (current == null || current.length == 0) {
            return new String[]{newUserAgent};
        }

        for (String existing : current) {
            if (newUserAgent.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 5) {
            int lfuIndex = findLeastFrequentIndex(current, FREQ_PREFIX_UA, frequencies);
            frequencies.remove(FREQ_PREFIX_UA + current[lfuIndex]);
            String[] updated = Arrays.copyOf(current, current.length);
            updated[lfuIndex] = newUserAgent;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newUserAgent;
        return updated;
    }

    private String[] updateNormalOperatingSystems(String[] current, String newOS, Map<String, Long> frequencies) {
        if (newOS == null || newOS.isEmpty() || newOS.equals("Unknown")) {
            return current;
        }

        frequencies.merge(FREQ_PREFIX_OS + newOS, 1L, Long::sum);

        if (current == null || current.length == 0) {
            return new String[]{newOS};
        }

        for (String existing : current) {
            if (newOS.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 5) {
            int lfuIndex = findLeastFrequentIndex(current, FREQ_PREFIX_OS, frequencies);
            frequencies.remove(FREQ_PREFIX_OS + current[lfuIndex]);
            String[] updated = Arrays.copyOf(current, current.length);
            updated[lfuIndex] = newOS;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newOS;
        return updated;
    }

    private String[] updateNormalBrowsers(String[] current, String newBrowser, Map<String, Long> frequencies) {
        if (!StringUtils.hasText(newBrowser)) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_BROWSER + newBrowser, 1L, Long::sum);
        return mergeFrequentStringDimension(current, newBrowser, frequencies, FREQ_PREFIX_BROWSER, 5);
    }

    private String[] updateNormalIpBands(String[] current, String newIpBand, Map<String, Long> frequencies) {
        if (!StringUtils.hasText(newIpBand)) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_IP_BAND + newIpBand, 1L, Long::sum);
        return mergeFrequentStringDimension(current, newIpBand, frequencies, FREQ_PREFIX_IP_BAND, 5);
    }

    private String[] updateNormalAuthenticationTypes(String[] current, String newAuthenticationType, Map<String, Long> frequencies) {
        if (!StringUtils.hasText(newAuthenticationType)) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_AUTH + newAuthenticationType, 1L, Long::sum);
        return mergeFrequentStringDimension(current, newAuthenticationType, frequencies, FREQ_PREFIX_AUTH, 5);
    }

    private String[] updateFrequentActionFamilies(String[] current, String newActionFamily, Map<String, Long> frequencies) {
        if (!StringUtils.hasText(newActionFamily)) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_ACTION + newActionFamily, 1L, Long::sum);
        return mergeFrequentStringDimension(current, newActionFamily, frequencies, FREQ_PREFIX_ACTION, 8);
    }

    private String[] updateFrequentResourceFamilies(String[] current, String newResourceFamily, Map<String, Long> frequencies) {
        if (!StringUtils.hasText(newResourceFamily)) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_RESOURCE + newResourceFamily, 1L, Long::sum);
        return mergeFrequentStringDimension(current, newResourceFamily, frequencies, FREQ_PREFIX_RESOURCE, 8);
    }

    private String[] mergeFrequentStringDimension(
            String[] current,
            String newValue,
            Map<String, Long> frequencies,
            String frequencyPrefix,
            int maxSize) {
        if (!StringUtils.hasText(newValue)) {
            return current;
        }
        if (current == null || current.length == 0) {
            return new String[]{newValue};
        }
        for (String existing : current) {
            if (newValue.equals(existing)) {
                return current;
            }
        }
        if (current.length >= maxSize) {
            int lfuIndex = findLeastFrequentIndex(current, frequencyPrefix, frequencies);
            frequencies.remove(frequencyPrefix + current[lfuIndex]);
            String[] updated = Arrays.copyOf(current, current.length);
            updated[lfuIndex] = newValue;
            return updated;
        }
        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newValue;
        return updated;
    }

    private int findLeastFrequentIndex(String[] elements, String freqPrefix, Map<String, Long> frequencies) {
        int minIndex = 0;
        long minFreq = Long.MAX_VALUE;
        for (int i = 0; i < elements.length; i++) {
            long freq = frequencies.getOrDefault(freqPrefix + elements[i], 0L);
            if (freq < minFreq) {
                minFreq = freq;
                minIndex = i;
            }
        }
        return minIndex;
    }

    public BaselineVector getBaseline(String userId) {
        if (baselineDataStore == null || userId == null) {
            return null;
        }

        BaselineVector userBaseline = getPersonalBaseline(userId);
        if (userBaseline != null) {
            return userBaseline;
        }

        BaselineVector orgBaseline = getOrganizationBaselineForUser(userId);
        if (orgBaseline != null) {

            return BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(orgBaseline.getAvgTrustScore())
                    .avgRequestCount(orgBaseline.getAvgRequestCount())
                    .updateCount(0L)
                    .lastUpdated(orgBaseline.getLastUpdated())
                    .normalIpRanges(orgBaseline.getNormalIpRanges())
                    .normalAccessHours(orgBaseline.getNormalAccessHours())
                    .normalAccessDays(orgBaseline.getNormalAccessDays())
                    .frequentPaths(orgBaseline.getFrequentPaths())
                    .normalUserAgents(orgBaseline.getNormalUserAgents())
                    .normalOperatingSystems(orgBaseline.getNormalOperatingSystems())
                    .normalBrowsers(orgBaseline.getNormalBrowsers())
                    .normalIpBands(orgBaseline.getNormalIpBands())
                    .normalAuthenticationTypes(orgBaseline.getNormalAuthenticationTypes())
                    .frequentActionFamilies(orgBaseline.getFrequentActionFamilies())
                    .frequentResourceFamilies(orgBaseline.getFrequentResourceFamilies())
                    .elementFrequencies(orgBaseline.getElementFrequencies() != null
                            ? new HashMap<>(orgBaseline.getElementFrequencies())
                            : new HashMap<>())
                    .build();
        }

        return null;
    }

    public BaselineVector getPersonalBaseline(String userId) {
        if (baselineDataStore == null || userId == null) {
            return null;
        }
        return baselineDataStore.getUserBaseline(userId);
    }

    public BaselineVector getOrganizationBaselineForUser(String userId) {
        if (baselineDataStore == null || userId == null) {
            return null;
        }
        String organizationId = extractOrganizationId(userId);
        if (organizationId == null) {
            return null;
        }
        return baselineDataStore.getOrganizationBaseline(organizationId);
    }

    public BaselineVector getOrganizationBaseline(String organizationId) {
        if (baselineDataStore == null || !StringUtils.hasText(organizationId)) {
            return null;
        }
        return baselineDataStore.getOrganizationBaseline(organizationId);
    }

    public BaselineMaturitySnapshot describeBaselineMaturity(String userId) {
        return describeBaselineMaturity(userId, null);
    }

    public BaselineMaturitySnapshot describeBaselineMaturity(String userId, String organizationId) {
        BaselineVector personalBaseline = getPersonalBaseline(userId);
        BaselineVector organizationBaseline = resolveOrganizationBaseline(userId, organizationId);
        boolean personalAvailable = personalBaseline != null;
        boolean organizationAvailable = organizationBaseline != null;
        boolean personalEstablished = isPersonalBaselineEstablished(personalBaseline);
        boolean organizationEstablished = isOrganizationBaselineEstablished(organizationBaseline);

        if (personalEstablished) {
            return new BaselineMaturitySnapshot(
                    personalAvailable,
                    true,
                    organizationAvailable,
                    organizationEstablished,
                    false,
                    List.of());
        }

        List<String> supportingDimensions = determineSupportingDimensions(organizationBaseline, organizationEstablished);
        return new BaselineMaturitySnapshot(
                personalAvailable,
                false,
                organizationAvailable,
                organizationEstablished,
                !supportingDimensions.isEmpty(),
                supportingDimensions);
    }

    public BaselineEvidenceSnapshot buildBaselineEvidenceSnapshot(String userId, SecurityEvent currentEvent) {
        if (!StringUtils.hasText(userId)) {
            return new BaselineEvidenceSnapshot(
                    LearningEvidenceScope.PERSONAL,
                    false,
                    false,
                    null,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    "",
                    BaselineEvidenceStatus.MISSING_USER_ID,
                    "Cannot lookup baseline without user identifier");
        }
        BaselineVector personalBaseline = getPersonalBaseline(userId);
        BaselineMaturitySnapshot maturity = describeBaselineMaturity(userId, resolveOrganizationId(currentEvent, userId));
        if (personalBaseline == null) {
            return new BaselineEvidenceSnapshot(
                    LearningEvidenceScope.PERSONAL,
                    false,
                    false,
                    null,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    buildNewUserWarning(userId, currentEvent),
                    BaselineEvidenceStatus.NO_DATA,
                    buildNewUserWarning(userId, currentEvent));
        }
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                maturity.personalBaselineAvailable(),
                maturity.personalBaselineEstablished(),
                personalBaseline.getUpdateCount(),
                personalBaseline.getAvgTrustScore(),
                strings(personalBaseline.getNormalIpRanges()),
                integers(personalBaseline.getNormalAccessHours()),
                integers(personalBaseline.getNormalAccessDays()),
                strings(firstNonEmpty(personalBaseline.getNormalBrowsers(), personalBaseline.getNormalUserAgents())),
                strings(personalBaseline.getNormalOperatingSystems()),
                strings(personalBaseline.getFrequentPaths()),
                strings(personalBaseline.getNormalAuthenticationTypes()),
                strings(personalBaseline.getFrequentActionFamilies()),
                strings(personalBaseline.getFrequentResourceFamilies()),
                buildBaselineEvidenceSummary(
                        maturity.personalBaselineEstablished(),
                        personalBaseline),
                BaselineEvidenceStatus.AVAILABLE,
                "");
    }

    public BaselineEvidenceSnapshot buildSupportingBaselineEvidenceSnapshot(String userId) {
        return buildSupportingBaselineEvidenceSnapshot(userId, null);
    }

    public BaselineEvidenceSnapshot buildSupportingBaselineEvidenceSnapshot(String userId, String organizationId) {
        BaselineVector organizationBaseline = resolveOrganizationBaseline(userId, organizationId);
        BaselineMaturitySnapshot maturity = describeBaselineMaturity(userId, organizationId);
        if (organizationBaseline == null) {
            return new BaselineEvidenceSnapshot(
                    LearningEvidenceScope.SUPPORTING,
                    false,
                    false,
                    null,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    "",
                    BaselineEvidenceStatus.NO_DATA,
                    "supporting baseline unavailable");
        }

        StringBuilder summary = new StringBuilder();
        summary.append("organization baseline available");
        if (maturity.organizationBaselineEstablished()) {
            summary.append(" | organization baseline established");
        }
        List<String> supportingDimensions = maturity.supportingDimensions();
        if (supportingDimensions != null && !supportingDimensions.isEmpty()) {
            summary.append(" | supportingDimensions=").append(String.join(", ", supportingDimensions));
        }

        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.SUPPORTING,
                maturity.organizationBaselineAvailable(),
                maturity.organizationBaselineEstablished(),
                organizationBaseline.getUpdateCount(),
                organizationBaseline.getAvgTrustScore(),
                strings(organizationBaseline.getNormalIpRanges()),
                integers(organizationBaseline.getNormalAccessHours()),
                integers(organizationBaseline.getNormalAccessDays()),
                strings(firstNonEmpty(organizationBaseline.getNormalBrowsers(), organizationBaseline.getNormalUserAgents())),
                strings(organizationBaseline.getNormalOperatingSystems()),
                strings(organizationBaseline.getFrequentPaths()),
                strings(organizationBaseline.getNormalAuthenticationTypes()),
                strings(organizationBaseline.getFrequentActionFamilies()),
                strings(organizationBaseline.getFrequentResourceFamilies()),
                summary.toString(),
                BaselineEvidenceStatus.AVAILABLE,
                "");
    }

    private String buildBaselineEvidenceSummary(boolean established, BaselineVector baseline) {
        if (baseline == null) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        parts.add(established ? "personal baseline established" : "personal baseline provisional");
        if (baseline.getUpdateCount() != null) {
            parts.add("observations=" + baseline.getUpdateCount());
        }
        addSummaryPart(parts, "hours", integers(baseline.getNormalAccessHours()));
        addSummaryPart(parts, "days", integers(baseline.getNormalAccessDays()));
        addSummaryPart(parts, "networks", strings(baseline.getNormalIpRanges()));
        addSummaryPart(parts, "browsers", strings(firstNonEmpty(baseline.getNormalBrowsers(), baseline.getNormalUserAgents())));
        addSummaryPart(parts, "paths", strings(baseline.getFrequentPaths()));
        addSummaryPart(parts, "auth", strings(baseline.getNormalAuthenticationTypes()));
        addSummaryPart(parts, "actions", strings(baseline.getFrequentActionFamilies()));
        addSummaryPart(parts, "resources", strings(baseline.getFrequentResourceFamilies()));
        return String.join(" | ", parts);
    }

    private static final int ORG_BASELINE_MAX_ARRAY_SIZE = 50;

    private void updateOrganizationBaseline(String userId, SecurityEvent currentEvent, BaselineVector userBaseline) {
        try {
            String orgId = resolveOrganizationId(currentEvent, userId);
            if (orgId == null) {
                return;
            }

            double alpha = hcadProperties.getBaseline().getLearning().getAlpha();
            BaselineVector orgBaseline = baselineDataStore.getOrganizationBaseline(orgId);

            if (orgBaseline == null) {
                BaselineVector newOrg = BaselineVector.builder()
                        .userId("org:" + orgId)
                        .avgTrustScore(userBaseline.getAvgTrustScore())
                        .avgRequestCount(userBaseline.getAvgRequestCount())
                        .updateCount(1L)
                        .lastUpdated(Instant.now())
                        .normalIpRanges(userBaseline.getNormalIpRanges())
                        .normalAccessHours(userBaseline.getNormalAccessHours())
                        .normalAccessDays(userBaseline.getNormalAccessDays())
                        .frequentPaths(userBaseline.getFrequentPaths())
                        .normalUserAgents(userBaseline.getNormalUserAgents())
                        .normalOperatingSystems(userBaseline.getNormalOperatingSystems())
                        .normalBrowsers(userBaseline.getNormalBrowsers())
                        .normalIpBands(userBaseline.getNormalIpBands())
                        .normalAuthenticationTypes(userBaseline.getNormalAuthenticationTypes())
                        .frequentActionFamilies(userBaseline.getFrequentActionFamilies())
                        .frequentResourceFamilies(userBaseline.getFrequentResourceFamilies())
                        .elementFrequencies(userBaseline.getElementFrequencies() != null
                                ? new HashMap<>(userBaseline.getElementFrequencies()) : new HashMap<>())
                        .build();
                baselineDataStore.saveOrganizationBaseline(orgId, newOrg);
                return;
            }

            double newAvgTrust = orgBaseline.getAvgTrustScore() * (1 - alpha)
                    + userBaseline.getAvgTrustScore() * alpha;
            long newAvgRequest = (long) (orgBaseline.getAvgRequestCount() * (1 - alpha)
                    + userBaseline.getAvgRequestCount() * alpha);

            BaselineVector updated = BaselineVector.builder()
                    .userId("org:" + orgId)
                    .avgTrustScore(newAvgTrust)
                    .avgRequestCount(newAvgRequest)
                    .updateCount(orgBaseline.getUpdateCount() + 1)
                    .lastUpdated(Instant.now())
                    .normalIpRanges(mergeStringArrays(
                            orgBaseline.getNormalIpRanges(), userBaseline.getNormalIpRanges()))
                    .normalAccessHours(mergeIntegerArrays(
                            orgBaseline.getNormalAccessHours(), userBaseline.getNormalAccessHours()))
                    .normalAccessDays(mergeIntegerArrays(
                            orgBaseline.getNormalAccessDays(), userBaseline.getNormalAccessDays()))
                    .frequentPaths(mergeStringArrays(
                            orgBaseline.getFrequentPaths(), userBaseline.getFrequentPaths()))
                    .normalUserAgents(mergeStringArrays(
                            orgBaseline.getNormalUserAgents(), userBaseline.getNormalUserAgents()))
                    .normalOperatingSystems(mergeStringArrays(
                            orgBaseline.getNormalOperatingSystems(), userBaseline.getNormalOperatingSystems()))
                    .normalBrowsers(mergeStringArrays(
                            orgBaseline.getNormalBrowsers(), userBaseline.getNormalBrowsers()))
                    .normalIpBands(mergeStringArrays(
                            orgBaseline.getNormalIpBands(), userBaseline.getNormalIpBands()))
                    .normalAuthenticationTypes(mergeStringArrays(
                            orgBaseline.getNormalAuthenticationTypes(), userBaseline.getNormalAuthenticationTypes()))
                    .frequentActionFamilies(mergeStringArrays(
                            orgBaseline.getFrequentActionFamilies(), userBaseline.getFrequentActionFamilies()))
                    .frequentResourceFamilies(mergeStringArrays(
                            orgBaseline.getFrequentResourceFamilies(), userBaseline.getFrequentResourceFamilies()))
                    .elementFrequencies(mergeFrequencies(
                            orgBaseline.getElementFrequencies(), userBaseline.getElementFrequencies()))
                    .build();
            baselineDataStore.saveOrganizationBaseline(orgId, updated);

        } catch (Exception e) {
            log.error("[BaselineLearningService] Organization baseline update failed: userId={}", userId, e);
        }
    }

    private String resolveOrganizationId(SecurityEvent currentEvent, String userId) {
        if (currentEvent != null && currentEvent.getMetadata() != null) {
            String metadataOrganizationId = firstNonBlankText(
                    textValue(currentEvent.getMetadata().get("organizationId")),
                    textValue(currentEvent.getMetadata().get("orgId")));
            if (StringUtils.hasText(metadataOrganizationId)) {
                return metadataOrganizationId;
            }
        }
        return null;
    }

    private BaselineVector resolveOrganizationBaseline(String userId, String organizationId) {
        return getOrganizationBaseline(organizationId);
    }

    private String[] mergeStringArrays(String[] existing, String[] incoming) {
        if (incoming == null || incoming.length == 0) {
            return existing;
        }
        if (existing == null || existing.length == 0) {
            return incoming;
        }
        Set<String> merged = new LinkedHashSet<>(Arrays.asList(existing));
        for (String value : incoming) {
            if (value != null && !value.isEmpty()) {
                merged.add(value);
            }
        }
        if (merged.size() > ORG_BASELINE_MAX_ARRAY_SIZE) {
            return merged.stream()
                    .skip(merged.size() - ORG_BASELINE_MAX_ARRAY_SIZE)
                    .toArray(String[]::new);
        }
        return merged.toArray(new String[0]);
    }

    private Integer[] mergeIntegerArrays(Integer[] existing, Integer[] incoming) {
        if (incoming == null || incoming.length == 0) {
            return existing;
        }
        if (existing == null || existing.length == 0) {
            return incoming;
        }
        Set<Integer> merged = new LinkedHashSet<>(Arrays.asList(existing));
        for (Integer value : incoming) {
            if (value != null) {
                merged.add(value);
            }
        }
        return merged.toArray(new Integer[0]);
    }

    private Map<String, Long> mergeFrequencies(Map<String, Long> existing, Map<String, Long> incoming) {
        if (incoming == null || incoming.isEmpty()) {
            return existing != null ? existing : new HashMap<>();
        }
        if (existing == null || existing.isEmpty()) {
            return new HashMap<>(incoming);
        }
        Map<String, Long> merged = new HashMap<>(existing);
        for (Map.Entry<String, Long> entry : incoming.entrySet()) {
            merged.merge(entry.getKey(), entry.getValue(), Long::sum);
        }
        return merged;
    }

    private String extractOrganizationId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return null;
        }

        int underscoreIndex = userId.indexOf('_');
        if (underscoreIndex > 0) {
            return userId.substring(0, underscoreIndex);
        }

        int atIndex = userId.indexOf('@');
        if (atIndex > 0) {
            return userId.substring(0, atIndex);
        }

        return null;
    }

    private boolean isPersonalBaselineEstablished(BaselineVector baseline) {
        if (baseline == null) {
            return false;
        }
        return value(baseline.getUpdateCount()) >= minimumSampleCount();
    }

    private boolean isOrganizationBaselineEstablished(BaselineVector baseline) {
        if (baseline == null) {
            return false;
        }
        return value(baseline.getUpdateCount()) >= minimumSampleCount();
    }

    private int minimumSampleCount() {
        int configured = hcadProperties.getBaseline().getStatistical().getMinSamples();
        return Math.max(1, configured);
    }

    private long value(Long input) {
        return input != null ? input : 0L;
    }

    private List<String> determineSupportingDimensions(BaselineVector organizationBaseline, boolean organizationEstablished) {
        if (organizationBaseline == null) {
            return COHORT_SUPPORT_DIMENSIONS;
        }
        List<String> missingDimensions = new ArrayList<>();
        if (organizationBaseline.getNormalAccessHours() == null || organizationBaseline.getNormalAccessHours().length == 0) {
            missingDimensions.add("ACCESS_HOURS");
        }
        if (organizationBaseline.getNormalAccessDays() == null || organizationBaseline.getNormalAccessDays().length == 0) {
            missingDimensions.add("ACCESS_DAYS");
        }
        if (organizationBaseline.getNormalOperatingSystems() == null || organizationBaseline.getNormalOperatingSystems().length == 0) {
            missingDimensions.add("OPERATING_SYSTEMS");
        }
        if (!organizationEstablished && missingDimensions.isEmpty()) {
            return COHORT_SUPPORT_DIMENSIONS;
        }
        return List.copyOf(missingDimensions);
    }

    public String buildBaselinePromptContext(String userId, SecurityEvent currentEvent) {
        return buildBaselinePromptContext(userId, resolveOrganizationId(currentEvent, userId), currentEvent);
    }

    public String buildBaselinePromptContext(String userId, String organizationId, SecurityEvent currentEvent) {
        if (userId == null) {
            return "Baseline: User ID not available";
        }

        BaselineVector userBaseline = baselineDataStore.getUserBaseline(userId);
        BaselineVector orgBaseline = resolveOrganizationBaseline(userId, organizationId);

        if (userBaseline == null && orgBaseline == null) {
            return buildNewUserWarning(userId, currentEvent);
        }

        StringBuilder sb = new StringBuilder();

        if (userBaseline != null) {
            sb.append("Personal Baseline:\n");
            appendBaselineDetails(sb, userBaseline);
        } else {
            sb.append("[NO_PERSONAL_BASELINE] This user has no personal behavioral history.\n");
        }

        if (orgBaseline != null) {
            sb.append("\nOrganization Baseline");
            if (userBaseline == null) {
                sb.append(" (reference only - NOT this user's personal patterns)");
            }
            sb.append(":\n");
            appendBaselineDetails(sb, orgBaseline);
        }

        return sb.toString();
    }

    private void appendBaselineDetails(StringBuilder sb, BaselineVector baseline) {
        String[] normalIps = baseline.getNormalIpRanges();
        Integer[] normalHours = baseline.getNormalAccessHours();
        Integer[] normalDays = baseline.getNormalAccessDays();
        String[] normalUserAgents = baseline.getNormalUserAgents();
        String[] normalOS = baseline.getNormalOperatingSystems();
        String[] frequentPaths = baseline.getFrequentPaths();

        if (normalIps != null && normalIps.length > 0) {
            sb.append("Known IPs: ").append(String.join(", ", normalIps)).append("\n");
        }

        if (normalHours != null && normalHours.length > 0) {
            StringBuilder hours = new StringBuilder();
            for (int i = 0; i < normalHours.length; i++) {
                if (i > 0) hours.append(", ");
                hours.append(normalHours[i]);
            }
            sb.append("Known Hours: ").append(hours).append("\n");
        }

        if (normalDays != null && normalDays.length > 0) {
            StringBuilder days = new StringBuilder();
            for (int i = 0; i < normalDays.length; i++) {
                if (i > 0) days.append(", ");
                days.append(normalDays[i]);
            }
            sb.append("Known Days: ").append(days).append("\n");
        }

        String uaSignature = normalUserAgents != null && normalUserAgents.length > 0
                ? extractUASignature(normalUserAgents[0]) : "none";
        sb.append("Known UA: ").append(uaSignature).append("\n");

        if (normalOS != null && normalOS.length > 0) {
            sb.append("Known OS: ").append(String.join(", ", normalOS)).append("\n");
        }

        if (frequentPaths != null && frequentPaths.length > 0) {
            sb.append("Frequent Paths: ").append(String.join(", ", frequentPaths)).append("\n");
        }
    }

    private String buildNewUserWarning(String userId, SecurityEvent currentEvent) {
        StringBuilder sb = new StringBuilder();

        sb.append("=== PERSONAL BASELINE STATUS ===\n");
        sb.append("PersonalBaselineStatus: NOT_ESTABLISHED\n");
        sb.append("PersonalBaselineSummary: No verified personal behavior baseline is available for this subject yet.\n");
        sb.append("BaselineInterpretation: Missing personal history is uncertainty, not proof of compromise or legitimacy.\n");
        sb.append("BaselineComparisonStatus: No verified personal history is available for direct comparison.\n");
        sb.append("BaselineCollectorGuidance: Use only current request facts and any separately retrieved evidence.\n\n");

        sb.append("Current Request Context:\n");
        if (currentEvent != null) {
            String sourceIp = currentEvent.getSourceIp();
            String normalizedIp = extractIpRange(sourceIp);
            if (sourceIp != null && !sourceIp.isBlank() && normalizedIp != null && !normalizedIp.equals(sourceIp)) {
                sb.append(String.format("  IP: %s (range %s)\n", sourceIp, normalizedIp));
            }
            else {
                sb.append(String.format("  IP: %s\n", sourceIp != null && !sourceIp.isBlank() ? sourceIp : "NOT_PROVIDED"));
            }

            if (currentEvent.getTimestamp() != null) {
                sb.append(String.format("  Hour: %d\n", currentEvent.getTimestamp().getHour()));
            }

            String userAgent = currentEvent.getUserAgent();
            String uaSignature = extractUASignature(userAgent);
            sb.append(String.format("  UA: %s\n", uaSignature));
        }
        sb.append("\n");

        sb.append("=== BASELINE COMPARISON NOTES ===\n");
        sb.append("- RELATED CONTEXT may contain verified historical evidence if retrieval returns matching records.\n");
        sb.append("- If RELATED CONTEXT is EMPTY, there is no verified personal comparison evidence for this request.\n");
        sb.append("- Do not infer subject legitimacy or compromise solely from the absence of personal baseline data.\n\n");

        return sb.toString();
    }

    private String extractPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("targetResource")) {
            Object targetResource = metadata.get("targetResource");
            if (targetResource != null && !targetResource.toString().isEmpty()) {
                return targetResource.toString();
            }
        }

        if (metadata != null && metadata.containsKey("requestPath")) {
            Object path = metadata.get("requestPath");
            if (path != null) {
                return path.toString();
            }
        }

        return null;
    }

    private String extractBrowser(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        String explicitBrowser = extractMetadataText(event, "deviceBrowser", "userAgentBrowser");
        String explicitVersion = extractMetadataText(event, "deviceBrowserVersion");
        if (StringUtils.hasText(explicitBrowser)) {
            return StringUtils.hasText(explicitVersion)
                    ? explicitBrowser + "/" + explicitVersion
                    : explicitBrowser;
        }
        return extractUASignature(event.getUserAgent());
    }

    private String extractActionFamily(SecurityEvent event) {
        String explicit = extractMetadataText(event, "actionFamily", "operation", "httpMethod", "method");
        return SecuritySemanticNormalizer.normalizeActionFamily(explicit);
    }

    private String extractResourceFamily(SecurityEvent event) {
        String explicit = extractMetadataText(event, "resourceFamily", "resourceType", "resourceCategory");
        if (StringUtils.hasText(explicit)) {
            return SecuritySemanticNormalizer.normalizeResourceFamily(explicit);
        }
        return SecuritySemanticNormalizer.normalizePathFamily(extractPath(event));
    }

    private String extractPathFamily(SecurityEvent event) {
        return SecuritySemanticNormalizer.normalizePathFamily(extractPath(event));
    }

    private String extractMetadataText(SecurityEvent event, String... keys) {
        if (event == null || event.getMetadata() == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = event.getMetadata().get(key);
            if (value == null) {
                continue;
            }
            String text = String.valueOf(value).trim();
            if (!text.isEmpty()) {
                return text;
            }
        }
        return null;
    }

    private String extractOS(String userAgent) {
        return SecurityEventEnricher.extractOSFromUserAgent(userAgent);
    }

    private String extractUASignature(String userAgent) {
        return SecurityEventEnricher.extractBrowserSignature(userAgent);
    }

    private String[] firstNonEmpty(String[] primary, String[] fallback) {
        return primary != null && primary.length > 0 ? primary : fallback;
    }

    private void addSummaryPart(List<String> parts, String label, List<String> values) {
        if (parts == null || values == null || values.isEmpty()) {
            return;
        }
        parts.add(label + "=" + String.join(", ", values));
    }

    private List<String> strings(String[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> integers(Integer[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(Objects::nonNull)
                .map(String::valueOf)
                .distinct()
                .toList();
    }

    private String firstNonBlankText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private String textValue(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    public record BaselineMaturitySnapshot(
            boolean personalBaselineAvailable,
            boolean personalBaselineEstablished,
            boolean organizationBaselineAvailable,
            boolean organizationBaselineEstablished,
            boolean cohortSeedRecommended,
            List<String> supportingDimensions) {

        public BaselineMaturitySnapshot {
            supportingDimensions = supportingDimensions == null ? List.of() : List.copyOf(supportingDimensions);
        }
    }
}
