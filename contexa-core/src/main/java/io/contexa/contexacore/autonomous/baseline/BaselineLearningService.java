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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.support.VocabularyMigration;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

@Slf4j
@RequiredArgsConstructor
public class BaselineLearningService {

    private final BaselineDataStore baselineDataStore;
    private final SecurityZeroTrustProperties zeroTrustProperties;

    /** The update lock of a user's baseline: the key the admin approval used, so every learning path takes one lock. */
    private static final String USER_LOCK_PREFIX = "baseline:update:";
    private static final String ORGANIZATION_LOCK_PREFIX = "baseline:update:org:";
    private static final Duration LOCK_HOLD = Duration.ofSeconds(10);
    private static final Duration LOCK_WAIT = Duration.ofSeconds(5);
    private static final int LOCAL_LOCK_STRIPES = 64;

    /** The locks of this JVM when no lock service is set, striped so that their number stays fixed. */
    private final ReentrantLock[] localLocks = localLocks();
    private volatile DistributedLockService lockService;

    /** The most recent learned company dates a baseline keeps, enough for any minimum of days (W5-10 D4). */
    private static final int RECENT_LEARNED_DATES = 31;
    private static final String FREQ_PREFIX_IP = "ip:";
    private static final String FREQ_PREFIX_UA = "ua:";
    private static final String FREQ_PREFIX_OS = "os:";
    private static final String FREQ_PREFIX_PATH = "path:";
    private static final String FREQ_PREFIX_HOUR = "hour:";
    private static final String FREQ_PREFIX_DAY = "day:";
    private static final String FREQ_PREFIX_BROWSER = "browser:";
    private static final String FREQ_PREFIX_DEVICE = "device:";
    private static final String FREQ_PREFIX_IP_BAND = "ipBand:";
    private static final String FREQ_PREFIX_AUTH = "auth:";
    private static final String FREQ_PREFIX_ACTION = "action:";
    private static final String FREQ_PREFIX_RESOURCE = "resource:";
    /**
     * The share of an organization's learned requests a value must hold to be usual for the organization (W5-10 D7);
     * a value seen less often was seen, not usual.
     */
    private static final double ORGANIZATION_USUAL_SHARE = 0.05;
    private static final List<String> COHORT_SUPPORT_DIMENSIONS = List.of(
            "ACCESS_HOURS",
            "ACCESS_DAYS",
            "OPERATING_SYSTEMS");

    /** The lock service the baseline updates run under, user by user and organization by organization (W5-8). */
    public void setLockService(DistributedLockService lockService) {
        this.lockService = lockService;
    }

    public boolean learnIfNormal(String userId, SecurityDecision decision, SecurityEvent event) {
        if (!zeroTrustProperties.getBaseline().getLearning().isEnabled()) {
            return false;
        }

        if (userId == null || decision == null) return false;
        if (!shouldLearnFromSecurityEvent(decision)) return false;

        try {
            // The personal read, learning and write run under the user's lock (W5-8), the user within the request's
            // tenant (W5-10 D9).
            String key = personalKey(userId, event);
            LearnedBaseline learned = underLock(USER_LOCK_PREFIX + key,
                    () -> learnPersonal(userId, key, decision, event));
            if (learned == null) {
                return false;
            }
            updateOrganizationBaseline(userId, event, learned.previous(), learned.current());
            return true;

        } catch (Exception e) {
            log.error("[BaselineLearningService] SecurityEvent learning failed: userId={}", userId, e);
            return false;
        }
    }

    /** The personal baseline before and after one learning. */
    private record LearnedBaseline(BaselineVector previous, BaselineVector current) {
    }

    /**
     * Reads, learns and writes the user's baseline; null when nothing was learned. A read that fails is not taken for
     * a missing baseline, so no new baseline is written over one that could not be read (W5-8).
     */
    private LearnedBaseline learnPersonal(String userId, String key, SecurityDecision decision, SecurityEvent event) {
        BaselineDataStore.BaselineRead read = readPersonal(key);
        boolean earlierKey = false;
        if (read.state() == BaselineDataStore.BaselineRead.State.ABSENT && !key.equals(userId)) {
            // A baseline learned before the tenant key is read and moved under it (W5-10 D9).
            read = readPersonal(userId);
            earlierKey = read.baseline() != null;
        }
        if (read.isFailed()) {
            log.error("[BaselineLearningService] Personal baseline could not be read, nothing learned: userId={}",
                    userId);
            return null;
        }
        BaselineVector current = read.baseline();
        BaselineVector updated = updateWithEMAFromSecurityEvent(current, userId, decision, event);
        if (updated == null) {
            return null;
        }
        baselineDataStore.saveUserBaseline(key, updated);
        if (earlierKey) {
            // The earlier key goes, so that the baseline is not counted twice nor left behind by an account purge.
            baselineDataStore.deleteUserBaselineKey(userId);
        }
        return new LearnedBaseline(current, updated);
    }

    private BaselineDataStore.BaselineRead readPersonal(String key) {
        BaselineDataStore.BaselineRead read = baselineDataStore.readUserBaseline(key);
        return read != null ? read : BaselineDataStore.BaselineRead.of(baselineDataStore.getUserBaseline(key));
    }

    /** The key of the user's personal baseline within the request's tenant, the user alone without one (W5-10 D9). */
    private String personalKey(String userId, SecurityEvent event) {
        return BaselineDataStore.userKey(extractMetadataText(event, "tenantId", "tenant_id"), userId);
    }

    /** Runs the update under the key's lock; null, with nothing done, when the lock is not taken in time (W5-8). */
    private <T> T underLock(String key, Supplier<T> update) {
        DistributedLockService locks = lockService;
        if (locks == null) {
            ReentrantLock local = localLocks[Math.floorMod(key.hashCode(), LOCAL_LOCK_STRIPES)];
            local.lock();
            try {
                return update.get();
            } finally {
                local.unlock();
            }
        }
        String owner = UUID.randomUUID().toString();
        if (!locks.tryLockWithWait(key, owner, LOCK_HOLD, LOCK_WAIT)) {
            log.error("[BaselineLearningService] Baseline update lock not taken, nothing learned: key={}", key);
            return null;
        }
        try {
            return update.get();
        } finally {
            locks.unlock(key, owner);
        }
    }

    private static ReentrantLock[] localLocks() {
        ReentrantLock[] locks = new ReentrantLock[LOCAL_LOCK_STRIPES];
        for (int index = 0; index < locks.length; index++) {
            locks[index] = new ReentrantLock();
        }
        return locks;
    }

    private boolean shouldLearnFromSecurityEvent(SecurityDecision decision) {
        return decision.resolveAutonomousAction() == ZeroTrustAction.ALLOW;
    }

    private BaselineVector updateWithEMAFromSecurityEvent(BaselineVector current, String userId,
                                                          SecurityDecision decision, SecurityEvent event) {

        double currentTrustScore = resolveVerifiedTrustSignal(decision);

        String currentIp = event != null ? event.getSourceIp() : null;
        Integer currentHour = extractHourFromSecurityEvent(event);
        Integer currentDay = extractDayFromSecurityEvent(event);
        String currentDate = event != null && event.getTimestamp() != null
                ? event.getLocalTimestamp().toLocalDate().toString() : null;
        String currentPath = extractPathFamily(event);
        String currentUserAgent = event != null ? event.getUserAgent() : null;
        String currentBrowser = extractBrowser(event);
        // The system is read in the order the request's device is resolved, so the baseline learns what it is compared
        // with (W2-4).
        String currentOS = SecuritySemanticNormalizer.normalizeOperatingSystem(
                extractMetadataText(event, "deviceOs", "os"), extractOS(currentUserAgent));
        String currentDevice = SecuritySemanticNormalizer.device(currentBrowser, currentOS);
        String currentIpBand = SecuritySemanticNormalizer.normalizeNetwork(currentIp, extractMetadataText(event, "ipBand"));
        String currentAuthenticationType = SecuritySemanticNormalizer.normalizeAuthenticationType(
                extractMetadataText(event, "authMethod", "authenticationType"));
        String currentActionFamily = extractActionFamily(event);
        String currentResourceFamily = extractResourceFamily(event);

        // A client without a browser signature (an API client, a server call) is learned in every other dimension;
        // its browser, device and user-agent signature stay unlearned (W5-6).
        String uaSignature = extractUASignature(currentUserAgent);

        if (current == null) {

            Map<String, Long> frequencies = new HashMap<>();
            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                    .userId(userId)
                    .vocabularyVersion(VocabularyVersion.CURRENT)
                    .avgTrustScore(currentTrustScore)
                    .avgRequestCount(1L)
                    .updateCount(1L)
                    .lastUpdated(Instant.now())
                    .learnedDates(learnedDates(null, currentDate))
                    .recentNovelty(recentNovelty(null, true));

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
            if (currentDevice != null) {
                builder.normalDevices(new String[]{currentDevice});
                frequencies.put(FREQ_PREFIX_DEVICE + currentDevice, 1L);
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

            if (StringUtils.hasText(uaSignature)) {
                builder.normalUserAgents(new String[]{uaSignature});
                frequencies.put(FREQ_PREFIX_UA + uaSignature, 1L);
            }

            if (StringUtils.hasText(currentOS)) {
                builder.normalOperatingSystems(new String[]{currentOS});
                frequencies.put(FREQ_PREFIX_OS + currentOS, 1L);
            }

            builder.elementFrequencies(frequencies);
            return builder.build();
        }

        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double alpha = zeroTrustProperties.getBaseline().getLearning().getAlpha();
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        Map<String, Long> frequencies = current.getElementFrequencies() != null
                ? new HashMap<>(current.getElementFrequencies())
                : new HashMap<>();

        // Every stored vocabulary value is read into today's vocabulary with its count (W5-7): a network learned
        // before W2-4 as a prefix, a login method or a family under an earlier name, a path under the earlier rule.
        String[] storedIpRanges = canonicalized(current.getNormalIpRanges(), FREQ_PREFIX_IP, frequencies,
                VocabularyMigration::network);
        String[] storedIpBands = canonicalized(current.getNormalIpBands(), FREQ_PREFIX_IP_BAND, frequencies,
                VocabularyMigration::network);
        String[] storedOperatingSystems = canonicalized(current.getNormalOperatingSystems(), FREQ_PREFIX_OS,
                frequencies, VocabularyMigration::operatingSystem);
        String[] storedAuthenticationTypes = canonicalized(current.getNormalAuthenticationTypes(), FREQ_PREFIX_AUTH,
                frequencies, stored -> VocabularyMigration.authenticationType(stored, current.getVocabularyVersion()));
        String[] storedActionFamilies = canonicalized(current.getFrequentActionFamilies(), FREQ_PREFIX_ACTION,
                frequencies, VocabularyMigration::actionFamily);
        String[] storedResourceFamilies = canonicalized(current.getFrequentResourceFamilies(), FREQ_PREFIX_RESOURCE,
                frequencies, VocabularyMigration::resourceClass);
        String[] storedPaths = canonicalized(current.getFrequentPaths(), FREQ_PREFIX_PATH, frequencies,
                VocabularyMigration::pathFamily);
        // W5-10 D4: whether this learning brings a value the baseline had not seen, on the dimensions its convergence
        // reads; read before the lists take the request's values.
        boolean novel = isNew(current.getNormalAccessHours(), currentHour) || isNew(storedIpBands, currentIpBand)
                || isNew(current.getNormalDevices(), currentDevice) || isNew(storedActionFamilies, currentActionFamily);
        String[] normalIpRanges = updateNormalIpRanges(storedIpRanges, currentIpBand, frequencies);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour, frequencies);
        Integer[] normalAccessDays = updateNormalAccessDays(current.getNormalAccessDays(), currentDay, frequencies);
        String[] frequentPaths = updateFrequentPaths(storedPaths, currentPath, frequencies);
        String[] normalBrowsers = updateNormalBrowsers(current.getNormalBrowsers(), currentBrowser, frequencies);
        String[] normalDevices = updateNormalDevices(current.getNormalDevices(), currentDevice, frequencies);
        String[] normalIpBands = updateNormalIpBands(storedIpBands, currentIpBand, frequencies);
        String[] normalAuthenticationTypes = updateNormalAuthenticationTypes(storedAuthenticationTypes,
                currentAuthenticationType, frequencies);
        String[] frequentActionFamilies = updateFrequentActionFamilies(storedActionFamilies, currentActionFamily,
                frequencies);
        String[] frequentResourceFamilies = updateFrequentResourceFamilies(storedResourceFamilies,
                currentResourceFamily, frequencies);

        String[] normalUserAgents = updateNormalUserAgents(current.getNormalUserAgents(), uaSignature, frequencies);

        String[] normalOperatingSystems = updateNormalOperatingSystems(storedOperatingSystems, currentOS, frequencies);

        return BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(newTrustScore)
                .avgRequestCount(oldRequestCount + 1)
                .updateCount(oldUpdateCount + 1)
                .lastUpdated(Instant.now())
                .vocabularyVersion(VocabularyVersion.CURRENT)
                .learnedDates(learnedDates(current.getLearnedDates(), currentDate))
                .recentNovelty(recentNovelty(current.getRecentNovelty(), novel))

                .normalIpRanges(normalIpRanges)
                .normalAccessHours(normalAccessHours)
                .normalAccessDays(normalAccessDays)
                .frequentPaths(frequentPaths)
                .normalUserAgents(normalUserAgents)
                .normalOperatingSystems(normalOperatingSystems)
                .normalBrowsers(normalBrowsers)
                .normalDevices(normalDevices)
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
        return event.getLocalTimestamp().getHour();
    }

    private double resolveVerifiedTrustSignal(SecurityDecision decision) {
        if (decision == null || decision.resolveAutonomousAction() == null) {
            return 0.5d;
        }
        return switch (decision.resolveAutonomousAction()) {
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
        return event.getLocalTimestamp().getDayOfWeek().getValue();
    }

    private String extractIpRange(String ip) {
        return SecuritySemanticNormalizer.normalizeNetwork(null, ip);
    }

    /**
     * The stored values in today's form, their frequencies moved to the new keys: a three-octet prefix and its /24
     * band, or "Windows" and WINDOWS, are one value in two forms (W2-4). A value that no longer names anything (a
     * device class learned as a system) is dropped with its frequency.
     */
    private static String[] canonicalized(String[] values, String prefix, Map<String, Long> frequencies,
            UnaryOperator<String> canonical) {
        if (values == null || values.length == 0) {
            return values;
        }
        Set<String> forms = new LinkedHashSet<>();
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            String form = canonical.apply(value);
            if (form == null || !form.equals(value)) {
                Long count = frequencies.remove(prefix + value);
                if (form != null && count != null) {
                    frequencies.merge(prefix + form, count, Long::sum);
                }
            }
            if (form != null) {
                forms.add(form);
            }
        }
        return forms.toArray(String[]::new);
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

    private String[] updateNormalDevices(String[] current, String newDevice, Map<String, Long> frequencies) {
        if (!StringUtils.hasText(newDevice)) {
            return current;
        }
        frequencies.merge(FREQ_PREFIX_DEVICE + newDevice, 1L, Long::sum);
        return mergeFrequentStringDimension(current, newDevice, frequencies, FREQ_PREFIX_DEVICE, 5);
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
        String[] normalizedCurrent = semanticResourceFamilies(current).toArray(String[]::new);
        if (!StringUtils.hasText(newResourceFamily)) {
            return normalizedCurrent;
        }
        frequencies.merge(FREQ_PREFIX_RESOURCE + newResourceFamily, 1L, Long::sum);
        return mergeFrequentStringDimension(normalizedCurrent, newResourceFamily, frequencies, FREQ_PREFIX_RESOURCE, 8);
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

        // A user without a personal baseline starts from the request itself: the organization baseline is a peer
        // reference only and never becomes the user's usual behaviour (W5-5).
        return getPersonalBaseline(userId);
    }

    public BaselineVector getPersonalBaseline(String userId) {
        if (baselineDataStore == null || userId == null) {
            return null;
        }
        return baselineDataStore.getUserBaseline(userId);
    }

    /**
     * The user's personal baseline within the request's tenant, or the one learned before the tenant key while it has
     * not moved (W5-10 D9).
     */
    public BaselineVector getPersonalBaseline(String userId, SecurityEvent event) {
        if (baselineDataStore == null || userId == null) {
            return null;
        }
        String key = personalKey(userId, event);
        BaselineVector baseline = baselineDataStore.getUserBaseline(key);
        return baseline != null || key.equals(userId) ? baseline : baselineDataStore.getUserBaseline(userId);
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
        return describeBaselineMaturity(personalBaseline, organizationBaseline);
    }

    /** The maturity of the user's baseline within the request's tenant (W5-10 D9). */
    public BaselineMaturitySnapshot describeBaselineMaturity(String userId, String organizationId, SecurityEvent event) {
        BaselineVector personalBaseline = getPersonalBaseline(userId, event);
        BaselineVector organizationBaseline = resolveOrganizationBaseline(userId, organizationId);
        return describeBaselineMaturity(personalBaseline, organizationBaseline);
    }

    private BaselineMaturitySnapshot describeBaselineMaturity(
            BaselineVector personalBaseline,
            BaselineVector organizationBaseline) {
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

    public PromptBaselineEvidence buildPromptBaselineEvidenceSnapshot(String userId, SecurityEvent currentEvent) {
        String organizationId = resolveOrganizationId(currentEvent, userId);
        BaselineVector personalBaseline = getPersonalBaseline(userId, currentEvent);
        BaselineVector organizationBaseline = resolveOrganizationBaseline(userId, organizationId);
        BaselineMaturitySnapshot maturity = describeBaselineMaturity(personalBaseline, organizationBaseline);
        return new PromptBaselineEvidence(
                maturity,
                personalBaseline,
                organizationBaseline,
                buildBaselineEvidenceSnapshot(userId, currentEvent, personalBaseline, maturity),
                buildSupportingBaselineEvidenceSnapshot(organizationBaseline, maturity));
    }

    public BaselineEvidenceSnapshot buildBaselineEvidenceSnapshot(String userId, SecurityEvent currentEvent) {
        BaselineVector personalBaseline = getPersonalBaseline(userId, currentEvent);
        BaselineMaturitySnapshot maturity = describeBaselineMaturity(
                personalBaseline,
                resolveOrganizationBaseline(userId, resolveOrganizationId(currentEvent, userId)));
        return buildBaselineEvidenceSnapshot(userId, currentEvent, personalBaseline, maturity);
    }

    private BaselineEvidenceSnapshot buildBaselineEvidenceSnapshot(
            String userId,
            SecurityEvent currentEvent,
            BaselineVector personalBaseline,
            BaselineMaturitySnapshot maturity) {
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
                networks(personalBaseline.getNormalIpRanges()),
                integers(personalBaseline.getNormalAccessHours()),
                integers(personalBaseline.getNormalAccessDays()),
                strings(firstNonEmpty(personalBaseline.getNormalBrowsers(), personalBaseline.getNormalUserAgents())),
                operatingSystems(personalBaseline.getNormalOperatingSystems()),
                pathFamilies(personalBaseline.getFrequentPaths()),
                strings(personalBaseline.getNormalAuthenticationTypes()),
                strings(personalBaseline.getFrequentActionFamilies()),
                semanticResourceFamilies(personalBaseline.getFrequentResourceFamilies()),
                buildBaselineEvidenceSummary(
                        maturity.personalBaselineEstablished(),
                        personalBaseline),
                BaselineEvidenceStatus.AVAILABLE,
                // W5-10 D4: a baseline not established says which conditions it misses.
                maturity.personalBaselineEstablished() ? ""
                        : String.join("; ", personalBaselineShortfalls(personalBaseline)),
                strings(personalBaseline.getNormalDevices()),
                personalBaseline.getElementFrequencies());
    }

    public BaselineEvidenceSnapshot buildSupportingBaselineEvidenceSnapshot(String userId) {
        return buildSupportingBaselineEvidenceSnapshot(userId, null);
    }

    public BaselineEvidenceSnapshot buildSupportingBaselineEvidenceSnapshot(String userId, String organizationId) {
        BaselineVector organizationBaseline = resolveOrganizationBaseline(userId, organizationId);
        BaselineMaturitySnapshot maturity = describeBaselineMaturity(
                getPersonalBaseline(userId),
                organizationBaseline);
        return buildSupportingBaselineEvidenceSnapshot(organizationBaseline, maturity);
    }

    private BaselineEvidenceSnapshot buildSupportingBaselineEvidenceSnapshot(
            BaselineVector organizationBaseline,
            BaselineMaturitySnapshot maturity) {
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

        // W5-10 D7: the organization's usual values are its frequent ones, read from its counts, which W5-5 keeps
        // as the sum of its members' learned requests; the union of its members' lists names every value seen once.
        Map<String, Long> frequencies = organizationBaseline.getElementFrequencies() != null
                ? organizationBaseline.getElementFrequencies() : Map.of();
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.SUPPORTING,
                maturity.organizationBaselineAvailable(),
                maturity.organizationBaselineEstablished(),
                organizationBaseline.getUpdateCount(),
                organizationBaseline.getAvgTrustScore(),
                organizationUsual(networks(organizationBaseline.getNormalIpRanges()), FREQ_PREFIX_IP, frequencies),
                organizationUsual(integers(organizationBaseline.getNormalAccessHours()), FREQ_PREFIX_HOUR, frequencies),
                organizationUsual(integers(organizationBaseline.getNormalAccessDays()), FREQ_PREFIX_DAY, frequencies),
                organizationUsual(strings(organizationBaseline.getNormalBrowsers()), FREQ_PREFIX_BROWSER, frequencies),
                organizationUsual(operatingSystems(organizationBaseline.getNormalOperatingSystems()), FREQ_PREFIX_OS,
                        frequencies),
                organizationUsual(pathFamilies(organizationBaseline.getFrequentPaths()), FREQ_PREFIX_PATH, frequencies),
                organizationUsual(strings(organizationBaseline.getNormalAuthenticationTypes()), FREQ_PREFIX_AUTH,
                        frequencies),
                organizationUsual(strings(organizationBaseline.getFrequentActionFamilies()), FREQ_PREFIX_ACTION,
                        frequencies),
                organizationUsual(semanticResourceFamilies(organizationBaseline.getFrequentResourceFamilies()),
                        FREQ_PREFIX_RESOURCE, frequencies),
                summary.toString(),
                BaselineEvidenceStatus.AVAILABLE,
                "",
                organizationUsual(strings(organizationBaseline.getNormalDevices()), FREQ_PREFIX_DEVICE, frequencies),
                frequencies);
    }

    /**
     * The values of one dimension that hold at least {@link #ORGANIZATION_USUAL_SHARE} of the organization's learned
     * values of that dimension; a value without a count is not known to be usual and is left out.
     */
    private static List<String> organizationUsual(List<String> values, String prefix, Map<String, Long> frequencies) {
        long total = 0L;
        for (Map.Entry<String, Long> frequency : frequencies.entrySet()) {
            if (frequency.getKey() != null && frequency.getKey().startsWith(prefix) && frequency.getValue() != null) {
                total += frequency.getValue();
            }
        }
        if (total <= 0L) {
            return List.of();
        }
        List<String> usual = new ArrayList<>();
        for (String value : values) {
            Long held = frequencies.get(prefix + value);
            if (held != null && held >= ORGANIZATION_USUAL_SHARE * total) {
                usual.add(value);
            }
        }
        return List.copyOf(usual);
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
        addSummaryPart(parts, "networks", networks(baseline.getNormalIpRanges()));
        List<String> devices = strings(baseline.getNormalDevices());
        if (!devices.isEmpty()) {
            addSummaryPart(parts, "devices", devices);
        }
        else {
            addSummaryPart(parts, "browsers", strings(firstNonEmpty(baseline.getNormalBrowsers(), baseline.getNormalUserAgents())));
        }
        addSummaryPart(parts, "paths", pathFamilies(baseline.getFrequentPaths()));
        addSummaryPart(parts, "auth", strings(baseline.getNormalAuthenticationTypes()));
        addSummaryPart(parts, "actions", strings(baseline.getFrequentActionFamilies()));
        addSummaryPart(parts, "resources", semanticResourceFamilies(baseline.getFrequentResourceFamilies()));
        return String.join(" | ", parts);
    }

    private static final int ORG_BASELINE_MAX_ARRAY_SIZE = 50;

    /**
     * Adds a member's learning to the organization baseline: the lists as a union, the frequencies by what this
     * learning added to the member's (W5-5), not the member's whole history again.
     */
    private void updateOrganizationBaseline(String userId, SecurityEvent currentEvent, BaselineVector previousBaseline,
                                            BaselineVector userBaseline) {
        String orgId = resolveOrganizationId(currentEvent, userId);
        if (orgId == null) {
            return;
        }
        // The organization's read, merge and write run under its own lock, after the user's is released (W5-8).
        underLock(ORGANIZATION_LOCK_PREFIX + orgId, () -> {
            mergeIntoOrganizationBaseline(userId, orgId, previousBaseline, userBaseline);
            return Boolean.TRUE;
        });
    }

    private void mergeIntoOrganizationBaseline(String userId, String orgId, BaselineVector previousBaseline,
                                               BaselineVector userBaseline) {
        try {
            double alpha = zeroTrustProperties.getBaseline().getLearning().getAlpha();
            BaselineDataStore.BaselineRead read = baselineDataStore.readOrganizationBaseline(orgId);
            if (read == null) {
                read = BaselineDataStore.BaselineRead.of(baselineDataStore.getOrganizationBaseline(orgId));
            }
            if (read.isFailed()) {
                log.error("[BaselineLearningService] Organization baseline could not be read, not updated: "
                        + "organizationId={}", orgId);
                return;
            }
            BaselineVector orgBaseline = read.baseline();

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
                        .normalDevices(userBaseline.getNormalDevices())
                        .normalIpBands(userBaseline.getNormalIpBands())
                        .normalAuthenticationTypes(userBaseline.getNormalAuthenticationTypes())
                        .frequentActionFamilies(userBaseline.getFrequentActionFamilies())
                        .frequentResourceFamilies(userBaseline.getFrequentResourceFamilies())
                        .elementFrequencies(learnedIncrements(previousBaseline, userBaseline))
                        .vocabularyVersion(VocabularyVersion.CURRENT)
                        .build();
                baselineDataStore.saveOrganizationBaseline(orgId, newOrg);
                return;
            }

            double newAvgTrust = orgBaseline.getAvgTrustScore() * (1 - alpha)
                    + userBaseline.getAvgTrustScore() * alpha;
            long newAvgRequest = (long) (orgBaseline.getAvgRequestCount() * (1 - alpha)
                    + userBaseline.getAvgRequestCount() * alpha);

            // W5-7: the organization's stored values are read into today's vocabulary with their counts, as a
            // member's are, before the member's learning is added; the baseline is then in today's vocabulary.
            Map<String, Long> orgFrequencies = orgBaseline.getElementFrequencies() != null
                    ? new HashMap<>(orgBaseline.getElementFrequencies()) : new HashMap<>();
            String orgVocabulary = orgBaseline.getVocabularyVersion();
            String[] orgIpRanges = canonicalized(orgBaseline.getNormalIpRanges(), FREQ_PREFIX_IP, orgFrequencies,
                    VocabularyMigration::network);
            String[] orgIpBands = canonicalized(orgBaseline.getNormalIpBands(), FREQ_PREFIX_IP_BAND, orgFrequencies,
                    VocabularyMigration::network);
            String[] orgOperatingSystems = canonicalized(orgBaseline.getNormalOperatingSystems(), FREQ_PREFIX_OS,
                    orgFrequencies, VocabularyMigration::operatingSystem);
            String[] orgAuthenticationTypes = canonicalized(orgBaseline.getNormalAuthenticationTypes(),
                    FREQ_PREFIX_AUTH, orgFrequencies, stored -> VocabularyMigration.authenticationType(stored, orgVocabulary));
            String[] orgActionFamilies = canonicalized(orgBaseline.getFrequentActionFamilies(), FREQ_PREFIX_ACTION,
                    orgFrequencies, VocabularyMigration::actionFamily);
            String[] orgResourceFamilies = canonicalized(orgBaseline.getFrequentResourceFamilies(),
                    FREQ_PREFIX_RESOURCE, orgFrequencies, VocabularyMigration::resourceClass);
            String[] orgPaths = canonicalized(orgBaseline.getFrequentPaths(), FREQ_PREFIX_PATH, orgFrequencies,
                    VocabularyMigration::pathFamily);
            BaselineVector updated = BaselineVector.builder()
                    .userId("org:" + orgId)
                    .avgTrustScore(newAvgTrust)
                    .avgRequestCount(newAvgRequest)
                    .updateCount(orgBaseline.getUpdateCount() + 1)
                    .lastUpdated(Instant.now())
                    .vocabularyVersion(VocabularyVersion.CURRENT)
                    .normalIpRanges(mergeStringArrays(orgIpRanges, userBaseline.getNormalIpRanges()))
                    .normalAccessHours(mergeIntegerArrays(
                            orgBaseline.getNormalAccessHours(), userBaseline.getNormalAccessHours()))
                    .normalAccessDays(mergeIntegerArrays(
                            orgBaseline.getNormalAccessDays(), userBaseline.getNormalAccessDays()))
                    .frequentPaths(mergeStringArrays(orgPaths, userBaseline.getFrequentPaths()))
                    .normalUserAgents(mergeStringArrays(
                            orgBaseline.getNormalUserAgents(), userBaseline.getNormalUserAgents()))
                    .normalOperatingSystems(mergeStringArrays(orgOperatingSystems,
                            userBaseline.getNormalOperatingSystems()))
                    .normalBrowsers(mergeStringArrays(
                            orgBaseline.getNormalBrowsers(), userBaseline.getNormalBrowsers()))
                    .normalDevices(mergeStringArrays(
                            orgBaseline.getNormalDevices(), userBaseline.getNormalDevices()))
                    .normalIpBands(mergeStringArrays(orgIpBands, userBaseline.getNormalIpBands()))
                    .normalAuthenticationTypes(mergeStringArrays(orgAuthenticationTypes,
                            userBaseline.getNormalAuthenticationTypes()))
                    .frequentActionFamilies(mergeStringArrays(orgActionFamilies,
                            userBaseline.getFrequentActionFamilies()))
                    .frequentResourceFamilies(mergeStringArrays(orgResourceFamilies,
                            userBaseline.getFrequentResourceFamilies()))
                    .elementFrequencies(mergeFrequencies(orgFrequencies,
                            learnedIncrements(previousBaseline, userBaseline)))
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

    /** What a learning added to the member's frequencies: each count less the previous one, where it grew. */
    private static Map<String, Long> learnedIncrements(BaselineVector previous, BaselineVector learned) {
        Map<String, Long> increments = new HashMap<>();
        if (learned == null || learned.getElementFrequencies() == null) {
            return increments;
        }
        Map<String, Long> before = previous != null && previous.getElementFrequencies() != null
                ? previous.getElementFrequencies() : Map.of();
        learned.getElementFrequencies().forEach((key, count) -> {
            Long previousCount = before.get(key);
            long added = (count != null ? count : 0L) - (previousCount != null ? previousCount : 0L);
            if (key != null && added > 0) {
                increments.put(key, added);
            }
        });
        return increments;
    }

    /** A personal baseline is established when it misses none of the conditions (W5-10 D4). */
    private boolean isPersonalBaselineEstablished(BaselineVector baseline) {
        return baseline != null && personalBaselineShortfalls(baseline).isEmpty();
    }

    /**
     * The conditions of an established personal baseline a stored baseline misses, as the BaselineStatus line states
     * them (W5-10 D4): enough learned requests, learned on enough company dates, and its recent learnings no longer
     * bringing values it had not seen. A baseline stored before its dates were kept is not known to be established.
     */
    private List<String> personalBaselineShortfalls(BaselineVector baseline) {
        List<String> shortfalls = new ArrayList<>();
        long learned = value(baseline.getUpdateCount());
        if (learned < minimumSampleCount()) {
            shortfalls.add(learned + " of " + minimumSampleCount() + " learned requests");
        }
        if (baseline.getLearnedDates() == null || baseline.getRecentNovelty() == null) {
            shortfalls.add("learned dates and new values not recorded (stored before they were kept)");
            return shortfalls;
        }
        SecurityZeroTrustProperties.BaselineSettings.StatisticalSettings statistical =
                zeroTrustProperties.getBaseline().getStatistical();
        long dates = Arrays.stream(baseline.getLearnedDates()).filter(StringUtils::hasText).distinct().count();
        int minDays = Math.max(1, statistical.getMinDays());
        if (dates < minDays) {
            shortfalls.add("learned on " + dates + " of " + minDays + " dates");
        }
        int window = convergenceWindow();
        String novelty = baseline.getRecentNovelty();
        String recent = novelty.length() > window ? novelty.substring(novelty.length() - window) : novelty;
        long recentNew = recent.chars().filter(flag -> flag == '1').count();
        int allowed = (int) Math.floor(statistical.getMaxNewValueRatio() * window);
        if (recent.length() < window) {
            shortfalls.add("only " + recent.length() + " learnings to check that new values stopped (" + window
                    + " needed)");
        }
        else if (recentNew > allowed) {
            shortfalls.add(recentNew + " of the last " + window + " learnings brought new values (at most " + allowed
                    + ")");
        }
        return shortfalls;
    }

    private int convergenceWindow() {
        return Math.max(1, zeroTrustProperties.getBaseline().getStatistical().getConvergenceWindow());
    }

    /** The recent learned company dates with this one last, each once. */
    private static String[] learnedDates(String[] stored, String date) {
        List<String> dates = new ArrayList<>(stored != null ? Arrays.asList(stored) : List.of());
        if (date != null) {
            dates.remove(date);
            dates.add(date);
        }
        return dates.subList(Math.max(0, dates.size() - RECENT_LEARNED_DATES), dates.size()).toArray(String[]::new);
    }

    /** The recent learnings' novelty with this one last, kept to the convergence window. */
    private String recentNovelty(String stored, boolean novel) {
        String novelty = (stored != null ? stored : "") + (novel ? '1' : '0');
        int window = convergenceWindow();
        return novelty.length() > window ? novelty.substring(novelty.length() - window) : novelty;
    }

    /** Whether a value of the request is one the stored values do not hold. */
    private static boolean isNew(Object[] stored, Object value) {
        return value != null && (stored == null || !Arrays.asList(stored).contains(value));
    }

    private boolean isOrganizationBaselineEstablished(BaselineVector baseline) {
        if (baseline == null) {
            return false;
        }
        return value(baseline.getUpdateCount()) >= minimumSampleCount();
    }

    private int minimumSampleCount() {
        int configured = zeroTrustProperties.getBaseline().getStatistical().getMinSamples();
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
                sb.append(String.format("  Hour: %d\n", currentEvent.getLocalTimestamp().getHour()));
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

    /** The request's action family as the context gives it, so the baseline learns the same family it is compared with. */
    private String extractActionFamily(SecurityEvent event) {
        ActionFamilyResolver.Resolution action = ActionFamilyResolver.resolve(event != null ? event.getMetadata() : null);
        return action.family() == ActionFamily.UNKNOWN ? null : action.family().name();
    }

    private String extractResourceFamily(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        if (metadata == null) {
            return null;
        }
        // Every classification value goes to the same normalizer as the current request and the past records. A family
        // hint names a business category and is not one of them (W2-10).
        return SecuritySemanticNormalizer.normalizeResourceClass(
                metadata.get("resourceSensitivity"),
                metadata.get("sensitivity"),
                metadata.get("resourceType"));
    }

    /** The path family the context gives the request: the host's URL template first, else the generalized path. */
    private String extractPathFamily(SecurityEvent event) {
        return SecuritySemanticNormalizer.pathFamilyOf(event != null ? event.getMetadata() : null, extractPath(event));
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

    /** Stored path families read under today's rule: one stored from a request path reads with its identifiers generalized. */
    private List<String> pathFamilies(String[] stored) {
        if (stored == null || stored.length == 0) {
            return List.of();
        }
        return Arrays.stream(stored)
                .map(SecuritySemanticNormalizer::normalizePathFamily)
                .filter(StringUtils::hasText)
                .distinct()
                .sorted()
                .toList();
    }

    /** Stored values in ascending order, so the same baseline reads the same way on every run (E-1). */
    private List<String> strings(String[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(StringUtils::hasText)
                .distinct()
                .sorted()
                .toList();
    }

    /** The stored networks in today's form: a three-octet prefix learned before W2-4 reads as its /24 band. */
    private List<String> networks(String[] values) {
        return strings(values == null ? null : Arrays.stream(values)
                .map(value -> SecuritySemanticNormalizer.normalizeNetwork(null, value))
                .toArray(String[]::new));
    }

    /** The stored systems in one vocabulary: "Windows" learned before W2-4 reads as WINDOWS. */
    private List<String> operatingSystems(String[] values) {
        return strings(values == null ? null : Arrays.stream(values)
                .map(SecuritySemanticNormalizer::normalizeOperatingSystem)
                .toArray(String[]::new));
    }

    private List<String> semanticResourceFamilies(String[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(value -> StringUtils.hasText(value) && !value.contains("/"))
                .map(SecuritySemanticNormalizer::normalizeResourceClass)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    /** Stored values in ascending order: the arrays keep insertion order, which differs between runs (E-1). */
    private List<String> integers(Integer[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .map(String::valueOf)
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

    public record PromptBaselineEvidence(
            BaselineMaturitySnapshot maturity,
            BaselineVector personalBaseline,
            BaselineVector organizationBaseline,
            BaselineEvidenceSnapshot personal,
            BaselineEvidenceSnapshot supporting) {
    }
}
