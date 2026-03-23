package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.domain.entity.BaselineSignalOutboxRecord;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.BaselineSignalOutboxRepository;

import java.time.Clock;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.temporal.TemporalAdjusters;
import java.util.*;

public class BaselineSignalAggregationService {

    private static final String FREQ_PREFIX_HOUR = "hour:";
    private static final String FREQ_PREFIX_DAY = "day:";
    private static final String FREQ_PREFIX_OS = "os:";

    private final BaselineDataStore baselineDataStore;
    private final BaselineSignalOutboxRepository baselineSignalOutboxRepository;
    private final SaasForwardingProperties properties;
    private final Clock clock;

    public BaselineSignalAggregationService(
            BaselineDataStore baselineDataStore,
            BaselineSignalOutboxRepository baselineSignalOutboxRepository,
            SaasForwardingProperties properties) {
        this(
                baselineDataStore,
                baselineSignalOutboxRepository,
                properties,
                Clock.systemDefaultZone());
    }

    BaselineSignalAggregationService(
            BaselineDataStore baselineDataStore,
            BaselineSignalOutboxRepository baselineSignalOutboxRepository,
            SaasForwardingProperties properties,
            Clock clock) {
        this.baselineDataStore = baselineDataStore;
        this.baselineSignalOutboxRepository = baselineSignalOutboxRepository;
        this.properties = properties;
        this.clock = clock;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getBaselineSignal() != null
                && properties.getBaselineSignal().isEnabled();
    }

    public BaselineSignalOutboxRecord captureCurrentPeriod() {
        if (!isEnabled()) {
            return null;
        }
        List<BaselineVector> organizationBaselines = collectOrganizationBaselines();
        long userBaselineCount = baselineDataStore.countUserBaselines();
        if (organizationBaselines.size() < properties.getBaselineSignal().getMinimumOrganizationBaselineCount()
                || userBaselineCount < properties.getBaselineSignal().getMinimumUserBaselineCount()) {
            return null;
        }

        LocalDate periodStart = currentPeriodStart();
        BaselineSignalOutboxRecord record = baselineSignalOutboxRepository.findByPeriodStart(periodStart)
                .orElseGet(() -> baselineSignalOutboxRepository.save(BaselineSignalOutboxRecord.initialize(periodStart)));

        Map<String, Long> hourDistribution = aggregateIntegerDistribution(
                organizationBaselines,
                FREQ_PREFIX_HOUR,
                BaselineVector::getNormalAccessHours,
                properties.getBaselineSignal().getHourBucketLimit());
        Map<String, Long> dayDistribution = aggregateIntegerDistribution(
                organizationBaselines,
                FREQ_PREFIX_DAY,
                BaselineVector::getNormalAccessDays,
                properties.getBaselineSignal().getDayBucketLimit());
        Map<String, Long> operatingSystemDistribution = aggregateStringDistribution(
                organizationBaselines,
                FREQ_PREFIX_OS,
                BaselineVector::getNormalOperatingSystems,
                properties.getBaselineSignal().getOperatingSystemLimit());

        record.setSignalId(periodStart.toString());
        record.updateSnapshot(
                properties.getBaselineSignal().getIndustryCategory(),
                organizationBaselines.size(),
                userBaselineCount,
                hourDistribution,
                dayDistribution,
                operatingSystemDistribution,
                java.time.LocalDateTime.now(clock));
        return baselineSignalOutboxRepository.save(record);
    }

    LocalDate currentPeriodStart() {
        return LocalDate.now(clock).with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
    }

    private List<BaselineVector> collectOrganizationBaselines() {
        List<BaselineVector> baselines = new ArrayList<>();
        for (BaselineVector baseline : baselineDataStore.listOrganizationBaselines()) {
            if (baseline == null) {
                continue;
            }
            long updateCount = baseline.getUpdateCount() != null ? baseline.getUpdateCount() : 0L;
            if (updateCount <= 0L) {
                continue;
            }
            baselines.add(baseline);
        }
        return baselines;
    }

    private Map<String, Long> aggregateIntegerDistribution(
            List<BaselineVector> baselines,
            String prefix,
            java.util.function.Function<BaselineVector, Integer[]> fallbackExtractor,
            int limit) {
        LinkedHashMap<String, Long> aggregated = new LinkedHashMap<>();
        for (BaselineVector baseline : baselines) {
            Map<String, Long> frequencies = baseline.getElementFrequencies() != null
                    ? baseline.getElementFrequencies()
                    : Map.of();
            boolean contributed = false;
            for (Map.Entry<String, Long> entry : frequencies.entrySet()) {
                if (!entry.getKey().startsWith(prefix) || entry.getValue() == null || entry.getValue() <= 0L) {
                    continue;
                }
                String value = entry.getKey().substring(prefix.length());
                aggregated.merge(value, entry.getValue(), Long::sum);
                contributed = true;
            }
            if (!contributed) {
                Integer[] fallback = fallbackExtractor.apply(baseline);
                if (fallback == null) {
                    continue;
                }
                for (Integer value : fallback) {
                    if (value != null) {
                        aggregated.merge(String.valueOf(value), 1L, Long::sum);
                    }
                }
            }
        }
        return limitDistribution(aggregated, limit);
    }

    private Map<String, Long> aggregateStringDistribution(
            List<BaselineVector> baselines,
            String prefix,
            java.util.function.Function<BaselineVector, String[]> fallbackExtractor,
            int limit) {
        LinkedHashMap<String, Long> aggregated = new LinkedHashMap<>();
        for (BaselineVector baseline : baselines) {
            Map<String, Long> frequencies = baseline.getElementFrequencies() != null
                    ? baseline.getElementFrequencies()
                    : Map.of();
            boolean contributed = false;
            for (Map.Entry<String, Long> entry : frequencies.entrySet()) {
                if (!entry.getKey().startsWith(prefix) || entry.getValue() == null || entry.getValue() <= 0L) {
                    continue;
                }
                String value = entry.getKey().substring(prefix.length());
                aggregated.merge(value, entry.getValue(), Long::sum);
                contributed = true;
            }
            if (!contributed) {
                String[] fallback = fallbackExtractor.apply(baseline);
                if (fallback == null) {
                    continue;
                }
                for (String value : fallback) {
                    if (value != null && !value.isBlank()) {
                        aggregated.merge(value.trim(), 1L, Long::sum);
                    }
                }
            }
        }
        return limitDistribution(aggregated, limit);
    }

    private Map<String, Long> limitDistribution(Map<String, Long> distribution, int limit) {
        return distribution.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(Math.max(1, limit))
                .collect(
                        LinkedHashMap::new,
                        (target, entry) -> target.put(entry.getKey(), entry.getValue()),
                        LinkedHashMap::putAll);
    }

}
