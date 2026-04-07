package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.WorkProfile;
import org.springframework.util.StringUtils;

import java.util.*;

import static io.contexa.contexacore.autonomous.context.support.MetadataValueResolver.*;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves WorkProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class WorkProfileResolver extends AbstractProfileResolver<WorkProfile> {

    @Override
    protected WorkProfile doResolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        List<String> frequentProtectableResources = strings(
                metadata.get("topFrequentProtectableResources"),
                metadata.get("frequentProtectableResources"),
                metadata.get("baselineFrequentPaths"));
        if (frequentProtectableResources.isEmpty() && context.getObservedScope() != null) {
            frequentProtectableResources = copyList(context.getObservedScope().getFrequentResources());
        }

        List<String> frequentActionFamilies = strings(
                metadata.get("frequentActionFamilies"),
                metadata.get("normalActionFamilies"),
                metadata.get("baselineActionFamilies"));
        if (frequentActionFamilies.isEmpty() && context.getObservedScope() != null) {
            frequentActionFamilies = copyList(context.getObservedScope().getFrequentActionFamilies());
        }

        List<Integer> normalAccessHours = toIntList(
                metadata.get("normalAccessHours"),
                metadata.get("baselineAccessHours"));
        List<Integer> normalAccessDays = toIntList(
                metadata.get("normalAccessDays"),
                metadata.get("baselineAccessDays"));
        Double normalRequestRate = toDouble(metadata.get("normalRequestRate"), metadata.get("baselineAvgRequestRate"));
        Integer normalSessionLengthMinutes = toInt(metadata.get("normalSessionLengthMinutes"), metadata.get("baselineSessionLengthMinutes"));
        Double protectableInvocationDensity = toDouble(metadata.get("protectableInvocationDensity"));
        List<String> protectableResourceHeatmap = buildProtectableResourceHeatmap(metadata, context, frequentProtectableResources);

        if (protectableInvocationDensity == null
                && context.getObservedScope() != null
                && context.getObservedScope().getRecentProtectableAccessCount() != null
                && context.getSession() != null
                && context.getSession().getRecentRequestCount() != null
                && context.getSession().getRecentRequestCount() > 0) {
            protectableInvocationDensity = context.getObservedScope().getRecentProtectableAccessCount().doubleValue()
                    / context.getSession().getRecentRequestCount().doubleValue();
        }

        WorkProfile profile = WorkProfile.builder()
                .summary(text(metadata.get("workProfileSummary"), buildWorkProfileSummary(frequentProtectableResources, frequentActionFamilies, protectableInvocationDensity)))
                .frequentProtectableResources(frequentProtectableResources)
                .frequentActionFamilies(frequentActionFamilies)
                .frequentSensitiveResourceCategories(strings(
                        metadata.get("frequentSensitiveResourceCategories"),
                        metadata.get("sensitiveResourceCategories"),
                        metadata.get("normalSensitiveResourceCategories")))
                .protectableResourceHeatmap(protectableResourceHeatmap)
                .normalAccessHours(normalAccessHours)
                .normalAccessDays(normalAccessDays)
                .normalRequestRate(normalRequestRate)
                .normalSessionLengthMinutes(normalSessionLengthMinutes)
                .normalReadWriteExportRatio(text(
                        metadata.get("normalReadWriteExportRatio"),
                        metadata.get("readWriteExportRatio")))
                .normalPrivilegedActionFrequency(toDouble(
                        metadata.get("normalPrivilegedActionFrequency"),
                        metadata.get("privilegedActionFrequency")))
                .protectableInvocationDensity(protectableInvocationDensity)
                .seasonalBusinessProfile(text(metadata.get("seasonalBusinessProfile"), metadata.get("seasonal_business_profile")))
                .longTailLegitimateTasks(strings(metadata.get("longTailLegitimateTasks"), metadata.get("long_tail_legitimate_tasks")))
                .build();

        return profile;
    }

    @Override
    protected boolean doHasData(WorkProfile profile) {
        return StringUtils.hasText(profile.getSummary())
                || !profile.getFrequentProtectableResources().isEmpty()
                || !profile.getFrequentActionFamilies().isEmpty()
                || !profile.getFrequentSensitiveResourceCategories().isEmpty()
                || !profile.getNormalAccessHours().isEmpty()
                || !profile.getNormalAccessDays().isEmpty()
                || profile.getNormalRequestRate() != null
                || profile.getNormalSessionLengthMinutes() != null
                || profile.getNormalReadWriteExportRatio() != null
                || profile.getNormalPrivilegedActionFrequency() != null
                || profile.getProtectableInvocationDensity() != null
                || !profile.getProtectableResourceHeatmap().isEmpty()
                || StringUtils.hasText(profile.getSeasonalBusinessProfile())
                || !profile.getLongTailLegitimateTasks().isEmpty();
    }

    @Override
    protected String doBuildSummary(WorkProfile profile, CanonicalSecurityContext context) {
        return buildWorkProfileSummary(
                profile.getFrequentProtectableResources(),
                profile.getFrequentActionFamilies(),
                profile.getProtectableInvocationDensity());
    }

    @Override
    public void apply(WorkProfile profile, CanonicalSecurityContext context) {
        context.setWorkProfile(profile);
    }

    // --- Helper methods (moved from DefaultCanonicalSecurityContextProvider) ---

    private String buildWorkProfileSummary(List<String> frequentResources, List<String> frequentActionFamilies, Double protectableInvocationDensity) {
        List<String> facts = new ArrayList<>();
        if (!frequentResources.isEmpty()) {
            facts.add("Frequent protectable resources: " + String.join(", ", frequentResources));
        }
        if (!frequentActionFamilies.isEmpty()) {
            facts.add("Frequent action families: " + String.join(", ", frequentActionFamilies));
        }
        if (protectableInvocationDensity != null) {
            facts.add(String.format(Locale.ROOT, "Protectable invocation density: %.2f", protectableInvocationDensity));
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private List<String> buildProtectableResourceHeatmap(
            Map<String, Object> metadata,
            CanonicalSecurityContext context,
            List<String> frequentProtectableResources) {
        List<String> explicitHeatmap = strings(
                metadata.get("protectableResourceHeatmap"),
                metadata.get("protectable_heatmap"),
                metadata.get("protectableResourceCounts"));
        if (!explicitHeatmap.isEmpty()) {
            return explicitHeatmap;
        }

        Object history = metadata.get("protectableAccessHistory");
        if (history instanceof Collection<?> collection && !collection.isEmpty()) {
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (Object item : collection) {
                if (!(item instanceof Map<?, ?> entry)) {
                    continue;
                }
                String resourceId = text(entry.get("resourceId"), entry.get("requestPath"), entry.get("path"));
                if (!StringUtils.hasText(resourceId)) {
                    continue;
                }
                counts.merge(resourceId, 1, Integer::sum);
            }
            if (!counts.isEmpty()) {
                return counts.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                                .thenComparing(Map.Entry.comparingByKey()))
                        .limit(6)
                        .map(entry -> entry.getKey() + "=" + entry.getValue())
                        .toList();
            }
        }

        if (frequentProtectableResources != null && !frequentProtectableResources.isEmpty()) {
            return frequentProtectableResources.stream()
                    .limit(6)
                    .map(item -> item + "=OBSERVED")
                    .toList();
        }

        if (context != null && context.getObservedScope() != null && !context.getObservedScope().getFrequentResources().isEmpty()) {
            return context.getObservedScope().getFrequentResources().stream()
                    .limit(6)
                    .map(item -> item + "=OBSERVED")
                    .toList();
        }
        return List.of();
    }

    private List<String> copyList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(values);
    }
}
