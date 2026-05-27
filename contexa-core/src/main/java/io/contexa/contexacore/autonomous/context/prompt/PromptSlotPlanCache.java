package io.contexa.contexacore.autonomous.context.prompt;

import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class PromptSlotPlanCache implements PromptSlotPlanProvider {

    private final Map<String, PromptSlotPlan> plans = new ConcurrentHashMap<>();
    private final PromptSlotPlanProvider delegate;

    public PromptSlotPlanCache() {
        this(PromptSlotPlanProvider.unscoped());
    }

    public PromptSlotPlanCache(PromptSlotPlanProvider delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    }

    @Override
    public PromptSlotPlan planFor(String sectionKey, String labelKey) {
        String normalizedSection = StringUtils.hasText(sectionKey) ? sectionKey.trim() : "";
        String normalizedLabel = StringUtils.hasText(labelKey) ? labelKey.trim() : "";
        if (!StringUtils.hasText(normalizedLabel)) {
            return PromptSlotPlan.unscoped(normalizedSection, normalizedLabel);
        }
        String providerScope = StringUtils.hasText(delegate.cacheScopeKey())
                ? delegate.cacheScopeKey().trim()
                : "UNSCOPED";
        String cacheKey = providerScope + "\u001F" + normalizedSection + "\u001F" + normalizedLabel;
        return plans.computeIfAbsent(cacheKey, ignored -> delegate.planFor(normalizedSection, normalizedLabel));
    }

    public PromptSlotPlan planForLabel(String label) {
        return planFor(null, label);
    }

    public int cachedPlanCount() {
        return plans.size();
    }
}
