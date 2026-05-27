package io.contexa.contexacore.autonomous.context.prompt;

public record PromptSlotPlan(
        String slotKey,
        String sectionKey,
        String labelKey,
        String canonicalContextPath,
        String sourceProducer,
        String priority,
        String truncationPolicy) {

    public static PromptSlotPlan unscoped(String sectionKey, String labelKey) {
        return new PromptSlotPlan(
                null,
                sectionKey == null || sectionKey.isBlank() ? PromptSlot.UNSCOPED_SECTION : sectionKey.trim(),
                labelKey == null ? "" : labelKey.trim(),
                null,
                null,
                PromptSlot.DEFAULT_PRIORITY,
                null);
    }

    public PromptSlot bind(Object sourceValue, String renderedValue, String narrative) {
        return new PromptSlot(
                slotKey,
                sectionKey,
                labelKey,
                sourceValue,
                renderedValue,
                narrative,
                priority);
    }
}
