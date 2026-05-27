package io.contexa.contexacore.autonomous.context.prompt;

public record PromptSlot(
        String slotKey,
        String section,
        String label,
        Object sourceValue,
        String renderedValue,
        String narrative,
        String priority) {

    public static final String UNSCOPED_SECTION = "UNSCOPED";
    public static final String DEFAULT_PRIORITY = "STANDARD";

    public static PromptSlot line(String label, Object sourceValue, String renderedValue) {
        return new PromptSlot(
                null,
                UNSCOPED_SECTION,
                label,
                sourceValue,
                renderedValue,
                null,
                DEFAULT_PRIORITY);
    }
}
