package io.contexa.contexacore.autonomous.context.prompt;

import org.springframework.util.StringUtils;

import java.util.List;

public class PromptSlotRenderer {

    public String render(List<PromptSlot> slots) {
        if (slots == null || slots.isEmpty()) {
            return "";
        }
        StringBuilder rendered = new StringBuilder();
        for (PromptSlot slot : slots) {
            rendered.append(renderLine(slot));
        }
        return rendered.toString();
    }

    public String renderLine(PromptSlot slot) {
        if (slot == null || !StringUtils.hasText(slot.label()) || !StringUtils.hasText(slot.renderedValue())) {
            return "";
        }
        return slot.label() + ": " + slot.renderedValue() + "\n";
    }
}
