package io.contexa.contexacore.std.security;

import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MemoryQuarantineService {

    private final MemoryReadPolicy memoryReadPolicy;

    public MemoryQuarantineService(MemoryReadPolicy memoryReadPolicy) {
        this.memoryReadPolicy = memoryReadPolicy != null ? memoryReadPolicy : new MemoryReadPolicy();
    }

    public MemoryQuarantineDecision evaluate(Document document) {
        MemoryReadDecision memoryReadDecision = memoryReadPolicy.evaluate(document);
        Map<String, Object> metadata = document != null && document.getMetadata() != null ? document.getMetadata() : Map.of();
        boolean poisoned = resolvePoisoned(metadata);
        List<String> facts = new ArrayList<>();
        facts.add("Memory read decision=" + memoryReadDecision.decision() + ".");
        if (poisoned) {
            facts.add("Poisoned knowledge metadata is present.");
            return new MemoryQuarantineDecision(false, "DENIED_POISONED_KNOWLEDGE", "QUARANTINED", true, List.copyOf(facts));
        }
        if (!memoryReadDecision.allowed()) {
            String quarantineState = "DENIED_MEMORY_QUARANTINED".equals(memoryReadDecision.decision()) ? "QUARANTINED" : "REVIEW_REQUIRED";
            facts.add("Memory artifact is not runtime approved.");
            return new MemoryQuarantineDecision(false, memoryReadDecision.decision(), quarantineState, false, List.copyOf(facts));
        }
        facts.add("Memory artifact is runtime safe.");
        return new MemoryQuarantineDecision(true, memoryReadDecision.decision(), "ACTIVE", false, List.copyOf(facts));
    }

    private boolean resolvePoisoned(Map<String, Object> metadata) {
        Object explicit = metadata.get("knowledgePoisoned");
        if (explicit instanceof Boolean value) {
            return value;
        }
        String state = normalize(text(metadata, "poisonedKnowledgeState", "knowledgePoisonedState", "knowledgeSafetyStatus"));
        return "POISONED".equals(state) || "QUARANTINED".equals(state) || "BLOCKED".equals(state);
    }

    private String text(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString();
            }
        }
        return null;
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : null;
    }

    public record MemoryQuarantineDecision(
            boolean allowed,
            String decision,
            String quarantineState,
            boolean poisoned,
            List<String> facts) {

        public MemoryQuarantineDecision {
            facts = facts == null ? List.of() : List.copyOf(facts);
        }
    }
}