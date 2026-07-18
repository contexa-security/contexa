package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class OfficialVerificationLongHorizonEvidenceValues {

    Map<String, Object> firstMetadata(
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            String type
    ) {
        return events.stream()
                .filter(item -> type.equalsIgnoreCase(item.type()))
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .filter(item -> item != null && !item.isEmpty())
                .findFirst()
                .map(LinkedHashMap::new)
                .orElseGet(LinkedHashMap::new);
    }

    Map<String, Object> firstPresent(Map<String, Object>... sources) {
        for (Map<String, Object> source : sources) {
            if (source != null && !source.isEmpty()) {
                return source;
            }
        }
        return Map.of();
    }

    Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            raw.forEach((key, item) -> {
                if (key != null && item != null) {
                    normalized.put(String.valueOf(key), item);
                }
            });
            return Map.copyOf(normalized);
        }
        return Map.of();
    }

    int integer(Map<String, Object> source, String... keys) {
        if (source == null) {
            return 0;
        }
        for (String key : keys) {
            Object candidate = source.get(key);
            if (candidate instanceof Number number) {
                return number.intValue();
            }
            if (candidate instanceof String textValue) {
                try {
                    return Integer.parseInt(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    long longValue(Map<String, Object> source, String... keys) {
        if (source == null) {
            return -1L;
        }
        for (String key : keys) {
            Object candidate = source.get(key);
            if (candidate instanceof Number number) {
                return number.longValue();
            }
            if (candidate instanceof String textValue) {
                try {
                    return Long.parseLong(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return -1L;
    }

    boolean containsValue(Map<String, Object> source, String... keys) {
        if (source == null) {
            return false;
        }
        for (String key : keys) {
            if (source.containsKey(key) && source.get(key) != null) {
                return true;
            }
        }
        return false;
    }

    boolean booleanValue(Object value) {
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        return value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    String text(Map<String, Object> source, String... keys) {
        if (source == null) {
            return null;
        }
        for (String key : keys) {
            Object candidate = source.get(key);
            if (candidate == null) {
                continue;
            }
            String normalized = String.valueOf(candidate).trim();
            if (!normalized.isBlank()) {
                return normalized;
            }
        }
        return null;
    }

    String value(String input) {
        return StringUtils.hasText(input) ? input : "n/a";
    }

    boolean sameValue(String left, String right) {
        return StringUtils.hasText(left) && left.equals(right);
    }
}