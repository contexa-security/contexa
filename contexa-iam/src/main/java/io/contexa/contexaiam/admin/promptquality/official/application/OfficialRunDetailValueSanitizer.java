package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class OfficialRunDetailValueSanitizer {

    private static final int TECHNICAL_MAP_ENTRY_LIMIT = 40;
    private static final int TECHNICAL_LIST_ENTRY_LIMIT = 20;
    private static final int TECHNICAL_STRING_LIMIT = 2000;
    private static final int DETAIL_FACT_MAP_ENTRY_LIMIT = 16;
    private static final int DETAIL_FACT_STRING_LIMIT = 320;
    private static final int DETAIL_CHECK_STRING_LIMIT = 640;

    private OfficialRunDetailValueSanitizer() {
    }

    static String detailCheckText(String value) {
        return truncate(value, DETAIL_CHECK_STRING_LIMIT);
    }

    static Map<String, String> detailStringMap(Map<String, String> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new LinkedHashMap<>();
        int count = 0;
        for (Map.Entry<String, String> entry : source.entrySet()) {
            if (count++ >= DETAIL_FACT_MAP_ENTRY_LIMIT) {
                result.put("_truncated", "true");
                break;
            }
            result.put(entry.getKey(), truncate(entry.getValue(), DETAIL_FACT_STRING_LIMIT));
        }
        return result;
    }

    static Map<String, Object> limitedObjectMap(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        return limitedObjectMap(source, 0);
    }

    private static Map<String, Object> limitedObjectMap(Map<?, ?> source, int depth) {
        Map<String, Object> result = new LinkedHashMap<>();
        int count = 0;
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (count++ >= TECHNICAL_MAP_ENTRY_LIMIT) {
                result.put("_truncated", true);
                break;
            }
            result.put(String.valueOf(entry.getKey()), limitedTechnicalValue(entry.getValue(), depth + 1));
        }
        return result;
    }

    private static Object limitedTechnicalValue(Object value, int depth) {
        if (value == null || value instanceof Number || value instanceof Boolean) {
            return value;
        }
        if (value instanceof CharSequence sequence) {
            return truncate(sequence.toString(), TECHNICAL_STRING_LIMIT);
        }
        if (depth >= 2) {
            return truncate(String.valueOf(value), TECHNICAL_STRING_LIMIT);
        }
        if (value instanceof Map<?, ?> map) {
            return limitedObjectMap(map, depth);
        }
        if (value instanceof List<?> list) {
            List<Object> result = new ArrayList<>();
            int count = 0;
            for (Object item : list) {
                if (count++ >= TECHNICAL_LIST_ENTRY_LIMIT) {
                    result.add("[truncated " + (list.size() - TECHNICAL_LIST_ENTRY_LIMIT) + " items]");
                    break;
                }
                result.add(limitedTechnicalValue(item, depth + 1));
            }
            return result;
        }
        return truncate(String.valueOf(value), TECHNICAL_STRING_LIMIT);
    }

    private static String truncate(String value, int limit) {
        if (value == null || value.length() <= limit) {
            return value;
        }
        return value.substring(0, limit) + "...[truncated " + (value.length() - limit) + " chars]";
    }
}