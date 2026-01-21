package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityResponse {

    private Double riskScore;

    private Double confidence;

    private String confidenceReasoning;

    private String action;

    private String reasoning;

    private String mitre;

    public static SecurityResponse fromJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }

        SecurityResponse response = new SecurityResponse();

        try {
            
            Double riskScore = extractDouble(json, "\"r\"");
            if (riskScore == null) {
                riskScore = extractDouble(json, "\"riskScore\"");
            }
            response.setRiskScore(riskScore);

            Double confidence = extractDouble(json, "\"c\"");
            if (confidence == null) {
                confidence = extractDouble(json, "\"confidence\"");
            }
            response.setConfidence(confidence);

            String action = extractString(json, "\"a\"");
            if (action != null) {
                action = expandAction(action);
            } else {
                action = extractString(json, "\"action\"");
            }
            response.setAction(action);

            String reasoning = extractString(json, "\"d\"");
            if (reasoning == null) {
                reasoning = extractString(json, "\"reasoning\"");
            }
            if (reasoning == null) {
                reasoning = extractString(json, "\"reason\"");
            }
            response.setReasoning(reasoning);

            String mitre = extractString(json, "\"m\"");
            if (mitre == null) {
                mitre = extractString(json, "\"mitre\"");
            }
            response.setMitre(mitre);

            String confReasoning = extractString(json, "\"confidenceReasoning\"");
            response.setConfidenceReasoning(confReasoning);

        } catch (Exception e) {
            
            return null;
        }

        return response;
    }

    @Deprecated
    public static SecurityResponse fromCompactJson(String json) {
        return fromJson(json);
    }

    private static String expandAction(String shortAction) {
        if (shortAction == null) return null;

        return switch (shortAction.toUpperCase().trim()) {
            case "A", "ALLOW" -> "ALLOW";
            case "B", "BLOCK" -> "BLOCK";
            case "C", "CHALLENGE" -> "CHALLENGE";
            case "E", "ESCALATE" -> "ESCALATE";
            default -> shortAction;
        };
    }

    private static Double extractDouble(String json, String key) {
        int keyIndex = json.indexOf(key);
        if (keyIndex == -1) return null;

        int colonIndex = json.indexOf(':', keyIndex);
        if (colonIndex == -1) return null;

        int endIndex = findValueEnd(json, colonIndex + 1);
        String valueStr = json.substring(colonIndex + 1, endIndex).trim();

        try {
            return Double.parseDouble(valueStr);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String extractString(String json, String key) {
        int keyIndex = json.indexOf(key);
        if (keyIndex == -1) return null;

        int colonIndex = json.indexOf(':', keyIndex);
        if (colonIndex == -1) return null;

        int startQuote = json.indexOf('"', colonIndex + 1);
        if (startQuote == -1) return null;

        // 이스케이프된 따옴표 처리
        int endQuote = findEndQuote(json, startQuote + 1);
        if (endQuote == -1) return null;

        return json.substring(startQuote + 1, endQuote);
    }

    /**
     * 이스케이프된 따옴표를 고려하여 문자열의 끝 따옴표 위치 찾기
     */
    private static int findEndQuote(String json, int start) {
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                
                int backslashCount = 0;
                for (int j = i - 1; j >= start && json.charAt(j) == '\\'; j--) {
                    backslashCount++;
                }
                
                if (backslashCount % 2 == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static int findValueEnd(String json, int start) {
        int commaIndex = json.indexOf(',', start);
        int braceIndex = json.indexOf('}', start);

        if (commaIndex == -1) return braceIndex;
        if (braceIndex == -1) return commaIndex;
        return Math.min(commaIndex, braceIndex);
    }

    public boolean isValid() {
        return riskScore != null
            && confidence != null
            && action != null
            && !action.isBlank();
    }

    public boolean hasValidAction() {
        if (action == null) return false;
        String normalized = action.toUpperCase().trim();
        return "ALLOW".equals(normalized)
            || "BLOCK".equals(normalized)
            || "CHALLENGE".equals(normalized)
            || "ESCALATE".equals(normalized);
    }
}
