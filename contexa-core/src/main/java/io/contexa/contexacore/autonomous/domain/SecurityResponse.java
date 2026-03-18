package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityResponse {

    private Double riskScore;

    private Double confidence;

    private String action;

    private String reasoning;

    private String mitre;

    private List<String> evidence;
    private String legitimateHypothesis;
    private String suspiciousHypothesis;

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
            response.setAction("CHALLENGE");

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

            List<String> evidence = extractStringArray(json, "\"evidence\"");
            response.setEvidence(evidence);

            String legitimateHypothesis = extractString(json, "\"legitimateHypothesis\"");
            response.setLegitimateHypothesis(legitimateHypothesis);

            String suspiciousHypothesis = extractString(json, "\"suspiciousHypothesis\"");
            response.setSuspiciousHypothesis(suspiciousHypothesis);

        } catch (Exception e) {
            log.error("[SecurityResponse] Failed to parse JSON response", e);
            return null;
        }

        return response;
    }

    private static String expandAction(String shortAction) {
        if (shortAction == null) return null;
        return ZeroTrustAction.fromString(shortAction).name();
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

        int endQuote = findEndQuote(json, startQuote + 1);
        if (endQuote == -1) return null;

        return json.substring(startQuote + 1, endQuote);
    }

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

    private static List<String> extractStringArray(String json, String key) {
        int keyIndex = json.indexOf(key);
        if (keyIndex == -1) return null;

        int bracketStart = json.indexOf('[', keyIndex);
        if (bracketStart == -1) return null;

        int bracketEnd = json.indexOf(']', bracketStart);
        if (bracketEnd == -1) return null;

        String arrayContent = json.substring(bracketStart + 1, bracketEnd);
        List<String> result = new ArrayList<>();

        int i = 0;
        while (i < arrayContent.length()) {
            int startQuote = arrayContent.indexOf('"', i);
            if (startQuote == -1) break;
            int endQuote = findEndQuote(arrayContent, startQuote + 1);
            if (endQuote == -1) break;
            result.add(arrayContent.substring(startQuote + 1, endQuote));
            i = endQuote + 1;
        }

        return result.isEmpty() ? null : result;
    }

    public boolean isValid() {
        return riskScore != null
            && confidence != null
            && action != null
            && !action.isBlank();
    }

}
