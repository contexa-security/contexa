package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Layer 2: 컨텍스트 분석 응답 모델
 *
 * Spring AI BeanOutputConverter를 위한 구조화된 응답
 * Layer 2에서 100-300ms 내에 처리되는 컨텍스트 기반 위협 분석 결과
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Layer2SecurityResponse {

    private Double riskScore;

    private Double confidence;

    private String action;

    private String reasoning;

    private List<String> behaviorPatterns;

    private String threatCategory;

    private List<String> mitigationActions;

    private Map<String, Object> sessionAnalysis;

    private List<String> relatedEvents;

    private String recommendation;

    /**
     * 축약 JSON 응답을 파싱하여 Layer2SecurityResponse 객체 생성
     *
     * 축약 형식: {"r":0.75,"c":0.85,"a":"E","d":"session anomaly detected"}
     * - r: riskScore
     * - c: confidence
     * - a: A=ALLOW, E=ESCALATE, B=BLOCK
     * - d: description (reasoning)
     *
     * @param json 축약 JSON 문자열
     * @return Layer2SecurityResponse 객체
     */
    public static Layer2SecurityResponse fromCompactJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }

        Layer2SecurityResponse response = new Layer2SecurityResponse();

        try {
            // JSON에서 "r" (riskScore) 추출
            Double r = extractDouble(json, "\"r\"");
            if (r != null) {
                response.setRiskScore(r);
            }

            // JSON에서 "c" (confidence) 추출
            Double c = extractDouble(json, "\"c\"");
            if (c != null) {
                response.setConfidence(c);
            }

            // JSON에서 "a" (action) 추출 및 변환
            String a = extractString(json, "\"a\"");
            if (a != null) {
                response.setAction(expandAction(a));
            }

            // JSON에서 "d" (description/reasoning) 추출
            String d = extractString(json, "\"d\"");
            if (d != null) {
                response.setReasoning(d);
            }

            // 기존 필드명도 지원 (하위 호환)
            if (response.getRiskScore() == null) {
                response.setRiskScore(extractDouble(json, "\"riskScore\""));
            }
            if (response.getConfidence() == null) {
                response.setConfidence(extractDouble(json, "\"confidence\""));
            }
            if (response.getAction() == null) {
                String action = extractString(json, "\"action\"");
                if (action != null) {
                    response.setAction(action);
                }
            }
            if (response.getReasoning() == null) {
                response.setReasoning(extractString(json, "\"reasoning\""));
            }

            // threatCategory 추출 (축약: "t" 또는 전체명)
            String threatCat = extractString(json, "\"t\"");
            if (threatCat == null) {
                threatCat = extractString(json, "\"threatCategory\"");
            }
            if (threatCat != null) {
                response.setThreatCategory(threatCat);
            }

        } catch (Exception e) {
            // 파싱 실패 시 null 반환
            return null;
        }

        return response;
    }

    /**
     * 축약 action 코드를 전체 action 문자열로 확장
     */
    private static String expandAction(String shortAction) {
        if (shortAction == null) return null;

        return switch (shortAction.toUpperCase().trim()) {
            case "A" -> "ALLOW";
            case "E" -> "ESCALATE";
            case "B" -> "BLOCK";
            case "M" -> "MONITOR";      // 하위 호환
            case "C" -> "CHALLENGE";    // 하위 호환
            default -> shortAction;     // 이미 전체 문자열인 경우
        };
    }

    /**
     * JSON에서 Double 값 추출
     */
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

    /**
     * JSON에서 String 값 추출
     */
    private static String extractString(String json, String key) {
        int keyIndex = json.indexOf(key);
        if (keyIndex == -1) return null;

        int colonIndex = json.indexOf(':', keyIndex);
        if (colonIndex == -1) return null;

        // 문자열 값 찾기 (따옴표로 감싸진 값)
        int startQuote = json.indexOf('"', colonIndex + 1);
        if (startQuote == -1) return null;

        int endQuote = json.indexOf('"', startQuote + 1);
        if (endQuote == -1) return null;

        return json.substring(startQuote + 1, endQuote);
    }

    /**
     * JSON 값의 끝 위치 찾기 (쉼표 또는 닫는 괄호)
     */
    private static int findValueEnd(String json, int start) {
        int commaIndex = json.indexOf(',', start);
        int braceIndex = json.indexOf('}', start);

        if (commaIndex == -1) return braceIndex;
        if (braceIndex == -1) return commaIndex;
        return Math.min(commaIndex, braceIndex);
    }
}