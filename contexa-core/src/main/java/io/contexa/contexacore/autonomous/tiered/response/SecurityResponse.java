package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

/**
 * AI Native v6.6: 통합 보안 응답 모델
 *
 * Layer1과 Layer2 모두 동일한 응답 형식을 사용합니다.
 * L1 = L2 원칙: 프롬프트와 응답 형식이 완전히 동일하며, 차이점은 LLM 모델만 다릅니다.
 *
 * 통합 응답 형식 (5개 필드 + 1개 디버깅용):
 * - riskScore: 위험 점수 (0.0 ~ 1.0)
 * - confidence: 신뢰도 (0.0 ~ 1.0)
 * - action: 액션 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
 * - reasoning: 분석 근거
 * - mitre: MITRE ATT&CK 기법 ID (선택)
 * - confidenceReasoning: confidence 값의 근거 (디버깅용)
 *
 * 제거된 필드:
 * - recommendation: action과 중복
 * - behaviorPatterns, threatCategory, mitigationActions: 프롬프트에서 요청 안함
 * - sessionAnalysis, relatedEvents: 프롬프트에서 요청 안함
 *
 * @since AI Native v6.6
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityResponse {

    /**
     * 위험 점수 (0.0 ~ 1.0)
     * 0 = 안전, 1 = 심각한 위협
     */
    private Double riskScore;

    /**
     * 신뢰도 (0.0 ~ 1.0)
     * LLM이 자신의 판단에 대해 얼마나 확신하는지
     */
    private Double confidence;

    /**
     * confidence 값의 근거 설명 (디버깅용)
     * LLM이 왜 이 confidence 값을 산출했는지 명시적 사유
     */
    private String confidenceReasoning;

    /**
     * 액션 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     * - ALLOW: 요청 허용
     * - BLOCK: 요청 차단
     * - CHALLENGE: 추가 인증 요구 (MFA)
     * - ESCALATE: Layer 2 또는 보안 분석가에게 전달
     */
    private String action;

    /**
     * 분석 근거 (max 30 tokens)
     * 판단의 이유를 간략하게 설명
     */
    private String reasoning;

    /**
     * MITRE ATT&CK 기법 ID (선택)
     * 위협이 탐지된 경우 해당 기법 ID (예: T1078, T1550)
     */
    private String mitre;

    /**
     * JSON 응답을 파싱하여 SecurityResponse 객체 생성
     *
     * 지원 형식:
     * 1. 축약 형식: {"r":0.75,"c":0.85,"a":"E","d":"session anomaly detected"}
     * 2. 전체 형식: {"riskScore":0.75,"confidence":0.85,"action":"ESCALATE","reasoning":"..."}
     *
     * @param json JSON 문자열
     * @return SecurityResponse 객체 (파싱 실패 시 null)
     */
    public static SecurityResponse fromJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }

        SecurityResponse response = new SecurityResponse();

        try {
            // riskScore 추출 (축약: "r" 또는 전체: "riskScore")
            Double riskScore = extractDouble(json, "\"r\"");
            if (riskScore == null) {
                riskScore = extractDouble(json, "\"riskScore\"");
            }
            response.setRiskScore(riskScore);

            // confidence 추출 (축약: "c" 또는 전체: "confidence")
            Double confidence = extractDouble(json, "\"c\"");
            if (confidence == null) {
                confidence = extractDouble(json, "\"confidence\"");
            }
            response.setConfidence(confidence);

            // action 추출 (축약: "a" 또는 전체: "action")
            String action = extractString(json, "\"a\"");
            if (action != null) {
                action = expandAction(action);
            } else {
                action = extractString(json, "\"action\"");
            }
            response.setAction(action);

            // reasoning 추출 (축약: "d" 또는 전체: "reasoning" 또는 "reason")
            String reasoning = extractString(json, "\"d\"");
            if (reasoning == null) {
                reasoning = extractString(json, "\"reasoning\"");
            }
            if (reasoning == null) {
                reasoning = extractString(json, "\"reason\"");
            }
            response.setReasoning(reasoning);

            // mitre 추출 (축약: "m" 또는 전체: "mitre")
            String mitre = extractString(json, "\"m\"");
            if (mitre == null) {
                mitre = extractString(json, "\"mitre\"");
            }
            response.setMitre(mitre);

            // confidenceReasoning 추출
            String confReasoning = extractString(json, "\"confidenceReasoning\"");
            response.setConfidenceReasoning(confReasoning);

        } catch (Exception e) {
            // 파싱 실패 시 null 반환
            return null;
        }

        return response;
    }

    /**
     * 하위 호환성: fromCompactJson() 별칭
     *
     * @deprecated fromJson() 사용 권장
     */
    @Deprecated
    public static SecurityResponse fromCompactJson(String json) {
        return fromJson(json);
    }

    /**
     * 축약 action 코드를 전체 action 문자열로 확장
     *
     * A -> ALLOW
     * B -> BLOCK
     * C -> CHALLENGE
     * E -> ESCALATE
     */
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
                // 이스케이프되지 않은 따옴표인지 확인
                int backslashCount = 0;
                for (int j = i - 1; j >= start && json.charAt(j) == '\\'; j--) {
                    backslashCount++;
                }
                // 짝수 개의 백슬래시면 이스케이프되지 않은 따옴표
                if (backslashCount % 2 == 0) {
                    return i;
                }
            }
        }
        return -1;
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

    /**
     * SecurityResponse가 유효한지 검사
     *
     * 필수 필드: riskScore, confidence, action
     *
     * @return 유효하면 true
     */
    public boolean isValid() {
        return riskScore != null
            && confidence != null
            && action != null
            && !action.isBlank();
    }

    /**
     * action이 유효한 값인지 검사
     *
     * @return ALLOW, BLOCK, CHALLENGE, ESCALATE 중 하나면 true
     */
    public boolean hasValidAction() {
        if (action == null) return false;
        String normalized = action.toUpperCase().trim();
        return "ALLOW".equals(normalized)
            || "BLOCK".equals(normalized)
            || "CHALLENGE".equals(normalized)
            || "ESCALATE".equals(normalized);
    }
}
