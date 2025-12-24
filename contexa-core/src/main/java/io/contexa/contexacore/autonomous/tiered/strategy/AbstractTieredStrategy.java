package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Tiered Strategy 추상 기반 클래스
 *
 * Layer1/Layer2/Layer3 전략의 공통 기능을 제공합니다:
 * - Cold→Hot Path 동기화
 * - Hot Path 피드백
 * - 공통 유틸리티 메서드
 *
 * 주의사항:
 * - 기존 Layer 클래스의 모든 기능 유지
 * - 공통 기능만 추출하여 제공
 * - 각 Layer의 독립성 보장
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {


    protected String getUserId(SecurityEvent event) {
        return event.getUserId() != null ?
            event.getUserId() : FeedbackConstants.DEFAULT_USER_ID;
    }

    protected abstract String getLayerName();

    @Override
    public String getStrategyName() {
        return getLayerName();
    }

    /**
     * LLM 응답에서 JSON 객체 추출
     *
     * LLM 응답은 종종 JSON 앞뒤에 텍스트를 포함합니다.
     * 이 메서드는 첫 번째 '{' 와 마지막 '}' 사이의 JSON 객체를 추출합니다.
     *
     * @param response LLM 응답 문자열
     * @return 추출된 JSON 문자열, 또는 원본 응답 (JSON 없는 경우)
     */
    protected String extractJsonObject(String response) {
        if (response == null || response.isEmpty()) {
            return "{}";
        }

        int startIndex = response.indexOf('{');
        int endIndex = response.lastIndexOf('}');

        if (startIndex != -1 && endIndex != -1 && endIndex > startIndex) {
            return response.substring(startIndex, endIndex + 1);
        }

        return response;
    }

    /**
     * 문자열 action을 SecurityDecision.Action으로 매핑 (AI Native v3.3.0)
     *
     * 공통 매핑 로직:
     * - ALLOW(A): 안전한 요청
     * - BLOCK(B): 극고위험군 (즉시 차단)
     * - CHALLENGE(C): 고위험군 (MFA 인증 요구)
     * - ESCALATE(E): 상위 Layer로 에스컬레이션
     *
     * Deprecated Actions (v3.3.0):
     * - INVESTIGATE(I): deprecated -> ESCALATE로 변환 (경고 로그)
     * - MONITOR(M): deprecated -> ESCALATE로 변환 (경고 로그)
     *
     * @param action LLM이 반환한 action 문자열
     * @return SecurityDecision.Action enum
     */
    protected SecurityDecision.Action mapStringToAction(String action) {
        if (action == null) return SecurityDecision.Action.ESCALATE;

        String upperAction = action.toUpperCase().trim();

        // Deprecated action 감지 및 경고 로그
        if ("INVESTIGATE".equals(upperAction) || "I".equals(upperAction)) {
            log.warn("[{}][AI Native v3.3.0] Deprecated action 'INVESTIGATE' detected. " +
                    "Converting to ESCALATE. Please update LLM prompt to use 4-action system: " +
                    "ALLOW, BLOCK, CHALLENGE, ESCALATE", getLayerName());
            return SecurityDecision.Action.ESCALATE;
        }
        if ("MONITOR".equals(upperAction) || "M".equals(upperAction)) {
            log.warn("[{}][AI Native v3.3.0] Deprecated action 'MONITOR' detected. " +
                    "Converting to ESCALATE. Please update LLM prompt to use 4-action system: " +
                    "ALLOW, BLOCK, CHALLENGE, ESCALATE", getLayerName());
            return SecurityDecision.Action.ESCALATE;
        }

        return switch (upperAction) {
            case "ALLOW", "A" -> SecurityDecision.Action.ALLOW;
            case "BLOCK", "B" -> SecurityDecision.Action.BLOCK;
            case "CHALLENGE", "C" -> SecurityDecision.Action.CHALLENGE;
            default -> {
                if (!"ESCALATE".equals(upperAction) && !"E".equals(upperAction)) {
                    log.warn("[{}][AI Native] Unknown action '{}' detected. Converting to ESCALATE",
                            getLayerName(), action);
                }
                yield SecurityDecision.Action.ESCALATE;
            }
        };
    }

    /**
     * 유효한 action인지 검증 (AI Native v3.3.0 - 4개 Action)
     *
     * 유효 Action: ALLOW(A), BLOCK(B), CHALLENGE(C), ESCALATE(E)
     *
     * @param action 검증할 action 문자열
     * @return 유효하면 true
     */
    protected boolean isValidAction(String action) {
        if (action == null || action.trim().isEmpty()) {
            return false;
        }
        String upperAction = action.toUpperCase().trim();
        return "ALLOW".equals(upperAction) || "A".equals(upperAction) ||
               "BLOCK".equals(upperAction) || "B".equals(upperAction) ||
               "CHALLENGE".equals(upperAction) || "C".equals(upperAction) ||
               "ESCALATE".equals(upperAction) || "E".equals(upperAction);
    }
}