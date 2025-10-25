package io.contexa.contexacore.simulation.interceptor;

import io.contexa.contexacore.simulation.context.SimulationModeHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 시뮬레이션 모드 인터셉터
 *
 * HTTP 요청에서 시뮬레이션 모드를 추출하여 ThreadLocal에 설정합니다.
 * 이를 통해 요청 처리 전체 과정에서 시뮬레이션 모드를 인식할 수 있습니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
public class SimulationModeInterceptor implements HandlerInterceptor {

    private static final String SIMULATION_MODE_HEADER = "X-Simulation-Mode";
    private static final String SIMULATION_CAMPAIGN_HEADER = "X-Simulation-Campaign";
    private static final String SIMULATION_ATTACK_HEADER = "X-Simulation-Attack";

    /**
     * 요청 처리 전 시뮬레이션 모드 설정
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param handler 핸들러
     * @return 계속 처리 여부
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            // HTTP 헤더에서 시뮬레이션 모드 추출
            String modeHeader = request.getHeader(SIMULATION_MODE_HEADER);
            String campaignId = request.getHeader(SIMULATION_CAMPAIGN_HEADER);
            String attackId = request.getHeader(SIMULATION_ATTACK_HEADER);

            // URL 파라미터에서도 확인 (헤더가 없을 경우)
            if (modeHeader == null) {
                modeHeader = request.getParameter("simulationMode");
                campaignId = request.getParameter("campaignId");
                attackId = request.getParameter("attackId");
            }

            // 시뮬레이션 모드가 지정된 경우 설정
            if (modeHeader != null) {
                SimulationModeHolder.Mode mode = parseMode(modeHeader);

                if (mode != SimulationModeHolder.Mode.NORMAL) {
                    // campaignId와 attackId가 없으면 기본값 생성
                    if (campaignId == null) {
                        campaignId = "simulation-" + System.currentTimeMillis();
                    }
                    if (attackId == null) {
                        attackId = "attack-" + System.nanoTime();
                    }

                    SimulationModeHolder.setMode(mode, campaignId, attackId);

                    log.info("Simulation mode activated - Mode: {}, Campaign: {}, Attack: {}, URI: {}",
                            mode, campaignId, attackId, request.getRequestURI());

                    // 무방비 모드일 경우 경고 로그
                    if (mode == SimulationModeHolder.Mode.UNPROTECTED) {
                        log.warn("UNPROTECTED MODE ACTIVE - Security will be bypassed for this request!");
                    }
                }
            } else {
                // 시뮬레이션 모드가 아닌 경우 정상 모드로 설정
                SimulationModeHolder.clear();
            }

            return true;
        } catch (Exception e) {
            log.error("Error setting simulation mode", e);
            // 오류가 발생해도 요청은 계속 처리
            SimulationModeHolder.clear();
            return true;
        }
    }

    /**
     * 요청 처리 완료 후 시뮬레이션 컨텍스트 정리
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param handler 핸들러
     * @param ex 예외 (있을 경우)
     */
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        try {
            // 현재 컨텍스트 정보 로깅
            if (SimulationModeHolder.isSimulation()) {
                log.debug("Clearing simulation context: {}", SimulationModeHolder.getContextInfo());
            }

            // ThreadLocal 정리
            SimulationModeHolder.clear();
        } catch (Exception e) {
            log.error("Error clearing simulation mode", e);
        }
    }

    /**
     * 문자열을 시뮬레이션 모드로 파싱
     *
     * @param modeString 모드 문자열
     * @return 시뮬레이션 모드
     */
    private SimulationModeHolder.Mode parseMode(String modeString) {
        if (modeString == null) {
            return SimulationModeHolder.Mode.NORMAL;
        }

        try {
            return SimulationModeHolder.Mode.valueOf(modeString.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid simulation mode: {}, defaulting to NORMAL", modeString);
            return SimulationModeHolder.Mode.NORMAL;
        }
    }
}