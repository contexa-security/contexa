package io.contexa.contexacore.autonomous.event;

/**
 * LLM 분석 이벤트 리스너 인터페이스
 *
 * ColdPathEventProcessor에서 발생하는 LLM 분석 이벤트를 외부 모듈(spring-boot-starter-contexa)에서
 * 수신하여 SSE로 클라이언트에 전송할 수 있도록 하는 인터페이스입니다.
 *
 * 모듈 간 느슨한 결합 유지:
 * - contexa-core: 이 인터페이스 정의 및 이벤트 발행
 * - spring-boot-starter-contexa: 이 인터페이스 구현하여 SSE 전송
 *
 * @author contexa
 * @since TIPS Demo v1.0
 */
public interface LlmAnalysisEventListener {

    /**
     * 컨텍스트 수집 완료 이벤트
     *
     * @param userId 사용자 ID
     * @param requestPath 요청 경로
     * @param analysisRequirement 분석 요구 수준 (NOT_REQUIRED, PREFERRED, REQUIRED, STRICT)
     */
    void onContextCollected(String userId, String requestPath, String analysisRequirement);

    /**
     * Layer1 분석 시작 이벤트
     *
     * @param userId 사용자 ID
     * @param requestPath 요청 경로
     */
    void onLayer1Start(String userId, String requestPath);

    /**
     * Layer1 분석 완료 이벤트
     *
     * @param userId 사용자 ID
     * @param action 보안 결정 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     * @param riskScore 위험 점수 (0.0-1.0)
     * @param confidence 신뢰도 (0.0-1.0)
     * @param reasoning 분석 근거
     * @param mitre MITRE ATT&CK 매핑
     * @param elapsedMs 분석 소요 시간 (밀리초)
     */
    void onLayer1Complete(String userId, String action, Double riskScore,
                          Double confidence, String reasoning, String mitre, Long elapsedMs);

    /**
     * Layer2 에스컬레이션 이벤트
     *
     * @param userId 사용자 ID
     * @param requestPath 요청 경로
     * @param reason 에스컬레이션 사유
     */
    void onLayer2Start(String userId, String requestPath, String reason);

    /**
     * Layer2 분석 완료 이벤트
     *
     * @param userId 사용자 ID
     * @param action 보안 결정 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     * @param riskScore 위험 점수 (0.0-1.0)
     * @param confidence 신뢰도 (0.0-1.0)
     * @param reasoning 분석 근거
     * @param mitre MITRE ATT&CK 매핑
     * @param elapsedMs 분석 소요 시간 (밀리초)
     */
    void onLayer2Complete(String userId, String action, Double riskScore,
                          Double confidence, String reasoning, String mitre, Long elapsedMs);

    /**
     * 최종 결정 적용 이벤트
     *
     * @param userId 사용자 ID
     * @param action 최종 보안 결정
     * @param layer 결정을 내린 레이어 (LAYER1, LAYER2)
     * @param requestPath 요청 경로
     */
    void onDecisionApplied(String userId, String action, String layer, String requestPath);

    /**
     * 에러 이벤트
     *
     * @param userId 사용자 ID
     * @param message 에러 메시지
     */
    void onError(String userId, String message);
}
