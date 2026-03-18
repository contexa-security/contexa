package io.contexa.springbootstartercontexa.service;

import io.contexa.contexacommon.annotation.Protectable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * 보안 플로우 테스트용 서비스
 *
 * 각 메서드는 @Protectable 어노테이션으로 보호되며,
 * AnalysisRequirement에 따라 다른 보안 정책이 적용된다.
 *
 * 메서드 식별자 형식: {패키지}.{클래스}.{메서드}({파라미터타입})
 */
@Slf4j
@Service
public class TestSecurityService {

    /**
     * 공개 데이터 조회 - 분석 불필요
     *
     * AnalysisRequirement.NOT_REQUIRED:
     * - LLM 분석 결과와 무관하게 인증만 확인
     * - 공개 API나 비민감 리소스에 적합
     *
     * 메서드 식별자: io.contexa.springbootstartercontexa.service.TestSecurityService.getPublicData(String)
     *
     * @param resourceId 리소스 식별자
     * @return 공개 데이터 문자열
     */
    @Protectable
    public String getPublicData(String resourceId) {
        log.info("공개 데이터 조회 요청 - resourceId: {}", resourceId);

        if (resourceId == null || resourceId.isBlank()) {
            throw new IllegalArgumentException("resourceId는 필수입니다.");
        }

        return String.format("공개 데이터 [%s]: 이 데이터는 인증된 모든 사용자가 접근 가능합니다.", resourceId);
    }

    /**
     * 일반 데이터 조회 - 분석 선호
     *
     * AnalysisRequirement.PREFERRED:
     * - LLM 분석 결과가 있으면 사용하고, 없으면 defaultAction 적용
     * - 일반적인 비즈니스 데이터에 적합
     *
     * 메서드 식별자: io.contexa.springbootstartercontexa.service.TestSecurityService.getNormalData(String)
     *
     * @param resourceId 리소스 식별자
     * @return 일반 데이터 문자열
     */
    @Protectable
    public String getNormalData(String resourceId) {
        log.info("일반 데이터 조회 요청 - resourceId: {}", resourceId);

        if (resourceId == null || resourceId.isBlank()) {
            throw new IllegalArgumentException("resourceId는 필수입니다.");
        }

        return String.format("일반 데이터 [%s]: 이 데이터는 ALLOW Action일 때 접근 가능합니다.", resourceId);
    }

    /**
     * 민감 데이터 조회 - 분석 필수
     *
     * AnalysisRequirement.REQUIRED:
     * - LLM 분석 결과가 반드시 필요
     * - 분석 미완료시 analysisTimeout까지 대기 후 차단
     * - 개인정보, 금융정보 등 민감한 데이터에 적합
     *
     * 메서드 식별자: io.contexa.springbootstartercontexa.service.TestSecurityService.getSensitiveData(String)
     *
     * @param resourceId 리소스 식별자
     * @return 민감 데이터 문자열
     */
    @Protectable
    public String getSensitiveData(String resourceId) {
        log.info("민감 데이터 조회 요청 - resourceId: {}", resourceId);

        if (resourceId == null || resourceId.isBlank()) {
            throw new IllegalArgumentException("resourceId는 필수입니다.");
        }

        return String.format("민감 데이터 [%s]: 이 데이터는 LLM 분석 완료 + ALLOW/MONITOR Action일 때만 접근 가능합니다.", resourceId);
    }

    /**
     * 중요 데이터 조회 - ALLOW만 허용
     *
     * AnalysisRequirement.STRICT:
     * - LLM 분석 결과가 반드시 ALLOW여야 함
     * - MONITOR도 차단됨
     * - 시스템 설정, 관리자 기능 등 가장 민감한 데이터에 적합
     *
     * 메서드 식별자: io.contexa.springbootstartercontexa.service.TestSecurityService.getCriticalData(String)
     *
     * @param resourceId 리소스 식별자
     * @return 중요 데이터 문자열
     */
    @Protectable
    public String getCriticalData(String resourceId) {
        log.info("중요 데이터 조회 요청 - resourceId: {}", resourceId);

        if (resourceId == null || resourceId.isBlank()) {
            throw new IllegalArgumentException("resourceId는 필수입니다.");
        }

        return String.format("중요 데이터 [%s]: 이 데이터는 ADMIN 권한 + LLM 분석 완료 + ALLOW Action일 때만 접근 가능합니다.", resourceId);
    }

    /**
     * Streaming bulk data access validation
     *
     * AnalysisRequirement.PREFERRED + enableRuntimeInterception:
     * - Triggers Zero Trust event before streaming response
     * - Used by /bulk-stream endpoint for real-time response blocking demo
     *
     * Method ID: io.contexa.springbootstartercontexa.service.TestSecurityService.validateBulkStreamAccess()
     */
    @Protectable
    public void validateBulkStreamAccess() {
        log.info("Bulk stream access validation - @Protectable triggered");
    }

    /**
     * 대량 데이터 조회 - 실시간 차단 활성화
     *
     * AnalysisRequirement.PREFERRED + enableRuntimeInterception:
     * - 메서드 실행 중에도 LLM이 BLOCK 판정하면 즉시 중단
     * - 대량 데이터 추출, 장시간 작업 등에 적합
     * - 데이터 유출 공격 방지에 효과적
     *
     * 메서드 식별자: io.contexa.springbootstartercontexa.service.TestSecurityService.getBulkData()
     *
     * @return 대량 데이터 문자열
     */
    @Protectable
    public String getBulkData() {
        log.info("대량 데이터 조회 요청");

        StringBuilder sb = new StringBuilder();
        sb.append("대량 데이터 조회 결과:\n");
        sb.append("==========================================\n");

        for (int i = 1; i <= 10000; i++) {
            sb.append(String.format("Record-%05d: 데이터 항목 %d번\n", i, i));

            // 매 1000건마다 로그 출력 (실시간 차단 테스트용)
            if (i % 1000 == 0) {
                log.debug("대량 데이터 처리 중 - 진행률: {}%", (i / 100));
            }
        }

        sb.append("==========================================\n");
        sb.append("총 1000,000건의 데이터가 조회되었습니다.");

        return sb.toString();
    }
}
