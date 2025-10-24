package io.contexa.contexacore.infra.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

import java.time.Duration;

/**
 * MFA 세션 Repository 인터페이스 - 분산환경 대응 개선
 * - 세션 ID 생성 및 유니크성 보장 추가
 * - Repository별 특성에 맞는 ID 관리 지원
 */
public interface MfaSessionRepository {

    // === 기존 메서드들 ===

    void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    @Nullable
    String getSessionId(HttpServletRequest request);

    void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    void refreshSession(String sessionId);

    boolean existsSession(String sessionId);

    void setSessionTimeout(Duration timeout);

    String getRepositoryType();

    // === 분산환경 대응 신규 메서드들 ===

    /**
     * Repository 특성에 맞는 안전한 세션 ID 생성
     * @param baseId 기본 ID (선택적)
     * @param request HTTP 요청 (컨텍스트 정보 활용)
     * @return 고유하고 안전한 세션 ID
     */
    String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request);

    /**
     * 세션 ID 유니크성 검증
     * @param sessionId 검증할 세션 ID
     * @return true: 사용 가능, false: 중복됨
     */
    boolean isSessionIdUnique(String sessionId);

    /**
     * 세션 ID 충돌 시 재생성
     * @param originalId 원본 ID
     * @param request HTTP 요청
     * @param maxAttempts 최대 재시도 횟수
     * @return 유니크한 세션 ID
     * @throws SessionIdGenerationException ID 생성 실패 시
     */
    String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts);

    /**
     * Repository별 세션 ID 포맷 검증
     * @param sessionId 검증할 세션 ID
     * @return true: 유효한 포맷, false: 잘못된 포맷
     */
    boolean isValidSessionIdFormat(String sessionId);

    /**
     * 분산환경에서의 세션 동기화 지원 여부
     * @return true: 분산 동기화 지원, false: 단일 서버만 지원
     */
    boolean supportsDistributedSync();

    /**
     * Repository별 세션 통계 정보
     * @return 세션 통계 정보
     */
    SessionStats getSessionStats();

    class SessionStats {
        private final long activeSessions;
        private final long totalSessionsCreated;
        private final long sessionCollisions;
        private final double averageSessionDuration;
        private final String repositoryType;

        public SessionStats(long activeSessions, long totalSessionsCreated,
                            long sessionCollisions, double averageSessionDuration,
                            String repositoryType) {
            this.activeSessions = activeSessions;
            this.totalSessionsCreated = totalSessionsCreated;
            this.sessionCollisions = sessionCollisions;
            this.averageSessionDuration = averageSessionDuration;
            this.repositoryType = repositoryType;
        }

        // Getters
        public long getActiveSessions() { return activeSessions; }
        public long getTotalSessionsCreated() { return totalSessionsCreated; }
        public long getSessionCollisions() { return sessionCollisions; }
        public double getAverageSessionDuration() { return averageSessionDuration; }
        public String getRepositoryType() { return repositoryType; }

        @Override
        public String toString() {
            return String.format("SessionStats{type=%s, active=%d, total=%d, collisions=%d, avgDuration=%.2fs}",
                    repositoryType, activeSessions, totalSessionsCreated, sessionCollisions, averageSessionDuration);
        }
    }
}