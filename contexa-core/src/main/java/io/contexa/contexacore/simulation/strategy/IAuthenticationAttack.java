package io.contexa.contexacore.simulation.strategy;

import io.contexa.contexacore.simulation.domain.LoginAttempt;
import java.util.List;

/**
 * 인증 공격 전략 인터페이스
 * 
 * 로그인, 세션, 토큰 등 인증 관련 공격을 정의합니다.
 * 브루트포스, 크리덴셜 스터핑, 세션 하이재킹 등을 포함합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
public interface IAuthenticationAttack extends IAttackStrategy {
    
    /**
     * 로그인 시도
     * 
     * @param username 사용자명
     * @param password 비밀번호
     * @return 로그인 시도 결과
     */
    LoginAttempt attemptLogin(String username, String password);
    
    /**
     * 여러 계정으로 로그인 시도
     * 
     * @param credentials 계정 정보 목록
     * @return 로그인 시도 결과 목록
     */
    List<LoginAttempt> attemptMultipleLogins(List<Credential> credentials);
    
    /**
     * 세션 토큰 조작
     * 
     * @param sessionToken 원본 세션 토큰
     * @return 조작된 토큰
     */
    String manipulateSessionToken(String sessionToken);
    
    /**
     * MFA 우회 시도
     * 
     * @param username 사용자명
     * @param mfaCode MFA 코드
     * @return 우회 성공 여부
     */
    boolean attemptMfaBypass(String username, String mfaCode);
    
    /**
     * 패스워드 복잡도 분석
     * 
     * @param password 비밀번호
     * @return 복잡도 점수 (0-100)
     */
    int analyzePasswordComplexity(String password);
    
    /**
     * 로그인 패턴 생성
     * 
     * @param patternType 패턴 유형
     * @return 생성된 로그인 시도 패턴
     */
    List<LoginAttempt> generateLoginPattern(LoginPatternType patternType);
    
    /**
     * 계정 정보
     */
    class Credential {
        private String username;
        private String password;
        private String domain;
        private String source; // leaked_db, generated, dictionary
        
        public Credential() {}
        
        public Credential(String username, String password) {
            this.username = username;
            this.password = password;
        }
        
        public Credential(String username, String password, String domain, String source) {
            this.username = username;
            this.password = password;
            this.domain = domain;
            this.source = source;
        }
        
        // Getters and Setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
    }
    
    /**
     * 로그인 패턴 유형
     */
    enum LoginPatternType {
        RAPID_FIRE("Rapid consecutive attempts"),
        SLOW_AND_STEADY("Slow attempts to avoid detection"),
        DISTRIBUTED("Distributed across multiple IPs"),
        TIME_DELAYED("Time-delayed attempts"),
        INTELLIGENT("Intelligent pattern based on response analysis"),
        RANDOM("Random pattern to confuse detection"),
        HUMAN_LIKE("Human-like typing and timing");
        
        private final String description;
        
        LoginPatternType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * MFA 우회 기법
     */
    enum MfaBypassTechnique {
        FATIGUE_ATTACK("Bombard user with MFA requests until they approve"),
        BACKUP_CODE_BRUTEFORCE("Try common backup codes"),
        SESSION_COOKIE_THEFT("Steal session cookie after MFA"),
        DOWNGRADE_ATTACK("Force fallback to weaker MFA method"),
        SOCIAL_ENGINEERING("Trick user into providing MFA code"),
        TIME_SYNC_ATTACK("Exploit time synchronization issues"),
        REPLAY_ATTACK("Replay captured MFA tokens");
        
        private final String description;
        
        MfaBypassTechnique(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}