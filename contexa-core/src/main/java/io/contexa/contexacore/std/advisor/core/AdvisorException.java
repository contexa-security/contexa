package io.contexa.contexacore.std.advisor.core;

/**
 * Advisor 처리 중 발생하는 예외
 * 
 * 블로킹 여부에 따라 체인 실행을 중단하거나 계속할 수 있습니다.
 */
public class AdvisorException extends RuntimeException {
    
    private final boolean blocking;
    private final String domain;
    private final String advisorName;
    
    /**
     * 블로킹 예외 생성
     */
    public static AdvisorException blocking(String domain, String advisorName, String message) {
        return new AdvisorException(domain, advisorName, message, true);
    }
    
    /**
     * 논블로킹 예외 생성
     */
    public static AdvisorException nonBlocking(String domain, String advisorName, String message) {
        return new AdvisorException(domain, advisorName, message, false);
    }
    
    private AdvisorException(String domain, String advisorName, String message, boolean blocking) {
        super(message);
        this.domain = domain;
        this.advisorName = advisorName;
        this.blocking = blocking;
    }
    
    public boolean isBlocking() {
        return blocking;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public String getAdvisorName() {
        return advisorName;
    }
}