package io.contexa.contexacore.std.advisor.core;

public class AdvisorException extends RuntimeException {
    
    private final boolean blocking;
    private final String domain;
    private final String advisorName;

    public static AdvisorException blocking(String domain, String advisorName, String message) {
        return new AdvisorException(domain, advisorName, message, true);
    }

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