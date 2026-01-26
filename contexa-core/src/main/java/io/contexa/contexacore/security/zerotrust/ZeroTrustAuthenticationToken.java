package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;

public class ZeroTrustAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private double trustScore;
    private double threatScore;
    private UserSecurityContext userContext;
    private LocalDateTime lastEvaluated;
    private String sessionId;

    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore) {
        super(principal, credentials, authorities);
        this.trustScore = trustScore;
        this.threatScore = threatScore;
        this.lastEvaluated = LocalDateTime.now();
    }

    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore,
                                        UserSecurityContext userContext,
                                        String sessionId) {
        super(principal, credentials, authorities);
        this.trustScore = trustScore;
        this.threatScore = threatScore;
        this.userContext = userContext;
        this.sessionId = sessionId;
        this.lastEvaluated = LocalDateTime.now();
    }

    public double getTrustScore() {return trustScore;}

    public void setTrustScore(double trustScore) {
        this.trustScore = trustScore;
    }

    public double getThreatScore() {
        return threatScore;
    }

    public void setThreatScore(double threatScore) {this.threatScore = threatScore;}

    public UserSecurityContext getUserContext() {
        return userContext;
    }

    public void setUserContext(UserSecurityContext userContext) {
        this.userContext = userContext;
    }

    public LocalDateTime getLastEvaluated() {
        return lastEvaluated;
    }

    public void setLastEvaluated(LocalDateTime lastEvaluated) {
        this.lastEvaluated = lastEvaluated;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
}