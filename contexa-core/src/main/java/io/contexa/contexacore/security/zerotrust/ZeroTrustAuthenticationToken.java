package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;

/**
 * Zero Trust Authentication Token
 *
 * Spring Security의 Authentication을 확장하여 Zero Trust 메타데이터를 포함합니다.
 * Trust Score, Threat Score, User Context 등의 정보를 Authentication 객체에 통합합니다.
 *
 * @author contexa
 * @since 1.0
 */
public class ZeroTrustAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private double trustScore;
    private double threatScore;
    private UserSecurityContext userContext;
    private LocalDateTime lastEvaluated;
    private String sessionId;
    private ZeroTrustSecurityService.TrustTier trustTier;

    /**
     * 인증된 토큰 생성자
     */
    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore) {
        super(principal, credentials, authorities);
        this.trustScore = trustScore;
        this.threatScore = threatScore;
        this.lastEvaluated = LocalDateTime.now();
        this.trustTier = calculateTrustTier(threatScore);
    }

    /**
     * 전체 파라미터를 포함한 생성자
     */
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
        this.trustTier = calculateTrustTier(threatScore);
    }

    /**
     * Trust Tier 계산
     */
    private ZeroTrustSecurityService.TrustTier calculateTrustTier(double threatScore) {
        if (threatScore >= 0.9) {
            return ZeroTrustSecurityService.TrustTier.UNTRUSTED;
        } else if (threatScore >= 0.7) {
            return ZeroTrustSecurityService.TrustTier.LOW;
        } else if (threatScore >= 0.5) {
            return ZeroTrustSecurityService.TrustTier.MEDIUM;
        } else if (threatScore >= 0.3) {
            return ZeroTrustSecurityService.TrustTier.HIGH;
        } else {
            return ZeroTrustSecurityService.TrustTier.FULL;
        }
    }

    public double getTrustScore() {
        return trustScore;
    }

    public void setTrustScore(double trustScore) {
        this.trustScore = trustScore;
    }

    public double getThreatScore() {
        return threatScore;
    }

    public void setThreatScore(double threatScore) {
        this.threatScore = threatScore;
        this.trustTier = calculateTrustTier(threatScore);
    }

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

    /**
     * 높은 위험 수준인지 확인
     */
    public boolean isHighRisk() {
        return threatScore >= 0.7;
    }

    @Override
    public String toString() {
        return "ZeroTrustAuthenticationToken{" +
            "principal=" + getPrincipal() +
            ", trustScore=" + trustScore +
            ", threatScore=" + threatScore +
            ", trustTier=" + trustTier +
            ", lastEvaluated=" + lastEvaluated +
            ", sessionId=" + sessionId +
            ", authenticated=" + isAuthenticated() +
            '}';
    }
}