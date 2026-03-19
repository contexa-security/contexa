package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ZeroTrustAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final double trustScore;
    private final double threatScore;
    private volatile ZeroTrustAction action;

    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore,
                                        ZeroTrustAction action) {
        super(principal, credentials, authorities);
        this.trustScore = trustScore;
        this.threatScore = threatScore;
        this.action = action;
    }

    public double getTrustScore() {
        return trustScore;
    }

    public double getThreatScore() {
        return threatScore;
    }

    public ZeroTrustAction getAction() {
        return action;
    }

    public void setAction(ZeroTrustAction action) {
        this.action = action;
    }
}
