package io.contexa.contexacore.security.zerotrust;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ZeroTrustAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final double trustScore;
    private final double threatScore;

    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore) {
        super(principal, credentials, authorities);
        this.trustScore = trustScore;
        this.threatScore = threatScore;
    }

    public double getTrustScore() {
        return trustScore;
    }

    public double getThreatScore() {
        return threatScore;
    }
}
