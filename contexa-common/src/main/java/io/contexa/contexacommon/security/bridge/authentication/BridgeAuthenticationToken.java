package io.contexa.contexacommon.security.bridge.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class BridgeAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public BridgeAuthenticationToken(
            Object principal,
            Collection<? extends GrantedAuthority> authorities,
            BridgeAuthenticationDetails details) {
        super(principal, null, authorities);
        setDetails(details);
    }

    @Override
    public BridgeAuthenticationDetails getDetails() {
        return (BridgeAuthenticationDetails) super.getDetails();
    }
}
