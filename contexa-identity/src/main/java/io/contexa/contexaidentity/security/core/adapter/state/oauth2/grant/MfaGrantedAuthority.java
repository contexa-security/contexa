package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.io.Serial;

public class MfaGrantedAuthority implements GrantedAuthority {

    @Serial
    private static final long serialVersionUID = 1L;
    private String role;

    public MfaGrantedAuthority() {}
    public MfaGrantedAuthority(String role) {
        Assert.hasText(role, "A granted authority textual representation is required");
        this.role = role;
    }
    @Override
    public String getAuthority() {
        return this.role;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof MfaGrantedAuthority sga) {
            return this.role.equals(sga.getAuthority());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.role.hashCode();
    }

    @Override
    public String toString() {
        return this.role;
    }
}
