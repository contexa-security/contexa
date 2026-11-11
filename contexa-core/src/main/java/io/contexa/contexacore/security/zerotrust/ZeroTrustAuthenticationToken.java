/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ZeroTrustAuthenticationToken extends UsernamePasswordAuthenticationToken {

    // The value the class had before the name was kept: a session stored by an earlier version is still read.
    private static final long serialVersionUID = 4527513060875169932L;

    private final double trustScore;
    private final double threatScore;
    private volatile ZeroTrustAction action;
    /** The name of the authentication this one stands in for; null where none was given, or in a session stored before. */
    private final String name;

    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore,
                                        ZeroTrustAction action) {
        this(principal, credentials, authorities, trustScore, threatScore, action, null);
    }

    /**
     * @param name the name of the authentication this one replaces. This class works the name out from the principal,
     *             and a principal that is no {@code UserDetails}, {@code AuthenticatedPrincipal} or {@code Principal}
     *             (the user entity of a passkey sign-in) gave its object string for it: the session was then no longer
     *             the user's for the decisions, the session tracking and the forced sign-out kept by name.
     */
    public ZeroTrustAuthenticationToken(Object principal, Object credentials,
                                        Collection<? extends GrantedAuthority> authorities,
                                        double trustScore, double threatScore,
                                        ZeroTrustAction action, String name) {
        super(principal, credentials, authorities);
        this.trustScore = trustScore;
        this.threatScore = threatScore;
        this.action = action;
        this.name = name;
    }

    @Override
    public String getName() {
        return name != null && !name.isBlank() ? name : super.getName();
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
