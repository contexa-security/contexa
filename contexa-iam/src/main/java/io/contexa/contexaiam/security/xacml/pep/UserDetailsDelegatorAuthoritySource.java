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
package io.contexa.contexaiam.security.xacml.pep;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

/**
 * The delegator's authority as the application's {@link UserDetailsService} knows the person (A1-8). A disabled or
 * locked account delegates nothing.
 */
public class UserDetailsDelegatorAuthoritySource implements DelegatorAuthoritySource {

    private final UserDetailsService userDetailsService;

    public UserDetailsDelegatorAuthoritySource(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Optional<Authentication> authenticationOf(String delegatorId) {
        try {
            UserDetails person = userDetailsService.loadUserByUsername(delegatorId);
            if (person == null || !person.isEnabled() || !person.isAccountNonLocked()) {
                return Optional.empty();
            }
            return Optional.of(UsernamePasswordAuthenticationToken.authenticated(person, null, person.getAuthorities()));
        } catch (UsernameNotFoundException unknown) {
            return Optional.empty();
        }
    }
}
