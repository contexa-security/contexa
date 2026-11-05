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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.agent.service.OAuth2AgentProvisioning;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

import java.util.Locale;
import java.util.function.BooleanSupplier;

/**
 * How many users could not answer a CHALLENGE (Q-1): neither a passkey nor an address a code can reach. An operator
 * sees it before a user meets it, at the start and on the console's user list. The bridge's copies exist from a user's
 * first sign-in, so under HOST_OWNED the number counts the users seen so far.
 */
@Slf4j
public class VerificationCoverageService implements ApplicationListener<ApplicationReadyEvent> {

    private final UserRepository users;
    private final String syntheticEmailDomain;
    private final BooleanSupplier mailDelivers;

    public VerificationCoverageService(UserRepository users, String syntheticEmailDomain, BooleanSupplier mailDelivers) {
        this.users = users;
        this.syntheticEmailDomain = syntheticEmailDomain;
        this.mailDelivers = mailDelivers;
    }

    public long usersWithoutFactor() {
        return users.countWithoutVerificationFactor(mailDelivers.getAsBoolean(),
                "%@" + syntheticEmailDomain.toLowerCase(Locale.ROOT),
                "%" + OAuth2AgentProvisioning.ACCOUNT_EMAIL_DOMAIN);
    }

    /** A notice for the operator: a store that cannot be read at the start stops nothing. */
    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        try {
            long count = usersWithoutFactor();
            if (count > 0) {
                log.warn("[Verification] {} users cannot answer a CHALLENGE: they have no passkey and no address a code "
                        + "can reach. Give them an address on the console's user page, provide a "
                        + "BridgeUserEmailProvider bean, or let them register a passkey at /contexa/step-up", count);
            }
        } catch (RuntimeException e) {
            log.error("[Verification] Could not count the users who cannot answer a CHALLENGE: {}", e.toString());
        }
    }
}
