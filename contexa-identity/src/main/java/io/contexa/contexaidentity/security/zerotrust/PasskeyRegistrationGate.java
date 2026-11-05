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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

import java.util.function.BooleanSupplier;

/**
 * Who may register a passkey in a sign-in Contexa owns (Q-13). A passkey answers a CHALLENGE, so it is no matter for the
 * first factor: whoever holds a stolen password would register one and answer with it. A session registers once it has
 * completed MFA, in its login or by a step-up; a session without one verifies first, and a session under a CHALLENGE
 * answers it first. A BLOCK or an ESCALATE refuses it.
 * <p>
 * Without an MFA flow nothing can be asked and no CHALLENGE can be answered with a passkey, so only what is in force
 * stops the request. A decision stops it under ENFORCE only, as everywhere else.
 */
public class PasskeyRegistrationGate {

    /** What becomes of a request to register a passkey. */
    public enum Verdict {
        /** The request goes on. */
        OPEN,
        /** The user verifies first, and comes back. */
        VERIFY,
        /** The request is refused. */
        REFUSED
    }

    private final ZeroTrustActionRepository actions;
    private final BooleanSupplier enforcing;
    private final BooleanSupplier verificationAvailable;

    public PasskeyRegistrationGate(ZeroTrustActionRepository actions, BooleanSupplier enforcing,
                                   BooleanSupplier verificationAvailable) {
        this.actions = actions;
        this.enforcing = enforcing;
        this.verificationAvailable = verificationAvailable;
    }

    public Verdict verdict(HttpServletRequest request, Authentication authentication) {
        boolean canVerify = verificationAvailable.getAsBoolean();
        if (enforcing.getAsBoolean()) {
            ZeroTrustAction action = actions.getCurrentAction(ZeroTrustUserKey.person(authentication.getName()),
                    SessionFingerprintUtil.generateContextBindingHash(request));
            if (action == ZeroTrustAction.BLOCK || action == ZeroTrustAction.ESCALATE) {
                return Verdict.REFUSED;
            }
            if (action == ZeroTrustAction.CHALLENGE) {
                return canVerify ? Verdict.VERIFY : Verdict.REFUSED;
            }
        }
        return !canVerify || mfaCompleted(authentication) ? Verdict.OPEN : Verdict.VERIFY;
    }

    private static boolean mfaCompleted(Authentication authentication) {
        return authentication.getDetails() instanceof LoginFactsDetails facts
                && Boolean.TRUE.equals(facts.getMfaCompleted());
    }
}
