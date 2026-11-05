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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.state.PasskeyCreationOptionsState;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedStepUp;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialCreationOptionsRequest;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialRequestOptionsRequest;
import org.springframework.security.web.webauthn.management.ImmutableRelyingPartyRegistrationRequest;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.security.web.webauthn.management.RelyingPartyPublicKey;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * The verification-only step-up of HOST_OWNED (ownership design S-2). The application owns sign-in; Contexa checks a
 * factor of the signed-in user and records the result as a decision (the CHALLENGE becomes ALLOW, or a BLOCK an
 * administrator let the user release by MFA is released), through the same {@link ChallengeResolution} as Contexa's own
 * MFA. The application's authentication, session and cookies are left as they were, and what the step-up hands out
 * is kept under the user's decision key, not in the session.
 * <p>
 * The user is the bridge's copy of the application's user (matched by the application's principal name, bridge-managed
 * users only, so an application user never reaches a Contexa account of the same name). Factors: a passkey registered
 * for that copy, a one-time code when the copy has a real e-mail address and mail is configured, and a re-authentication
 * the application itself makes (its own MFA or identity provider), seen in the bridge's authentication stamp.
 * <p>
 * A passkey answers a CHALLENGE, so registering one is no matter for the first factor (Q-13): the session has to confirm
 * the user first, with a one-time code or the application's own MFA sign-in moments before. A code passed for a
 * verification counts, so a user who just answered a CHALLENGE is offered the passkey at once.
 * <p>
 * The one-time code is Spring Security's ({@code JdbcOneTimeTokenService} over Contexa's {@code ctxa_one_time_tokens}),
 * kept under a short key of the copy ({@code step-up:<id>}): the bridge's user names are longer than the table's
 * user name column. Contexa's mail sender delivers it to the copy's own address.
 * <p>
 * A session context gets a limited number of answers for a code. At the limit the codes it asked for are discarded, and
 * it answers nothing more until a new code is mailed for it. The answers are counted for the context and not for the
 * user: a stolen cookie is another address or browser, so a thief's wrong answers use up the thief's own answers and
 * discard only what the thief asked for, and the owner of the session goes on with a code of their own.
 */
@Slf4j
public class HostOwnedStepUpService implements HostOwnedStepUp, DisposableBean {

    /** What the step-up resolves. */
    public enum Purpose { CHALLENGE, BLOCK }

    /** The outcome of a request for a code: sent, asked for again too soon, or not possible for this user now. */
    public enum CodeSending { SENT, TOO_SOON, UNAVAILABLE }

    /**
     * What the signed-in user can do on the step-up page.
     *
     * @param purpose            what a verification resolves, or null when nothing waits for one
     * @param passkey            a passkey is registered for the user
     * @param oneTimeCode        a one-time code can be sent to the user's address
     * @param passkeyEnrollable  a passkey can be registered once the user is confirmed (no restriction in force, none
     *                           registered yet)
     * @param passkeyRegistrable a passkey can be registered now: it is enrollable and this session confirmed the user
     * @param reauthenticationUrl where the application re-authenticates the user, when it said so
     */
    public record Situation(String decisionKey, @Nullable Purpose purpose, @Nullable Users user, boolean passkey,
                            boolean oneTimeCode, boolean passkeyEnrollable, boolean passkeyRegistrable,
                            @Nullable String reauthenticationUrl) {
    }

    private static final String ASSERTION = "assertion:";
    private static final String REGISTRATION = "registration:";
    private static final String CODE_KEY = "step-up:";
    private static final String CODE_SENT = "code-sent:";
    private static final String CODE_SPENT = "code-spent:";
    private static final String CODE_ANSWERS = "code-answers:";
    private static final String CODE_ISSUED = "code-issued:";
    private static final String CODE_DISCARDED = "code-discarded:";
    private static final String CODE_RECOVERY = "code-recovery:";
    private static final String USER_CONFIRMED = "user-confirmed:";

    /** How long a user waits before the next code is mailed (the earlier one is good for minutes still). */
    static final Duration CODE_RESEND_INTERVAL = Duration.ofSeconds(30);

    /** How long ago the application's own MFA sign-in may lie to confirm the user for a passkey (Q-13). */
    static final Duration RECENT_HOST_SIGN_IN = Duration.ofMinutes(5);

    /** Longer than a code lives, so a spent code is never accepted again, by a race or later. */
    private static final Duration CODE_SPENT_HOLD = Duration.ofMinutes(15);

    private final ZeroTrustActionRepository actions;
    private final ChallengeResolution resolution;
    private final UserRepository users;
    private final String syntheticEmailDomain;
    private final StepUpOptionsStore options;
    @Nullable
    private final OneTimeTokenService stepUpCodes;
    @Nullable
    private final EmailService email;
    @Nullable
    private final WebAuthnRelyingPartyOperations relyingParty;
    @Nullable
    private final PublicKeyCredentialUserEntityRepository userEntities;
    @Nullable
    private final UserCredentialRepository credentials;
    @Nullable
    private final PasskeyCreationOptionsCodec creationOptionsCodec;
    @Nullable
    private final String reauthenticationUrl;
    private final int maxCodeAnswers;

    /**
     * @param maxCodeAnswers the answers a session context gets for a one-time code, the setting of Contexa's own MFA
     *                       ({@code contexa.auth.mfa.max-retry-attempts})
     */
    public HostOwnedStepUpService(ZeroTrustActionRepository actions, ChallengeResolution resolution,
                                  UserRepository users, String syntheticEmailDomain, StepUpOptionsStore options,
                                  @Nullable OneTimeTokenService stepUpCodes, @Nullable EmailService email,
                                  @Nullable WebAuthnRelyingPartyOperations relyingParty,
                                  @Nullable PublicKeyCredentialUserEntityRepository userEntities,
                                  @Nullable UserCredentialRepository credentials,
                                  @Nullable PasskeyCreationOptionsCodec creationOptionsCodec,
                                  @Nullable String reauthenticationUrl, int maxCodeAnswers) {
        this.maxCodeAnswers = maxCodeAnswers;
        this.actions = actions;
        this.resolution = resolution;
        this.users = users;
        this.syntheticEmailDomain = syntheticEmailDomain;
        this.options = options;
        this.stepUpCodes = stepUpCodes;
        this.email = email;
        this.relyingParty = relyingParty;
        this.userEntities = userEntities;
        this.credentials = credentials;
        this.creationOptionsCodec = creationOptionsCodec;
        this.reauthenticationUrl = reauthenticationUrl != null && !reauthenticationUrl.isBlank()
                ? reauthenticationUrl : null;
    }

    /**
     * The one-time code service of Spring Security starts a scheduler thread (not a daemon) when it is built and stops it only in
     * {@code destroy()}; this service built it, so it stops it. Otherwise the thread outlives a closed or a failed application context
     * and the JVM of the application does not end.
     */
    @Override
    public void destroy() throws Exception {
        if (stepUpCodes instanceof DisposableBean disposable) {
            disposable.destroy();
        }
    }

    /** The user's situation, or null for an anonymous request or an agent's (an agent answers no factor). */
    @Nullable
    public Situation situation(HttpServletRequest request, @Nullable Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || isAgentRequest(request)) {
            return null;
        }
        String decisionKey = ZeroTrustUserKey.person(authentication.getName());
        ZeroTrustAction action = actions.getCurrentAction(decisionKey,
                SessionFingerprintUtil.generateContextBindingHash(request));
        Purpose purpose = null;
        if (action == ZeroTrustAction.CHALLENGE) {
            purpose = Purpose.CHALLENGE;
        } else if (action == ZeroTrustAction.BLOCK && actions.isBlockMfaPending(decisionKey)) {
            purpose = Purpose.BLOCK;
        }
        Users user = bridgedUser(authentication.getName());
        boolean passkey = user != null && hasPasskey(user);
        boolean restricted = action == ZeroTrustAction.CHALLENGE || action == ZeroTrustAction.BLOCK
                || action == ZeroTrustAction.ESCALATE;
        boolean enrollable = user != null && relyingParty != null && !passkey && !restricted;
        return new Situation(decisionKey, purpose, user, passkey, user != null && canSendCode(user), enrollable,
                enrollable && userConfirmed(request, decisionKey), reauthenticationUrl);
    }

    /** Whether the session passed a one-time code in the last minutes, or the application signed in with MFA just now. */
    private boolean userConfirmed(HttpServletRequest request, String decisionKey) {
        if (request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP) instanceof AuthenticationStamp stamp
                && Boolean.TRUE.equals(stamp.mfaCompleted()) && stamp.authenticationTime() != null
                && stamp.authenticationTime().isAfter(Instant.now().minus(RECENT_HOST_SIGN_IN))) {
            return true;
        }
        return options.holds(userConfirmedKey(request, decisionKey));
    }

    /** Bound to the session's context, as an ALLOW is: the proof of one session opens nothing in another. */
    private static String userConfirmedKey(HttpServletRequest request, String decisionKey) {
        return USER_CONFIRMED + sessionContext(request, decisionKey);
    }

    private static String sessionContext(HttpServletRequest request, String decisionKey) {
        return decisionKey + ":" + SessionFingerprintUtil.generateContextBindingHash(request);
    }

    // ----- one-time code -----

    /**
     * Sends a one-time code to the user's own address. One code per interval: a session under a CHALLENGE (a stolen
     * one, a script) must not be able to fill the real user's mailbox.
     */
    public CodeSending sendCode(HttpServletRequest request, Authentication authentication) {
        Situation situation = situation(request, authentication);
        if (!codeAnswers(situation)) {
            return CodeSending.UNAVAILABLE;
        }
        String interval = CODE_SENT + situation.user().getId();
        if (!options.claim(interval, CODE_RESEND_INTERVAL)) {
            return CodeSending.TOO_SOON;
        }
        try {
            OneTimeToken token = stepUpCodes.generate(new GenerateOneTimeTokenRequest(codeKey(situation.user())));
            email.sendHtmlMessage(situation.user().getEmail(), "Your verification code",
                    "<p>Your verification code is: <strong style=\"font-size:1.2em;\">" + token.getTokenValue()
                            + "</strong></p><p>It expires in a few minutes. If you did not ask for it, ignore this "
                            + "email.</p>");
            keepAsIssued(sessionContext(request, situation.decisionKey()), token);
            return CodeSending.SENT;
        } catch (RuntimeException e) {
            options.release(interval);
            log.warn("[StepUp] The verification code could not be sent: decisionKey={}, reason={}",
                    situation.decisionKey(), e.getMessage());
            return CodeSending.UNAVAILABLE;
        }
    }

    /** The context a code was mailed for answers for it from now on, with all its answers back. */
    private void keepAsIssued(String context, OneTimeToken token) {
        String earlier = options.take(CODE_ISSUED + context, String.class);
        String issued = fingerprint(token.getTokenValue());
        options.put(CODE_ISSUED + context, earlier != null ? earlier + "," + issued : issued);
        options.clearCount(CODE_ANSWERS + context);
    }

    /** A one-time code answers a verification that waits, or confirms the user for a first passkey (Q-13). */
    private static boolean codeAnswers(@Nullable Situation situation) {
        return situation != null && situation.oneTimeCode()
                && (situation.purpose() != null || situation.passkeyEnrollable());
    }

    /**
     * Checks a one-time code of the user and, when it is the user's, resolves the step-up and confirms the user. The
     * caller is told the same for a wrong code and for a code past the limit, so nothing shows where the limit lies.
     */
    public boolean verifyCode(HttpServletRequest request, Authentication authentication, String code) {
        Situation situation = situation(request, authentication);
        if (!codeAnswers(situation) || code == null || code.isBlank()) {
            return false;
        }
        // Counted before any code is looked at: answers at once look at no more codes than the limit lets through.
        String context = sessionContext(request, situation.decisionKey());
        long answer = options.increment(CODE_ANSWERS + context, StepUpOptionsStore.TIME_TO_LIVE);
        if (answer > maxCodeAnswers) {
            return false;
        }
        OneTimeToken token = options.holds(CODE_DISCARDED + fingerprint(code.trim())) ? null
                : stepUpCodes.consume(OneTimeTokenAuthenticationToken.unauthenticated(code.trim()));
        if (token == null || !codeKey(situation.user()).equals(token.getUsername())) {
            if (answer == maxCodeAnswers) {
                discardCodes(context, situation);
            }
            return false;
        }
        // The token service reads a code before it deletes it, so requests at once can all be handed the same one:
        // the spending is claimed here, once, across nodes when the store is shared.
        if (!options.claim(CODE_SPENT + token.getTokenValue(), CODE_SPENT_HOLD)) {
            return false;
        }
        options.clearCount(CODE_ANSWERS + context);
        if (situation.purpose() != null) {
            complete(request, situation, null);
        }
        options.put(userConfirmedKey(request, situation.decisionKey()), Boolean.TRUE);
        return true;
    }

    /**
     * The context used up its answers: the codes mailed for it stop answering, and a context that asked for none
     * discards nothing, so wrong answers from a stolen cookie spoil no code of the owner's. Only one caller gets here
     * for a count. The wait between two mails is lifted so that a user who typed wrongly gets a new code at once, but
     * once in the life of a code: lifted each time, wrong answers would mail as fast as they can be sent.
     */
    private void discardCodes(String context, Situation situation) {
        log.warn("[StepUp] A session context used up its answers for a code: decisionKey={}", situation.decisionKey());
        String issued = options.take(CODE_ISSUED + context, String.class);
        if (issued == null) {
            return;
        }
        for (String code : issued.split(",")) {
            options.put(CODE_DISCARDED + code, Boolean.TRUE);
        }
        if (options.claim(CODE_RECOVERY + situation.user().getId(), StepUpOptionsStore.TIME_TO_LIVE)) {
            options.release(CODE_SENT + situation.user().getId());
        }
    }

    /** What the store keeps of a code: a code is good for minutes, and only the token service holds it as it is. */
    private static String fingerprint(String code) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(code.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    // ----- passkey -----

    /** The challenge for the user's passkey, kept under the user's decision key until the answer. */
    @Nullable
    public PublicKeyCredentialRequestOptions passkeyOptions(HttpServletRequest request, Authentication authentication) {
        Situation situation = situation(request, authentication);
        if (situation == null || situation.purpose() == null || !situation.passkey() || relyingParty == null) {
            return null;
        }
        PublicKeyCredentialRequestOptions requestOptions = relyingParty.createCredentialRequestOptions(
                new ImmutablePublicKeyCredentialRequestOptionsRequest(asContexaUser(situation.user())));
        options.put(ASSERTION + situation.decisionKey(), requestOptions);
        return requestOptions;
    }

    /** Checks the passkey's answer to the challenge handed out and, when it is the user's passkey, resolves the step-up. */
    public boolean verifyPasskey(HttpServletRequest request, Authentication authentication,
                                 PublicKeyCredential<AuthenticatorAssertionResponse> credential) {
        Situation situation = situation(request, authentication);
        if (situation == null || situation.purpose() == null || !situation.passkey() || relyingParty == null) {
            return false;
        }
        PublicKeyCredentialRequestOptions requestOptions = options.take(ASSERTION + situation.decisionKey(),
                PublicKeyCredentialRequestOptions.class);
        if (requestOptions == null) {
            return false;
        }
        try {
            PublicKeyCredentialUserEntity owner = relyingParty.authenticate(
                    new RelyingPartyAuthenticationRequest(requestOptions, credential));
            if (owner == null || !situation.user().getUsername().equals(owner.getName())) {
                return false;
            }
        } catch (RuntimeException e) {
            log.warn("[StepUp] A passkey answer was refused: decisionKey={}, reason={}", situation.decisionKey(),
                    e.getMessage());
            return false;
        }
        complete(request, situation, null);
        return true;
    }

    /** The options of a first passkey registration; only while no restriction is in force and the user is confirmed. */
    @Nullable
    public PublicKeyCredentialCreationOptions registrationOptions(HttpServletRequest request,
                                                                  Authentication authentication) {
        Situation situation = situation(request, authentication);
        if (situation == null || !situation.passkeyRegistrable() || creationOptionsCodec == null) {
            return null;
        }
        ensureUserEntity(situation.user(), authentication.getName());
        PublicKeyCredentialCreationOptions creationOptions = relyingParty.createPublicKeyCredentialCreationOptions(
                new ImmutablePublicKeyCredentialCreationOptionsRequest(asContexaUser(situation.user())));
        options.put(REGISTRATION + situation.decisionKey(), creationOptionsCodec.encode(creationOptions));
        return creationOptions;
    }

    /** Registers the passkey answering the registration options handed out. */
    public boolean registerPasskey(HttpServletRequest request, Authentication authentication,
                                   PublicKeyCredential<AuthenticatorAttestationResponse> credential, String label) {
        Situation situation = situation(request, authentication);
        if (situation == null || !situation.passkeyRegistrable() || creationOptionsCodec == null) {
            return false;
        }
        PasskeyCreationOptionsState state = options.take(REGISTRATION + situation.decisionKey(),
                PasskeyCreationOptionsState.class);
        if (state == null) {
            return false;
        }
        try {
            relyingParty.registerCredential(new ImmutableRelyingPartyRegistrationRequest(
                    creationOptionsCodec.decode(state),
                    new RelyingPartyPublicKey(credential, label == null || label.isBlank() ? "passkey" : label)));
            options.take(userConfirmedKey(request, situation.decisionKey()), Boolean.class);
            return true;
        } catch (RuntimeException e) {
            log.warn("[StepUp] A passkey registration was refused: decisionKey={}, reason={}", situation.decisionKey(),
                    e.getMessage());
            return false;
        }
    }

    // ----- the application's own re-authentication -----

    @Override
    public boolean resolvedByHostReauthentication(HttpServletRequest request, Authentication authentication,
                                                  String decisionKey) {
        if (!(request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP) instanceof AuthenticationStamp stamp)
                || !Boolean.TRUE.equals(stamp.mfaCompleted()) || stamp.authenticationTime() == null) {
            return false;
        }
        Instant challengedAt = challengedAt(decisionKey);
        if (challengedAt == null || !stamp.authenticationTime().isAfter(challengedAt)) {
            return false;
        }
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        if (!resolution.releaseChallenge(decisionKey, contextBindingHash, request, null)) {
            return false;
        }
        resolution.markMfaVerified(decisionKey, stamp.authenticationTime());
        log.info("[StepUp] The application's re-authentication after the CHALLENGE released it: decisionKey={}",
                decisionKey);
        return true;
    }

    // ----- helpers -----

    private void complete(HttpServletRequest request, Situation situation, @Nullable Instant verifiedAt) {
        if (situation.purpose() == Purpose.BLOCK) {
            resolution.releaseBlockByMfa(situation.decisionKey());
        } else {
            resolution.releaseChallenge(situation.decisionKey(),
                    SessionFingerprintUtil.generateContextBindingHash(request), request, null);
        }
        Instant observedAt = RequestInfoExtractor.extractObservedAt(request);
        resolution.markMfaVerified(situation.decisionKey(),
                verifiedAt != null ? verifiedAt : observedAt != null ? observedAt : Instant.now());
        log.info("[StepUp] Step-up passed: decisionKey={}, purpose={}", situation.decisionKey(), situation.purpose());
    }

    /** The bridge's copy of the application's user; only bridge-managed users, and only one. */
    @Nullable
    private Users bridgedUser(String principal) {
        try {
            List<Users> bridged = users.findByExternalSubjectIdAndBridgeManagedTrue(principal);
            if (bridged.size() == 1) {
                return bridged.get(0);
            }
            if (bridged.size() > 1) {
                log.warn("[StepUp] More than one bridged user for one principal; no step-up factor is offered: "
                        + "principal={}, count={}", principal, bridged.size());
            }
            return null;
        } catch (RuntimeException e) {
            log.error("[StepUp] The bridged user could not be read: principal={}", principal, e);
            return null;
        }
    }

    private boolean hasPasskey(Users user) {
        if (userEntities == null || credentials == null) {
            return false;
        }
        PublicKeyCredentialUserEntity entity = userEntities.findByUsername(user.getUsername());
        return entity != null && !credentials.findByUserId(entity.getId()).isEmpty();
    }

    private boolean canSendCode(Users user) {
        String address = user.getEmail();
        return stepUpCodes != null && email != null && email.isMailSenderConfigured() && address != null
                && address.contains("@")
                && !address.toLowerCase(Locale.ROOT).endsWith("@" + syntheticEmailDomain.toLowerCase(Locale.ROOT));
    }

    private static String codeKey(Users user) {
        return CODE_KEY + user.getId();
    }

    /** The passkey owner shows the application's name of the user, not the bridge's key. */
    private void ensureUserEntity(Users user, String displayName) {
        if (userEntities != null && userEntities.findByUsername(user.getUsername()) == null) {
            userEntities.save(ImmutablePublicKeyCredentialUserEntity.builder()
                    .name(user.getUsername())
                    .id(Bytes.random())
                    .displayName(displayName)
                    .build());
        }
    }

    private static Authentication asContexaUser(Users user) {
        return UsernamePasswordAuthenticationToken.authenticated(user.getUsername(), null, List.of());
    }

    @Nullable
    private Instant challengedAt(String decisionKey) {
        try {
            // Q-12: another session's answer replaced the decision, and this session still has the CHALLENGE to answer.
            Instant heldSince = actions.challengeHeldSince(decisionKey);
            if (heldSince != null) {
                return heldSince;
            }
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = actions.getAnalysisData(decisionKey);
            return analysis != null && analysis.updatedAt() != null ? Instant.parse(analysis.updatedAt()) : null;
        } catch (DateTimeParseException | IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isAgentRequest(HttpServletRequest request) {
        return request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                && stamp.agentId() != null && !stamp.agentId().isBlank();
    }
}
