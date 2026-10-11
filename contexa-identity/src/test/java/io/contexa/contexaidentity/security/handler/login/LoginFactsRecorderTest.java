package io.contexa.contexaidentity.security.handler.login;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacore.security.zerotrust.ZeroTrustAuthenticationToken;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.Date;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The identity module records the facts of each completed login on the authentication, and the bridge reads them as
 * the stamp's standard fields (W1-4).
 */
class LoginFactsRecorderTest {

    private static final List<SimpleGrantedAuthority> ROLES = List.of(new SimpleGrantedAuthority("ROLE_USER"));
    private static final long LOGIN_TIME = 1_791_626_134L;

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aPasswordLoginIsRecordedAsOneFactor() {
        RestAuthenticationToken login = RestAuthenticationToken.authenticated(user("alice"), ROLES);
        Instant before = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        LoginFactsRecorder.recordSingleFactor(login, new MockHttpServletRequest());

        LoginFactsDetails facts = (LoginFactsDetails) login.getDetails();
        assertThat(facts.getAuthenticationType()).isEqualTo("PASSWORD");
        assertThat(facts.getAmr()).containsExactly("pwd");
        assertThat(facts.getMfaCompleted()).isFalse();
        assertThat(facts.getAuthenticationAssurance()).isEqualTo("AAL1");
        assertThat(facts.getPrincipalType()).isEqualTo("HUMAN_USER");
        assertThat(facts.getAuthenticationTime()).isAfterOrEqualTo(before);
    }

    @Test
    void eachLoginFlowNamesItsOwnMethod() {
        OneTimeTokenAuthenticationToken ott = OneTimeTokenAuthenticationToken.authenticated(user("bob"), ROLES);
        LoginFactsRecorder.recordSingleFactor(ott, null);
        assertThat(((LoginFactsDetails) ott.getDetails()).getAuthenticationType()).isEqualTo("ONE_TIME_CODE");

        ZeroTrustAuthenticationToken adjusted = new ZeroTrustAuthenticationToken(
                "carol", null, ROLES, 1.0, 0.0, null);
        LoginFactsRecorder.recordSingleFactor(adjusted, null);
        assertThat(adjusted.getDetails()).isNull();
    }

    @Test
    void anMfaLoginRecordsTheFirstStepAndEveryVerifiedFactor() {
        UsernamePasswordAuthenticationToken primary = UsernamePasswordAuthenticationToken.authenticated(
                user("dave"), null, ROLES);
        FactorContext factorContext = new FactorContext("mfa-1", primary, MfaState.NONE, "mfa");
        factorContext.addCompletedFactor(new AuthenticationStepConfig("mfa", "MFA_OTT", 1, false));
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("dave"), ROLES);

        LoginFactsRecorder.recordFinal(last, new MockHttpServletRequest(), factorContext);

        LoginFactsDetails facts = (LoginFactsDetails) last.getDetails();
        assertThat(facts.getAuthenticationType()).isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(facts.getAmr()).containsExactly("pwd", "otp", "mfa");
        assertThat(facts.getMfaCompleted()).isTrue();
        assertThat(facts.getAuthenticationAssurance()).isEqualTo("AAL2");
    }

    @Test
    void anMfaFlowEndingWithoutAFactorIsAOneFactorLogin() {
        RestAuthenticationToken primary = RestAuthenticationToken.authenticated(user("erin"), ROLES);
        FactorContext factorContext = new FactorContext("mfa-2", primary, MfaState.NONE, "mfa");

        LoginFactsRecorder.recordFinal(primary, null, factorContext);

        assertThat(((LoginFactsDetails) primary.getDetails()).getMfaCompleted()).isFalse();
        assertThat(((LoginFactsDetails) primary.getDetails()).getAuthenticationType()).isEqualTo("PASSWORD");
    }

    @Test
    void theBridgeReadsTheRecordedFactsAsExplicitStandardFields() {
        UsernamePasswordAuthenticationToken primary = UsernamePasswordAuthenticationToken.authenticated(
                user("frank"), null, ROLES);
        FactorContext factorContext = new FactorContext("mfa-3", primary, MfaState.NONE, "mfa");
        factorContext.addCompletedFactor(new AuthenticationStepConfig("mfa", "MFA_OTT", 1, false));
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("frank"), ROLES);
        LoginFactsRecorder.recordFinal(last, null, factorContext);
        SecurityContextHolder.getContext().setAuthentication(last);

        AuthenticationStamp stamp = new SecurityContextAuthenticationStampResolver()
                .resolve(null, snapshot(), new BridgeProperties()).orElseThrow();

        // The principal is the account, not the per-login identifier the facts carry (P2 correction 7).
        assertThat(stamp.principalId()).isEqualTo("frank");
        assertThat(stamp.authenticationType()).isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(stamp.mfaCompleted()).isTrue();
        assertThat(stamp.authenticationAssurance()).isEqualTo("AAL2");
        assertThat(stamp.principalType()).isEqualTo("HUMAN_USER");
        assertThat(stamp.authenticationTime()).isEqualTo(((LoginFactsDetails) last.getDetails()).getAuthenticationTime());
        assertThat(stamp.attributes())
                .containsEntry("authenticationTypeEvidenceState", "EXPLICIT_CUSTOMER_SIGNAL")
                .containsEntry("mfaCompletedEvidenceState", "EXPLICIT_CUSTOMER_SIGNAL")
                .containsEntry("principalTypeEvidenceState", "EXPLICIT_CUSTOMER_SIGNAL");
    }

    @Test
    void aPassedChallengeKeepsTheLoginAndAddsItsTime() {
        RestAuthenticationToken session = RestAuthenticationToken.authenticated(user("ivan"), ROLES);
        LoginFactsRecorder.recordSingleFactor(session, null);
        LoginFactsDetails login = (LoginFactsDetails) session.getDetails();
        FactorContext challenge = new FactorContext("mfa-4", session, MfaState.NONE, "mfa");
        challenge.setAttribute("challengeInitiated", true);
        challenge.addCompletedFactor(new AuthenticationStepConfig("mfa", "MFA_OTT", 1, false));
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("ivan"), ROLES);

        LoginFactsRecorder.recordFinal(last, null, challenge);

        LoginFactsDetails facts = (LoginFactsDetails) last.getDetails();
        assertThat(facts.getAuthenticationType()).isEqualTo("PASSWORD");
        assertThat(facts.getAuthenticationTime()).isEqualTo(login.getAuthenticationTime());
        assertThat(facts.getAuthenticationAssurance()).isEqualTo("AAL1");
        assertThat(facts.getMfaCompleted()).isTrue();
        assertThat(facts.getChallengeVerifiedAt()).isNotNull();
    }

    @Test
    void aChallengeWithoutRecordedLoginFactsLeavesTheLoginUnknown() {
        UsernamePasswordAuthenticationToken session = UsernamePasswordAuthenticationToken.authenticated(
                user("judy"), null, ROLES);
        FactorContext challenge = new FactorContext("mfa-5", session, MfaState.NONE, "mfa");
        challenge.setAttribute("challengeInitiated", true);
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("judy"), ROLES);

        LoginFactsRecorder.recordFinal(last, null, challenge);

        LoginFactsDetails facts = (LoginFactsDetails) last.getDetails();
        assertThat(facts.getAuthenticationType()).isNull();
        assertThat(facts.getAuthenticationTime()).isNull();
        assertThat(facts.getMfaCompleted()).isTrue();
        assertThat(facts.getChallengeVerifiedAt()).isNotNull();
    }

    @Test
    void theFactsSurviveSessionSerialization() throws Exception {
        RestAuthenticationToken login = RestAuthenticationToken.authenticated(user("gina"), ROLES);
        LoginFactsRecorder.recordSingleFactor(login, new MockHttpServletRequest());

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(login.getDetails());
        }
        Object restored;
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            restored = in.readObject();
        }

        assertThat(restored).isEqualTo(login.getDetails());
        assertThat(((LoginFactsDetails) restored).getAmr()).containsExactly("pwd");
    }

    @Test
    void theFactsBecomeStandardTokenClaims() {
        UsernamePasswordAuthenticationToken login = UsernamePasswordAuthenticationToken.authenticated(
                user("hank"), null, ROLES);
        LoginFactsRecorder.recordSingleFactor(login, null);
        Instant time = ((LoginFactsDetails) login.getDetails()).getAuthenticationTime();

        Map<String, String> facts = LoginFactClaims.of(login);
        assertThat(facts).containsEntry("auth_time", String.valueOf(time.getEpochSecond()))
                .containsEntry("amr", "pwd")
                .containsEntry("acr", "AAL1");

        Map<String, Object> claims = new LinkedHashMap<>();
        LoginFactClaims.writeClaims(facts, claims::put);
        // auth_time is a Date, the type the token engine writes it in (epoch seconds in the token).
        assertThat(claims).containsEntry("auth_time", Date.from(Instant.ofEpochSecond(time.getEpochSecond())))
                .containsEntry("amr", List.of("pwd"))
                .containsEntry("acr", "AAL1");
    }

    private static User user(String name) {
        return new User(name, "n/a", ROLES);
    }

    private static RequestContextSnapshot snapshot() {
        return new RequestContextSnapshot("/api/x", "GET", "127.0.0.1", "JUnit", null, "request-1", "/api/x",
                null, false, Instant.now());
    }

    @Test
    void eachLoginHasItsOwnIdentifierCarriedAsTheTokenSession() {
        UsernamePasswordAuthenticationToken first = UsernamePasswordAuthenticationToken.authenticated(user("iris"), null, ROLES);
        UsernamePasswordAuthenticationToken second = UsernamePasswordAuthenticationToken.authenticated(user("iris"), null, ROLES);
        LoginFactsRecorder.recordSingleFactor(first, null);
        LoginFactsRecorder.recordSingleFactor(second, null);
        String loginId = ((LoginFactsDetails) first.getDetails()).getSignInId();

        assertThat(loginId).matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        assertThat(((LoginFactsDetails) second.getDetails()).getSignInId()).isNotEqualTo(loginId);

        Map<String, String> facts = LoginFactClaims.of(first);
        assertThat(facts).containsEntry("sid", loginId);
        Map<String, Object> claims = new LinkedHashMap<>();
        LoginFactClaims.writeClaims(facts, claims::put);
        assertThat(claims).containsEntry("sid", loginId);
    }

    @Test
    void aPassedChallengeKeepsTheLoginIdentifier() {
        UsernamePasswordAuthenticationToken login = UsernamePasswordAuthenticationToken.authenticated(user("jack"), null, ROLES);
        LoginFactsRecorder.recordSingleFactor(login, null);
        LoginFactsDetails facts = (LoginFactsDetails) login.getDetails();

        LoginFactsDetails challenged = LoginFactsDetails.challengeVerified(null, null, facts, Instant.now());

        assertThat(challenged.getSignInId()).isEqualTo(facts.getSignInId());
    }

    @Test
    void aChallengeOnATokenRequestKeepsTheLoginTheTokenStates() {
        Jwt token = loginToken("kate", "login-7");
        // The bearer authentication, and the same token after Zero Trust re-wrapped it for the CHALLENGE.
        List<Authentication> challengedRequests = List.of(new JwtAuthenticationToken(token, ROLES),
                new ZeroTrustAuthenticationToken(token, null, ROLES, 0.5, 0.5, ZeroTrustAction.CHALLENGE));
        for (Authentication challenged : challengedRequests) {
            FactorContext challenge = new FactorContext("mfa-6", challenged, MfaState.NONE, "mfa");
            challenge.setAttribute("challengeInitiated", true);
            OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("kate"), ROLES);

            LoginFactsRecorder.recordFinal(last, null, challenge);

            LoginFactsDetails facts = (LoginFactsDetails) last.getDetails();
            assertThat(facts.getSignInId()).isEqualTo("login-7");
            assertThat(facts.getAuthenticationTime()).isEqualTo(Instant.ofEpochSecond(LOGIN_TIME));
            assertThat(facts.getAuthenticationType()).isEqualTo("PASSWORD");
            assertThat(facts.getAmr()).containsExactly("pwd");
            assertThat(facts.getAuthenticationAssurance()).isEqualTo("AAL1");
            assertThat(facts.getPrincipalType()).isEqualTo("HUMAN_USER");
            assertThat(facts.getMfaCompleted()).isTrue();
            assertThat(facts.getChallengeVerifiedAt()).isNotNull();
        }
    }

    @Test
    void theTokenOfAPassedChallengeStatesTheLoginAndTheChallenge() {
        FactorContext challenge = new FactorContext("mfa-7", new JwtAuthenticationToken(loginToken("liam", "login-8"),
                ROLES), MfaState.NONE, "mfa");
        challenge.setAttribute("challengeInitiated", true);
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("liam"), ROLES);
        LoginFactsRecorder.recordFinal(last, null, challenge);
        Instant verifiedAt = ((LoginFactsDetails) last.getDetails()).getChallengeVerifiedAt();

        Map<String, String> facts = LoginFactClaims.of(last);
        assertThat(facts).containsEntry("auth_time", String.valueOf(LOGIN_TIME))
                .containsEntry("amr", "pwd")
                .containsEntry("acr", "AAL1")
                .containsEntry("sid", "login-8")
                .containsEntry("principalType", "HUMAN_USER")
                .containsEntry("mfaCompleted", "true")
                .containsEntry("challengeVerifiedAt", verifiedAt.toString());

        Map<String, Object> claims = new LinkedHashMap<>();
        LoginFactClaims.writeClaims(facts, claims::put);
        assertThat(claims).containsEntry("auth_time", Date.from(Instant.ofEpochSecond(LOGIN_TIME)))
                .containsEntry("sid", "login-8")
                .containsEntry("principalType", "HUMAN_USER")
                .containsEntry("mfaCompleted", Boolean.TRUE)
                .containsEntry("challengeVerifiedAt", verifiedAt.toString());
    }

    @Test
    void aChallengeWithoutLoginFactsGivesTheTokenNoLoginTime() {
        UsernamePasswordAuthenticationToken session = UsernamePasswordAuthenticationToken.authenticated(
                user("mona"), null, ROLES);
        FactorContext challenge = new FactorContext("mfa-8", session, MfaState.NONE, "mfa");
        challenge.setAttribute("challengeInitiated", true);
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(user("mona"), ROLES);
        LoginFactsRecorder.recordFinal(last, null, challenge);

        Map<String, String> facts = LoginFactClaims.of(last);

        assertThat(facts).doesNotContainKeys("auth_time", "amr", "acr")
                .containsKeys("sid", "challengeVerifiedAt")
                .containsEntry("principalType", "HUMAN_USER")
                .containsEntry("mfaCompleted", "true");
    }

    @Test
    void theBridgeReadsTheTokenOfAPassedChallengeAsTheSessionStatesIt() {
        String verifiedAt = "2026-10-10T09:55:38.126512300Z";
        // The claims as a decoded token holds them: auth_time in epoch seconds.
        Jwt token = Jwt.withTokenValue("token").header("alg", "RS256").subject("nina")
                .claim("auth_time", LOGIN_TIME).claim("amr", List.of("pwd")).claim("acr", "AAL1").claim("sid", "login-9")
                .claim("principalType", "HUMAN_USER").claim("mfaCompleted", true).claim("challengeVerifiedAt", verifiedAt)
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(token, ROLES));

        AuthenticationStamp stamp = new SecurityContextAuthenticationStampResolver()
                .resolve(null, snapshot(), new BridgeProperties()).orElseThrow();

        assertThat(stamp.authenticationType()).isEqualTo("PASSWORD");
        assertThat(stamp.mfaCompleted()).isTrue();
        assertThat(stamp.authenticationAssurance()).isEqualTo("AAL1");
        assertThat(stamp.principalType()).isEqualTo("HUMAN_USER");
        assertThat(stamp.authenticationTime()).isEqualTo(Instant.ofEpochSecond(LOGIN_TIME));
        assertThat(stamp.attributes())
                .containsEntry("challengeVerifiedAt", verifiedAt)
                .containsEntry("mfaCompletedEvidenceState", "EXPLICIT_CUSTOMER_SIGNAL")
                .containsEntry("principalTypeEvidenceState", "EXPLICIT_CUSTOMER_SIGNAL");
    }

    private static Jwt loginToken(String subject, String loginId) {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject(subject)
                .claim("auth_time", LOGIN_TIME).claim("amr", List.of("pwd")).claim("acr", "AAL1").claim("sid", loginId)
                .claim("principalType", "HUMAN_USER")
                .build();
    }
}
