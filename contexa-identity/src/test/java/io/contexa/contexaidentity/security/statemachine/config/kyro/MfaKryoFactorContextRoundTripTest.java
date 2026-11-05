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
package io.contexa.contexaidentity.security.statemachine.config.kyro;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.authentication.BridgePrincipal;
import io.contexa.contexacore.security.zerotrust.ZeroTrustAuthenticationToken;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import io.contexa.contexaidentity.security.handler.login.LoginFactClaims;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.scaffold.subclass.ConstructorStrategy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;

import java.io.Serializable;
import java.lang.reflect.RecordComponent;
import java.math.BigDecimal;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * PR-80: what a distributed deployment keeps of an MFA flow, written by one node and read by another. The flow of every
 * kind of sign-in has to come back, whatever the application's objects in the sign-in are made of.
 */
public class MfaKryoFactorContextRoundTripTest {

    private static final List<GrantedAuthority> ROLES = List.of(new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_VET"));
    private static final String USERNAME = "alice";
    private static final String PASSWORD_HASH = "{bcrypt}$2a$10$the-hash-of-the-password";
    private static final long LOGIN_TIME = 1_760_000_000L;
    private static final String APP_PACKAGE = "com.customer.app.";
    private static final String HTTP_SESSION = "the-servlet-session";

    private final MfaKryoStateMachineSerialisationService writingNode = new MfaKryoStateMachineSerialisationService();
    private final MfaKryoStateMachineSerialisationService readingNode = new MfaKryoStateMachineSerialisationService();

    static Stream<Named<Authentication>> everyKindOfSignIn() {
        return Stream.of(
                named("form login", withLoginFacts(
                        UsernamePasswordAuthenticationToken.authenticated(contexaUser(), null, ROLES), "PASSWORD")),
                named("REST login", withLoginFacts(RestAuthenticationToken.authenticated(contexaUser(), ROLES), "PASSWORD")),
                named("one-time token", withLoginFacts(
                        OneTimeTokenAuthenticationToken.authenticated(contexaUser(), ROLES), "ONE_TIME_CODE")),
                named("one-time token of Spring's User", withLoginFacts(
                        OneTimeTokenAuthenticationToken.authenticated(springUser(), ROLES), "ONE_TIME_CODE")),
                named("passkey", withLoginFacts(new WebAuthnAuthentication(passkeyUser(), ROLES), "PASSKEY")),
                named("OAuth2 login with OIDC", oidcLogin()),
                named("OAuth2 login", oauth2Login()),
                named("JWT", new JwtAuthenticationToken(loginToken(), ROLES)),
                named("opaque bearer token", opaqueToken()),
                named("bridge user", bridgeUser()),
                named("Zero Trust adjusted", zeroTrustAdjusted(contexaUser())),
                named("Zero Trust adjusted JWT", zeroTrustAdjusted(loginToken())),
                named("remember-me", new RememberMeAuthenticationToken("key", contexaUser(), ROLES)),
                named("pre-authenticated", new PreAuthenticatedAuthenticationToken(contexaUser(), "n/a", ROLES)),
                named("a name that is not ASCII", OneTimeTokenAuthenticationToken.authenticated("김앨리스@예제.한국", ROLES)),
                named("the application's user", OneTimeTokenAuthenticationToken.authenticated(new AppUser(), ROLES)),
                named("the application's user that refers to itself",
                        OneTimeTokenAuthenticationToken.authenticated(new CyclicAppUser(), ROLES)),
                named("the application's own authentication", new AppAuthentication()),
                named("an authentication that is not authenticated", new UnauthenticatedAppToken()));
    }

    @ParameterizedTest
    @MethodSource("everyKindOfSignIn")
    void theFlowOfEveryKindOfSignInComesBack(Authentication signIn) throws Exception {
        FactorContext written = aChallengeInProgress(signIn);

        FactorContext restored = roundTrip(written);

        assertSameFlow(restored, written);
        assertSameSignIn(restored, written);
    }

    @ParameterizedTest
    @MethodSource("everyKindOfSignIn")
    void everyStepWritesTheFlowAgainAndNothingIsLost(Authentication signIn) throws Exception {
        FactorContext written = aChallengeInProgress(signIn);

        FactorContext restored = roundTrip(roundTrip(roundTrip(written)));

        assertSameFlow(restored, written);
        assertSameSignIn(restored, written);
    }

    @Test
    void theLoginOfAnMfaFlowStaysTheMethodsItWasMadeOf() throws Exception {
        Authentication primary = withLoginFacts(RestAuthenticationToken.authenticated(contexaUser(), ROLES), "PASSWORD");
        FactorContext login = new FactorContext("login-flow", primary, MfaState.NONE, "mfa");
        login.addCompletedFactor(new AuthenticationStepConfig("mfa", "MFA_OTT", 1, false));

        FactorContext restored = roundTrip(login);

        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(USERNAME, ROLES);
        LoginFactsRecorder.recordFinal(last, null, restored);
        assertThat(((LoginFactsDetails) last.getDetails()).getAuthenticationType()).isEqualTo("PASSWORD+ONE_TIME_CODE");
    }

    @Test
    @DisplayName("the application's user class may be gone where the flow is read (another node, a redeploy, a dev reloader)")
    void aUserClassTheReadingNodeCannotLoadLeavesTheFlowIntact() throws Exception {
        Authentication signIn = OneTimeTokenAuthenticationToken.authenticated(
                instanceOfALostClass(AppUser.class, "LostAppUser"), ROLES);
        FactorContext written = aChallengeInProgress(signIn);

        FactorContext restored = roundTrip(written);

        assertSameFlow(restored, written);
        assertSameSignIn(restored, written);
    }

    @Test
    void anAuthenticationClassTheReadingNodeCannotLoadLeavesTheFlowIntact() throws Exception {
        Authentication signIn = instanceOfALostClass(AppAuthentication.class, "LostAppAuthentication");
        FactorContext written = aChallengeInProgress(signIn);

        FactorContext restored = roundTrip(written);

        assertSameFlow(restored, written);
        assertSameSignIn(restored, written);
    }

    @ParameterizedTest
    @MethodSource("everyKindOfSignIn")
    void noCredentialAndNoObjectOfTheApplicationIsStored(Authentication signIn) throws Exception {
        String stored = new String(write(aChallengeInProgress(signIn)), StandardCharsets.ISO_8859_1);

        assertThat(stored).doesNotContain(withoutLastCharacter(PASSWORD_HASH),
                withoutLastCharacter(AppUser.class.getSimpleName()), withoutLastCharacter("alice@example.org"),
                withoutLastCharacter(HTTP_SESSION));
        assertThat(restoredCredentials(signIn)).isNull();
    }

    @Test
    void anAuthorityWithoutATextDoesNotMakeTheFlowUnreadable() throws Exception {
        List<GrantedAuthority> authorities = new ArrayList<>(ROLES);
        authorities.add(() -> null);
        Authentication signIn = UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, authorities);

        FactorContext restored = roundTrip(aChallengeInProgress(signIn));

        assertThat(authorityNames(restored.getPrimaryAuthentication())).containsExactlyInAnyOrder("ROLE_USER", "ROLE_VET");
    }

    @Test
    void flowsWrittenAndReadAtTheSameTimeStayApart() throws Exception {
        ExecutorService requests = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> finished = new ArrayList<>();
            for (int request = 0; request < 400; request++) {
                String username = "user-" + request;
                finished.add(requests.submit(() -> {
                    Authentication signIn = OneTimeTokenAuthenticationToken.authenticated(username, ROLES);
                    FactorContext written = aChallengeInProgress(signIn);
                    written.setAttribute("owner", Set.of(username));
                    FactorContext restored = roundTrip(written);
                    assertThat(restored.getPrimaryAuthentication().getName()).isEqualTo(username);
                    assertThat(restored.getAttribute("owner")).isEqualTo(Set.of(username));
                    return null;
                }));
            }
            for (Future<?> request : finished) {
                request.get();
            }
        } finally {
            requests.shutdownNow();
        }
    }

    static Stream<Arguments> everyCollectionAnAttributeCanHold() {
        return Stream.of(
                arguments(named("unmodifiableCollection", Collections.unmodifiableCollection(new ArrayList<>(List.of("a", "b"))))),
                arguments(named("unmodifiableList of an ArrayList", Collections.unmodifiableList(new ArrayList<>(List.of("a", "b"))))),
                arguments(named("unmodifiableList of a LinkedList", Collections.unmodifiableList(new LinkedList<>(List.of("a", "b"))))),
                arguments(named("unmodifiableSet", Collections.unmodifiableSet(new LinkedHashSet<>(List.of("a", "b"))))),
                arguments(named("unmodifiableSortedSet", Collections.unmodifiableSortedSet(new TreeSet<>(List.of("a", "b"))))),
                arguments(named("unmodifiableNavigableSet", Collections.unmodifiableNavigableSet(new TreeSet<>(List.of("a", "b"))))),
                arguments(named("unmodifiableMap", Collections.unmodifiableMap(new LinkedHashMap<>(Map.of("a", 1))))),
                arguments(named("unmodifiableSortedMap", Collections.unmodifiableSortedMap(new TreeMap<>(Map.of("a", 1))))),
                arguments(named("unmodifiableNavigableMap", Collections.unmodifiableNavigableMap(new TreeMap<>(Map.of("a", 1))))),
                arguments(named("List.of()", List.of())),
                arguments(named("List.of(a)", List.of("a"))),
                arguments(named("List.of(a, b)", List.of("a", "b"))),
                arguments(named("List.of(a, b, c)", List.of("a", "b", "c"))),
                arguments(named("Set.of()", Set.of())),
                arguments(named("Set.of(a)", Set.of("a"))),
                arguments(named("Set.of(a, b)", Set.of("a", "b"))),
                arguments(named("Set.of(a, b, c)", Set.of("a", "b", "c"))),
                arguments(named("Map.of()", Map.of())),
                arguments(named("Map.of(a, 1)", Map.of("a", 1))),
                arguments(named("Map.of(a, 1, b, 2)", Map.of("a", 1, "b", 2))),
                arguments(named("List.copyOf", List.copyOf(new ArrayList<>(List.of("a", "b"))))),
                arguments(named("Set.copyOf", Set.copyOf(new HashSet<>(List.of("a", "b"))))),
                arguments(named("Map.copyOf", Map.copyOf(new HashMap<>(Map.of("a", 1))))),
                arguments(named("Stream.toList", Stream.of("a", "b").toList())),
                arguments(named("toUnmodifiableList", Stream.of("a", "b").collect(Collectors.toUnmodifiableList()))),
                arguments(named("toUnmodifiableSet", Stream.of("a", "b").collect(Collectors.toUnmodifiableSet()))),
                arguments(named("emptyList", Collections.emptyList())),
                arguments(named("emptySet", Collections.emptySet())),
                arguments(named("emptyMap", Collections.emptyMap())),
                arguments(named("emptySortedSet", Collections.emptySortedSet())),
                arguments(named("emptyNavigableSet", Collections.emptyNavigableSet())),
                arguments(named("emptySortedMap", Collections.emptySortedMap())),
                arguments(named("emptyNavigableMap", Collections.emptyNavigableMap())),
                arguments(named("singletonList", Collections.singletonList("a"))),
                arguments(named("singleton", Collections.singleton("a"))),
                arguments(named("singletonMap", Collections.singletonMap("a", 1))),
                arguments(named("Arrays.asList", Arrays.asList("a", "b"))),
                arguments(named("EnumSet", EnumSet.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY))),
                arguments(named("nested in a mutable list", new ArrayList<>(List.of(
                        Collections.unmodifiableSet(new HashSet<>(List.of("a"))), Set.of("b"))))),
                arguments(named("nested in each other", Map.of("roles", List.of(Set.of("a")), "more",
                        Collections.unmodifiableMap(new HashMap<>(Map.of("k", Collections.singletonList("v"))))))));
    }

    @ParameterizedTest
    @MethodSource("everyCollectionAnAttributeCanHold")
    void anAttributeHoldingAJdkCollectionComesBack(Object value) throws Exception {
        FactorContext written = aChallengeInProgress(UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, ROLES));
        written.setAttribute("value", value);

        Object restored = roundTrip(written).getAttribute("value");

        assertThat(restored).isNotNull();
        assertSameContents(restored, value);
    }

    @Test
    void anAttributeOfAClassTheReadingNodeCannotLoadIsLeftOutAndTheFlowStays() throws Exception {
        FactorContext written = aChallengeInProgress(UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, ROLES));
        written.setAttribute("appRisk", instanceOfALostClass(AppRisk.class, "LostAppRisk"));

        FactorContext restored = roundTrip(written);

        assertThat(restored.getAttribute("appRisk")).isNull();
        written.removeAttribute("appRisk");
        assertSameFlow(restored, written);
    }

    private static Named<Serializable> value(String name, Serializable value) {
        return named(name, value);
    }

    static Stream<Named<Serializable>> plainValues() {
        return Stream.of(
                value("UUID", UUID.fromString("0e3bdc4c-9f5e-4c6f-8a53-0d1f6c2f3a11")),
                value("Instant", Instant.ofEpochSecond(LOGIN_TIME)),
                value("LocalDateTime", LocalDateTime.of(2026, 11, 5, 18, 55)),
                value("Duration", Duration.ofMinutes(5)),
                value("BigDecimal", new BigDecimal("0.85")),
                value("Locale", Locale.KOREA),
                value("an enum", AuthType.MFA_OTT),
                value("a record", new BridgePrincipal(USERNAME, "ext-7", "Alice", "HUMAN_USER", null, null, null, null,
                        7L, "bridge-key", true, false)));
    }

    @ParameterizedTest
    @MethodSource("plainValues")
    void anAttributeHoldingAPlainValueComesBack(Serializable value) throws Exception {
        FactorContext written = aChallengeInProgress(UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, ROLES));
        written.setAttribute("value", value);

        assertThat(roundTrip(written).getAttribute("value")).isEqualTo(value);
    }

    static Stream<Named<Serializable>> valuesThatAreNotOurs() {
        Map<AuthType, String> enumMap = new EnumMap<>(AuthType.class);
        enumMap.put(AuthType.MFA_OTT, "a");
        return Stream.of(
                value("a read-only set of the application", new ReadOnlyAppSet()),
                value("EnumMap", (Serializable) enumMap),
                value("synchronizedList", (Serializable) Collections.synchronizedList(new ArrayList<>(List.of("a")))),
                value("synchronizedMap", (Serializable) Collections.synchronizedMap(new HashMap<>(Map.of("a", 1)))),
                value("checkedList", (Serializable) Collections.checkedList(new ArrayList<>(List.of("a")), String.class)),
                value("a key set view", ConcurrentHashMap.newKeySet()));
    }

    /** Whether such a value comes back is its own affair; it never takes the flow with it. */
    @ParameterizedTest
    @MethodSource("valuesThatAreNotOurs")
    void anAttributeThatCannotBeRebuiltNeverTakesTheFlowWithIt(Serializable value) throws Exception {
        FactorContext written = aChallengeInProgress(UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, ROLES));
        written.setAttribute("value", value);

        FactorContext restored = roundTrip(written);

        written.removeAttribute("value");
        restored.removeAttribute("value");
        assertSameFlow(restored, written);
    }

    @Test
    void anAttributeThatCannotBeWrittenIsLeftOutAndTheFlowStays() throws Exception {
        ArrayList<Object> holdsItself = new ArrayList<>();
        holdsItself.add(holdsItself);
        FactorContext written = aChallengeInProgress(UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, ROLES));
        written.setAttribute("appCycle", holdsItself);

        FactorContext restored = roundTrip(written);

        assertThat(restored.getAttribute("appCycle")).isNull();
        written.removeAttribute("appCycle");
        assertSameFlow(restored, written);
        // The Kryo of the node that failed on the value goes back to its pool and has to keep working.
        assertSameFlow(roundTrip(written), written);
    }

    private FactorContext roundTrip(FactorContext context) throws Exception {
        StateMachineContext<MfaState, MfaEvent> read = readingNode.deserialiseStateMachineContext(write(context));
        assertThat(read.getState()).isEqualTo(context.getCurrentState());
        return StateContextHelper.getFactorContext(read.getExtendedState());
    }

    private byte[] write(FactorContext context) throws Exception {
        DefaultExtendedState extendedState = new DefaultExtendedState();
        StateContextHelper.setFactorContext(extendedState, context);
        return writingNode.serialiseStateMachineContext(new DefaultStateMachineContext<>(
                context.getCurrentState(), null, null, extendedState, null, context.getMfaSessionId()));
    }

    /** Kryo marks the end of a text in its last character, so the stored form of a whole text differs there. */
    private static String withoutLastCharacter(String text) {
        return text.substring(0, text.length() - 1);
    }

    private Object restoredCredentials(Authentication signIn) throws Exception {
        return roundTrip(aChallengeInProgress(signIn)).getPrimaryAuthentication().getCredentials();
    }

    /** A step-up in the middle of its second attempt, with every field and every attribute kind a flow holds. */
    private static FactorContext aChallengeInProgress(Authentication signIn) {
        FactorContext context = new FactorContext("mfa-session", signIn, MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION, "mfa");
        context.setStateConfig(new StateConfig("session", StateType.SESSION));
        context.setMfaRequiredAsPerPolicy(true);
        context.setCurrentProcessingFactor(AuthType.MFA_OTT);
        context.setCurrentStepId("mfa:mfa_ott:1");
        context.setRetryCount(1);
        context.setLastError("wrong code");
        context.setVersion(7);
        context.addCompletedFactor(new AuthenticationStepConfig("mfa", "MFA_PASSKEY", 2, false));
        context.incrementAttemptCount(AuthType.MFA_OTT);
        context.incrementFailedAttempts("mfa:mfa_ott:1");
        context.recordAttempt(AuthType.MFA_OTT, false, "Verification failed");
        context.setAttribute("challengeInitiated", true);
        context.setAttribute("challengeReason", "ZERO_TRUST_ADAPTIVE");
        context.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS,
                new LinkedHashSet<>(List.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY)));
        context.setAttribute("requiredFactors", new ArrayList<>(List.of("MFA_OTT")));
        context.setAttribute(FactorContextAttributes.Timestamps.LOGIN_TIMESTAMP, 1_760_000_123_456L);
        context.setAttribute(FactorContextAttributes.Policy.RISK_SCORE, 0.8d);
        context.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION, MfaEvent.INITIATE_CHALLENGE_AUTO);
        context.setAttribute("action", ZeroTrustAction.CHALLENGE);
        context.setAttribute("retryCount_MFA_OTT", 1);
        return context;
    }

    private static void assertSameFlow(FactorContext restored, FactorContext written) {
        assertThat(restored.getMfaSessionId()).isEqualTo(written.getMfaSessionId());
        assertThat(restored.getCurrentState()).isEqualTo(written.getCurrentState());
        assertThat(restored.getUsername()).isEqualTo(written.getUsername());
        assertThat(restored.getVersion()).isEqualTo(written.getVersion());
        assertThat(restored.getFlowTypeName()).isEqualTo(written.getFlowTypeName());
        assertThat(restored.getStateConfig()).isEqualTo(written.getStateConfig());
        assertThat(restored.isMfaRequiredAsPerPolicy()).isEqualTo(written.isMfaRequiredAsPerPolicy());
        assertThat(restored.getCurrentProcessingFactor()).isEqualTo(written.getCurrentProcessingFactor());
        assertThat(restored.getCurrentStepId()).isEqualTo(written.getCurrentStepId());
        assertThat(restored.getRetryCount()).isEqualTo(written.getRetryCount());
        assertThat(restored.getLastError()).isEqualTo(written.getLastError());
        assertThat(restored.getCreatedAt()).isEqualTo(written.getCreatedAt());
        assertThat(restored.getLastActivityTimestamp()).isEqualTo(written.getLastActivityTimestamp());
        assertThat(restored.getCompletedFactors()).isEqualTo(written.getCompletedFactors());
        assertThat(restored.getAttemptCount(AuthType.MFA_OTT)).isEqualTo(written.getAttemptCount(AuthType.MFA_OTT));
        assertThat(restored.getFailedAttempts("mfa:mfa_ott:1")).isEqualTo(written.getFailedAttempts("mfa:mfa_ott:1"));
        assertThat(restored.getMfaAttemptHistory()).hasSameSizeAs(written.getMfaAttemptHistory());
        assertThat(restored.getMfaAttemptHistory().get(0).getDetail()).isEqualTo(written.getMfaAttemptHistory().get(0).getDetail());
        assertThat(restored.getAvailableFactors()).containsExactlyElementsOf(written.getAvailableFactors());
        written.getAttributes().forEach((key, value) -> assertSameContents(restored.getAttribute(key), value));
        // The locks are not stored: the restored flow has to be able to take them.
        assertThat(restored.getNumberOfCompletedFactors()).isEqualTo(written.getNumberOfCompletedFactors());
        restored.changeState(restored.getCurrentState());
    }

    private static void assertSameSignIn(FactorContext restored, FactorContext written) {
        Authentication restoredSignIn = restored.getPrimaryAuthentication();
        Authentication writtenSignIn = written.getPrimaryAuthentication();
        assertThat(restoredSignIn.getName()).isEqualTo(writtenSignIn.getName());
        assertThat(authorityNames(restoredSignIn)).containsExactlyInAnyOrderElementsOf(authorityNames(writtenSignIn));
        assertThat(restoredSignIn.isAuthenticated()).isEqualTo(writtenSignIn.isAuthenticated());
        assertThat(restoredSignIn.getCredentials()).isNull();
        assertThat(loginAfterTheChallenge(restored)).isEqualTo(loginAfterTheChallenge(written));
    }

    /** What the session's facts say of the login once this flow's challenge is passed. */
    private static Map<String, String> loginAfterTheChallenge(FactorContext challenge) {
        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(USERNAME, ROLES);
        LoginFactsRecorder.recordFinal(last, null, challenge);
        Map<String, String> facts = new HashMap<>(LoginFactClaims.of(last));
        facts.remove("challengeVerifiedAt");
        if (!facts.containsKey("auth_time")) {
            // A login that left no facts gets a new identifier each time it is read.
            facts.remove("sid");
        }
        return facts;
    }

    private static void assertSameContents(Object restored, Object written) {
        if (written instanceof Set<?> || written instanceof List<?> || written instanceof Map<?, ?>) {
            assertThat(restored).isEqualTo(written);
        } else if (written instanceof Collection<?> collection) {
            assertThat(new ArrayList<Object>((Collection<?>) restored)).isEqualTo(new ArrayList<Object>(collection));
        } else {
            assertThat(restored).isEqualTo(written);
        }
    }

    private static List<String> authorityNames(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(name -> name != null)
                .toList();
    }

    private static UnifiedCustomUserDetails contexaUser() {
        UserDto user = UserDto.builder().id(7L).username(USERNAME).password(PASSWORD_HASH).email("alice@example.org")
                .enabled(true).build();
        return new UnifiedCustomUserDetails(user, new HashSet<>(ROLES));
    }

    private static UserDetails springUser() {
        return User.withUsername(USERNAME).password(PASSWORD_HASH).authorities(ROLES).build();
    }

    private static PublicKeyCredentialUserEntity passkeyUser() {
        return ImmutablePublicKeyCredentialUserEntity.builder()
                .name(USERNAME).id(new Bytes(new byte[] {1, 2, 3})).displayName("Alice").build();
    }

    private static Authentication oidcLogin() {
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.ofEpochSecond(LOGIN_TIME),
                Instant.ofEpochSecond(LOGIN_TIME + 600), Map.of("sub", USERNAME, "iss", "https://issuer.example.org"));
        Set<GrantedAuthority> authorities = new LinkedHashSet<>(ROLES);
        authorities.add(new OidcUserAuthority(idToken));
        return new OAuth2AuthenticationToken(new DefaultOidcUser(authorities, idToken), authorities, "google");
    }

    private static Authentication oauth2Login() {
        return new OAuth2AuthenticationToken(new DefaultOAuth2User(ROLES, Map.of("login", USERNAME, "id", 7), "login"),
                ROLES, "github");
    }

    private static Authentication opaqueToken() {
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque",
                Instant.ofEpochSecond(LOGIN_TIME), Instant.ofEpochSecond(LOGIN_TIME + 600));
        return new BearerTokenAuthentication(new DefaultOAuth2AuthenticatedPrincipal(USERNAME, Map.of("sub", USERNAME), ROLES),
                token, ROLES);
    }

    /** The token of a login, as it states the login in its claims. */
    private static Jwt loginToken() {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject(USERNAME)
                .claim("auth_time", LOGIN_TIME).claim("amr", List.of("pwd")).claim("sid", "login-1").build();
    }

    private static Authentication zeroTrustAdjusted(Object principal) {
        ZeroTrustAuthenticationToken adjusted = new ZeroTrustAuthenticationToken(principal, null,
                List.of(new SimpleGrantedAuthority("ROLE_MFA_CHALLENGE")), 0.3d, 0.7d, ZeroTrustAction.CHALLENGE);
        if (!(principal instanceof Jwt)) {
            adjusted.setDetails(new LoginFactsDetails("10.0.0.1", HTTP_SESSION, List.of("PASSWORD"),
                    Instant.ofEpochSecond(LOGIN_TIME)));
        }
        return adjusted;
    }

    private static Authentication bridgeUser() {
        BridgePrincipal principal = new BridgePrincipal(USERNAME, "ext-7", "Alice", "HUMAN_USER", null, null, null, null,
                7L, "bridge-key", true, false);
        return new BridgeAuthenticationToken(principal, ROLES, emptyBridgeDetails());
    }

    private static BridgeAuthenticationDetails emptyBridgeDetails() {
        RecordComponent[] components = BridgeAuthenticationDetails.class.getRecordComponents();
        Class<?>[] types = Arrays.stream(components).map(RecordComponent::getType).toArray(Class<?>[]::new);
        try {
            return BridgeAuthenticationDetails.class.getDeclaredConstructor(types).newInstance(new Object[components.length]);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static <T extends AbstractAuthenticationToken> T withLoginFacts(T token, String method) {
        token.setDetails(new LoginFactsDetails("10.0.0.1", HTTP_SESSION, List.of(method), Instant.ofEpochSecond(LOGIN_TIME)));
        return token;
    }

    /** An object of a class only the writing side knows: the class exists in a loader the reading node never sees. */
    @SuppressWarnings("unchecked")
    private static <T> T instanceOfALostClass(Class<T> base, String simpleName) throws Exception {
        Class<? extends T> lost = new ByteBuddy()
                .subclass(base, ConstructorStrategy.Default.DEFAULT_CONSTRUCTOR)
                .name(APP_PACKAGE + simpleName)
                .make()
                .load(new URLClassLoader(new URL[0], base.getClassLoader()))
                .getLoaded();
        return (T) lost.getDeclaredConstructor().newInstance();
    }

    /** A user of an application: no no-arg guarantees, read-only collections, a value only the application can make sense of. */
    public static class AppUser implements UserDetails {

        private final String username = USERNAME;
        private final String password = PASSWORD_HASH;
        private final Set<GrantedAuthority> authorities = Set.copyOf(ROLES);
        private final Map<String, Object> profile = Collections.unmodifiableMap(new HashMap<>(Map.of("email", "alice@example.org")));

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public String getUsername() {
            return username;
        }

        public Map<String, Object> getProfile() {
            return profile;
        }
    }

    /** The owner and its account refer to each other, as the entities of an application do. */
    public static class CyclicAppUser extends AppUser {

        private final Object self = this;

        public Object getSelf() {
            return self;
        }
    }

    /** An authentication an application made itself. */
    public static class AppAuthentication extends AbstractAuthenticationToken {

        private final AppUser user = new AppUser();

        public AppAuthentication() {
            super(ROLES);
            setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return PASSWORD_HASH;
        }

        @Override
        public Object getPrincipal() {
            return user;
        }
    }

    /** A sign-in in the middle of being made: it says it is not authenticated, and it has to stay that way. */
    public static class UnauthenticatedAppToken extends AbstractAuthenticationToken {

        public UnauthenticatedAppToken() {
            super(ROLES);
            setAuthenticated(false);
        }

        @Override
        public Object getCredentials() {
            return PASSWORD_HASH;
        }

        @Override
        public Object getPrincipal() {
            return USERNAME;
        }
    }

    /** A value an application keeps in the flow. */
    public static class AppRisk implements Serializable {

        private final List<String> reasons = List.of("new device");

        public List<String> getReasons() {
            return reasons;
        }
    }

    /** A read-only collection of an application: a generic collection reader cannot refill it. */
    public static class ReadOnlyAppSet extends AbstractSet<String> implements Serializable {

        private final String[] values = {"a", "b"};

        @Override
        public Iterator<String> iterator() {
            return Arrays.asList(values).iterator();
        }

        @Override
        public int size() {
            return values.length;
        }
    }
}
