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
package io.contexa.contexaiam.security.core;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.entity.LoginAttemptIp;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginAddressBlockedException;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.function.IntPredicate;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** PR-69: the address throttle was written and never read at sign-in. */
class LoginPolicyServiceAddressThrottleTest {

    private static final String ADDRESS = "203.0.113.7";
    /** A proxy nobody named: it stands on a private network, where no client on the internet can connect from. */
    private static final String UNNAMED_PROXY = "10.0.0.5";
    private static final String FORWARDED = "198.51.100.20";
    private static final int LIMIT = 30;
    private static final int UNNAMED_PROXY_LIMIT = 300;

    private final UserRepository users = mock(UserRepository.class);
    private final LoginAttemptIpRepository addresses = mock(LoginAttemptIpRepository.class);
    private final PasswordPolicyService policies = mock(PasswordPolicyService.class);
    private final LoginAttemptIpUpserter upserter = mock(LoginAttemptIpUpserter.class);
    private final PasswordPolicy policy = new PasswordPolicy();
    private LoginPolicyService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        policy.setMaxFailedAttempts(5);
        policy.setIpMaxFailedAttempts(LIMIT);
        policy.setIpWindowMinutes(15);
        when(policies.getCurrentPolicy()).thenReturn(policy);
        service = new LoginPolicyService(users, addresses, policies, upserter, mock(ObjectProvider.class));

        aRequestFrom(ADDRESS);
    }

    @AfterEach
    void clear() {
        LoginPolicyService.clearRequestState();
        RequestContextHolder.resetRequestAttributes();
    }

    private static LoginAttemptIp row(int failures, LocalDateTime blockedUntil) {
        return row(ADDRESS, failures, blockedUntil);
    }

    private static LoginAttemptIp row(String address, int failures, LocalDateTime blockedUntil) {
        return LoginAttemptIp.builder()
                .ipAddress(address)
                .failedAttempts(failures)
                .windowStartAt(LocalDateTime.now().minusMinutes(1))
                .blockedUntil(blockedUntil)
                .build();
    }

    @Test
    @DisplayName("a sign-in from an address under a block is refused")
    void aBlockedAddressIsRefused() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().plusMinutes(10))));

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @Test
    @DisplayName("a block that has run out refuses nothing, and neither does an address without a record")
    void anExpiredBlockIsNoBlock() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().minusSeconds(1))));
        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();

        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.empty());
        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a refused attempt is counted against neither the account nor the address")
    void aRefusedAttemptIsNotCounted() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().plusMinutes(10))));

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
        // what the failure event and the failure handler report for the same request
        service.onLoginFailure("admin", ADDRESS, "LoginAddressBlockedException", "EVENT");
        service.onLoginFailure("admin");

        verify(users, never()).incrementFailedAttempts(anyString());
        verify(addresses, never()).incrementFailedAttempts(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("whoever keeps trying from a blocked address does not extend its block")
    void attemptsUnderABlockDoNotExtendIt() {
        LocalDateTime until = LocalDateTime.now().plusMinutes(10);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, until)));
        when(users.incrementFailedAttempts("admin")).thenReturn(0);

        service.onLoginFailure("admin", ADDRESS, "PasswordChange", "PASSWORD_CHANGE");

        verify(addresses, never()).blockIp(anyString(), any());
        verify(addresses, never()).incrementFailedAttempts(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("the attempt that reaches the limit blocks the address")
    void theLimitBlocks() {
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), anyString())).thenReturn(1);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        service.onLoginFailure("nobody", ADDRESS, "BadCredentialsException", "EVENT");

        verify(addresses, times(1)).blockIp(eq(ADDRESS), any());
    }

    @Test
    @DisplayName("the attempt before the limit does not")
    void beforeTheLimit() {
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), anyString())).thenReturn(1);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(29, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        service.onLoginFailure("nobody", ADDRESS, "BadCredentialsException", "EVENT");

        verify(addresses, never()).blockIp(anyString(), any());
    }

    @Test
    @DisplayName("the throttle failing never turns into a failed sign-in")
    void theDatabaseFailingDoesNotRefuse() {
        when(addresses.findByIpAddress(ADDRESS)).thenThrow(new DataAccessResourceFailureException("database down"));

        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
    }

    /**
     * Two failures from an address nobody has failed from yet, at the same moment: both miss the row, both insert, one loses
     * on the unique key. That loss is no failure of the sign-in and must not reach it: the loser counts its failure with the
     * increment that follows, as the one that won does.
     */
    @Test
    @DisplayName("the insert that loses the race for a new address is counted again and fails nothing")
    void theInsertThatLosesTheRaceIsCountedAgain() {
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), anyString())).thenReturn(0, 1);
        doThrow(new DataIntegrityViolationException("duplicate key value violates unique constraint ctxa_idx_login_attempt_ip_address"))
                .when(upserter).insertIfAbsent(eq(ADDRESS), any(), anyString());
        // the row is missing when the failure looks, and there once the other server's insert has won
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.empty(), Optional.of(row(1, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        assertThatCode(() -> service.onLoginFailure("nobody", ADDRESS, "BadCredentialsException", "EVENT")).doesNotThrowAnyException();
        LoginPolicyService.clearRequestState();

        verify(addresses, times(2)).incrementFailedAttempts(eq(ADDRESS), any(), anyString());
        verify(addresses, never()).blockIp(anyString(), any());
    }

    @Test
    @DisplayName("a row that is there already is not inserted again")
    void aRowThatIsThereIsNotInsertedAgain() {
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), anyString())).thenReturn(0, 1);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(1, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        service.onLoginFailure("nobody", ADDRESS, "BadCredentialsException", "EVENT");
        LoginPolicyService.clearRequestState();

        verify(upserter, never()).insertIfAbsent(anyString(), any(), anyString());
        verify(addresses, times(2)).incrementFailedAttempts(eq(ADDRESS), any(), anyString());
    }

    @Test
    @DisplayName("outside a request there is no address to refuse")
    void outsideARequest() {
        RequestContextHolder.resetRequestAttributes();

        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
        verify(addresses, never()).findByIpAddress(any());
    }

    private void aRequestThroughAProxy() {
        aRequestFrom(UNNAMED_PROXY, FORWARDED);
    }

    private static void aRequestFrom(String peer, String... forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr(peer);
        for (String value : forwardedFor) {
            request.addHeader("X-Forwarded-For", value);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private void aBlockOn(String address) {
        when(addresses.findByIpAddress(address)).thenReturn(Optional.of(row(address, LIMIT, LocalDateTime.now().plusMinutes(10))));
    }

    /** One failure of the current request, with the address at the given count once it is counted. */
    private void aFailureAtTheCount(String address, int count) {
        when(addresses.incrementFailedAttempts(eq(address), any(), anyString())).thenReturn(1);
        when(addresses.findByIpAddress(address)).thenReturn(Optional.of(row(address, count, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        service.onLoginFailure("nobody", address, "BadCredentialsException", "EVENT");
        LoginPolicyService.clearRequestState();
    }

    private void assertBlockedFrom(String address, int limit) {
        aFailureAtTheCount(address, limit - 1);
        verify(addresses, never()).blockIp(anyString(), any());

        aFailureAtTheCount(address, limit);
        verify(addresses).blockIp(eq(address), any());
    }

    private static TieredStrategyProperties proxies(boolean validation, String... trusted) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getSecurity().setTrustedProxyValidationEnabled(validation);
        properties.getSecurity().setTrustedProxies(List.of(trusted));
        return properties;
    }

    @ParameterizedTest
    @ValueSource(strings = {FORWARDED, "127.0.0.1", "10.0.0.1", "::1", "unknown", "", " ", "1.1.1.1, 2.2.2.2",
            "203.0.113.7, 10.0.0.1", "not-an-address"})
    @DisplayName("a client on the internet that adds the header itself stays under the block of its own address")
    void aForgedHeaderFromAPublicAddressEscapesNothing(String forged) {
        aRequestFrom(ADDRESS, forged);
        aBlockOn(ADDRESS);

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @Test
    @DisplayName("several lines of the header escape nothing either")
    void forgedHeaderLinesEscapeNothing() {
        aRequestFrom(ADDRESS, "127.0.0.1", "10.0.0.1");
        aBlockOn(ADDRESS);

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {ADDRESS, "2001:db8::1", "2606:4700:4700::1111", "::ffff:203.0.113.7", "::ffff:8.8.8.8",
            "::10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::"})
    @DisplayName("a public peer that sends the header gets the plain limit, and so does one that only carries a private address inside it")
    void aPublicPeerGetsThePlainLimit(String peer) {
        aRequestFrom(peer, FORWARDED);

        assertBlockedFrom(peer, LIMIT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-an-address", "localhost", "evil.example", "999.1.1.1", "127.1", "0x7f.0.0.1"})
    @DisplayName("a peer that is no plain address counts as a public one")
    void aMalformedPeerGetsThePlainLimit(String peer) {
        aRequestFrom(peer, "10.0.0.1");

        assertBlockedFrom(peer, LIMIT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.1", "127.0.0.1", "169.254.1.1", "::1",
            "0:0:0:0:0:0:0:1", "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%eth0", "::ffff:10.0.0.5", "::ffff:127.0.0.1"})
    @DisplayName("a private, link-local or loopback peer that sends the header stays under its block: nothing lifts the limit")
    void aPrivatePeerUnderABlockIsRefused(String peer) {
        aRequestFrom(peer, FORWARDED);
        aBlockOn(peer);

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.1", "127.0.0.1", "169.254.1.1", "::1",
            "0:0:0:0:0:0:0:1", "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%eth0", "::ffff:10.0.0.5", "::ffff:127.0.0.1"})
    @DisplayName("such a peer is counted under its own address, at ten times the limit: it may be a proxy nobody named")
    void aPrivatePeerGetsTenTimesTheLimit(String peer) {
        aRequestFrom(peer, FORWARDED);

        assertBlockedFrom(peer, UNNAMED_PROXY_LIMIT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.5", "127.0.0.1", "::1", "fe80::1", "::ffff:10.0.0.5"})
    @DisplayName("without the header a private peer is a client like any other, at the plain limit")
    void aPrivatePeerWithoutTheHeaderGetsThePlainLimit(String peer) {
        aRequestFrom(peer);

        assertBlockedFrom(peer, LIMIT);
    }

    @Test
    @DisplayName("the ten times follow the limit of the policy")
    void theLimitOfThePolicyDecides() {
        policy.setIpMaxFailedAttempts(7);
        aRequestThroughAProxy();

        assertBlockedFrom(UNNAMED_PROXY, 70);
    }

    @Test
    @DisplayName("a limit near the largest number stays a limit")
    void theLargestLimitDoesNotWrap() {
        policy.setIpMaxFailedAttempts(Integer.MAX_VALUE);
        aRequestThroughAProxy();

        aFailureAtTheCount(UNNAMED_PROXY, 5);

        verify(addresses, never()).blockIp(anyString(), any());
    }

    @Test
    @DisplayName("an address the caller names that is not the peer's gets the plain limit")
    void anAddressThatIsNotThePeers() {
        aRequestThroughAProxy();

        assertBlockedFrom("192.0.2.9", LIMIT);
    }

    @Test
    @DisplayName("a policy without an address limit counts nothing, header or not: that is the policy's, and only the policy's")
    void aPolicyWithoutALimit() {
        policy.setIpMaxFailedAttempts(0);
        aRequestThroughAProxy();

        aFailureAtTheCount(UNNAMED_PROXY, UNNAMED_PROXY_LIMIT);

        verify(addresses, never()).incrementFailedAttempts(anyString(), any(), anyString());
        verify(addresses, never()).blockIp(anyString(), any());
    }

    /** The row of one address, kept as the repository keeps it, so that a series of requests adds up. */
    private LoginAttemptIp aCountedAddress(String address) {
        LoginAttemptIp row = row(address, 0, null);
        when(addresses.findByIpAddress(address)).thenAnswer(call -> Optional.of(row));
        when(addresses.incrementFailedAttempts(eq(address), any(), anyString())).thenAnswer(call -> {
            row.setFailedAttempts(row.getFailedAttempts() + 1);
            return 1;
        });
        when(addresses.blockIp(eq(address), any())).thenAnswer(call -> {
            row.setBlockedUntil(call.getArgument(1));
            return 1;
        });
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);
        return row;
    }

    /** How many wrong passwords get through from the address, when the attempt of each number sends the header or not. */
    private int attemptsBeforeTheBlock(String address, IntPredicate sendsTheHeader) {
        for (int attempt = 1; attempt <= 1_000; attempt++) {
            if (sendsTheHeader.test(attempt)) {
                aRequestFrom(address, FORWARDED);
            } else {
                aRequestFrom(address);
            }
            try {
                service.checkSignInAddress("nobody");
            } catch (LoginAddressBlockedException refused) {
                return attempt - 1;
            }
            service.onLoginFailure("nobody", address, "BadCredentialsException", "EVENT");
            LoginPolicyService.clearRequestState();
        }
        throw new AssertionError("the address was never blocked");
    }

    static Stream<Arguments> mixesOfTheHeader() {
        return Stream.of(
                arguments(Named.of("always", (IntPredicate) attempt -> true), UNNAMED_PROXY_LIMIT),
                arguments(Named.of("never", (IntPredicate) attempt -> false), LIMIT),
                arguments(Named.of("on the even attempts", (IntPredicate) attempt -> attempt % 2 == 0), LIMIT + 1),
                arguments(Named.of("on the odd attempts", (IntPredicate) attempt -> attempt % 2 == 1), LIMIT),
                arguments(Named.of("taken off just before the plain limit", (IntPredicate) attempt -> attempt < LIMIT), LIMIT),
                arguments(Named.of("taken off past the plain limit", (IntPredicate) attempt -> attempt <= 100), 101),
                arguments(Named.of("put on just before the plain limit", (IntPredicate) attempt -> attempt >= LIMIT),
                        UNNAMED_PROXY_LIMIT),
                arguments(Named.of("taken off once, just before the ten times",
                        (IntPredicate) attempt -> attempt != UNNAMED_PROXY_LIMIT - 1), UNNAMED_PROXY_LIMIT - 1));
    }

    @ParameterizedTest
    @MethodSource("mixesOfTheHeader")
    @DisplayName("one count stands for the address: no mix of requests with and without the header gets further than always sending it")
    void noMixGetsFurtherThanAlwaysSendingTheHeader(IntPredicate sendsTheHeader, int expected) {
        aCountedAddress(UNNAMED_PROXY);

        int attempts = attemptsBeforeTheBlock(UNNAMED_PROXY, sendsTheHeader);

        assertThat(attempts).isEqualTo(expected).isLessThanOrEqualTo(UNNAMED_PROXY_LIMIT);
    }

    @Test
    @DisplayName("a block reached without the header stands with it: the block is one fact of the address")
    void aBlockReachedWithoutTheHeader() {
        LoginAttemptIp row = aCountedAddress(UNNAMED_PROXY);
        attemptsBeforeTheBlock(UNNAMED_PROXY, attempt -> false);
        assertThat(row.getFailedAttempts()).isEqualTo(LIMIT);

        aRequestThroughAProxy();

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
        assertThat(service.isIpBlocked(UNNAMED_PROXY)).isTrue();
    }

    @Test
    @DisplayName("a block reached with the header stands without it")
    void aBlockReachedWithTheHeader() {
        LoginAttemptIp row = aCountedAddress(UNNAMED_PROXY);
        attemptsBeforeTheBlock(UNNAMED_PROXY, attempt -> true);
        assertThat(row.getFailedAttempts()).isEqualTo(UNNAMED_PROXY_LIMIT);

        aRequestFrom(UNNAMED_PROXY);

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @Test
    @DisplayName("only a block refuses: a count past the plain limit is compared when a failure is counted, never when a sign-in is read")
    void onlyABlockRefuses() {
        when(addresses.findByIpAddress(UNNAMED_PROXY)).thenReturn(Optional.of(row(UNNAMED_PROXY, 100, null)));

        aRequestFrom(UNNAMED_PROXY);
        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();

        aRequestThroughAProxy();
        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("failures behind an unnamed proxy count against its address, and the account lock stays")
    void anUnnamedProxyIsCountedAndTheAccountToo() {
        aRequestThroughAProxy();
        when(addresses.incrementFailedAttempts(eq(UNNAMED_PROXY), any(), anyString())).thenReturn(1);
        when(users.incrementFailedAttempts("admin")).thenReturn(1);
        when(users.findFailedAttempts("admin")).thenReturn(Optional.of(5));
        when(users.lockAccount(eq("admin"), any())).thenReturn(1);

        service.onLoginFailure("admin", UNNAMED_PROXY, "BadCredentialsException", "EVENT");

        verify(addresses).incrementFailedAttempts(eq(UNNAMED_PROXY), any(), anyString());
        verify(users).lockAccount(eq("admin"), any());
    }

    @Test
    @DisplayName("the password change reads the same block")
    void aPasswordChangeReadsTheSameBlock() {
        aRequestThroughAProxy();
        aBlockOn(UNNAMED_PROXY);

        assertThat(service.isIpBlocked(UNNAMED_PROXY)).isTrue();

        aRequestFrom(ADDRESS, FORWARDED);
        aBlockOn(ADDRESS);

        assertThat(service.isIpBlocked(ADDRESS)).as("a public peer's forged header").isTrue();
    }

    private List<ILoggingEvent> errorsOf(Runnable work) {
        Logger logger = (Logger) LoggerFactory.getLogger(LoginPolicyService.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            work.run();
            return appender.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    @DisplayName("the ERROR names the setting and the ten times, once for a burst of attempts")
    void theErrorNamesTheSettingOnce() {
        aRequestThroughAProxy();
        when(users.incrementFailedAttempts(anyString())).thenReturn(0);

        List<ILoggingEvent> errors = errorsOf(() -> {
            service.checkSignInAddress("first");
            service.onLoginFailure("first", UNNAMED_PROXY, "BadCredentialsException", "EVENT");
            service.checkSignInAddress("second");
        });

        assertThat(errors).hasSize(1);
        assertThat(errors.get(0).getFormattedMessage())
                .contains("contexa.security.tiered.security.trusted-proxies").contains(UNNAMED_PROXY)
                .contains("10 times").doesNotContain("not applied");
    }

    @Test
    @DisplayName("the first sign-in behind such a proxy tells it, whether or not anybody fails")
    void theFirstSignInTellsIt() {
        aRequestThroughAProxy();

        List<ILoggingEvent> errors = errorsOf(() -> service.checkSignInAddress("first"));

        assertThat(errors).hasSize(1);
    }

    @Test
    @DisplayName("a public peer that sends the header is a client: only the block of it names the setting")
    void aPublicPeerIsNoProxyToReport() {
        aRequestFrom(ADDRESS, FORWARDED);
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        assertThat(errorsOf(() -> service.checkSignInAddress("first"))).isEmpty();

        List<ILoggingEvent> errors = errorsOf(() -> aFailureAtTheCount(ADDRESS, LIMIT));

        assertThat(errors).hasSize(1);
        assertThat(errors.get(0).getFormattedMessage())
                .contains("contexa.security.tiered.security.trusted-proxies").contains(ADDRESS);
    }

    @Test
    @DisplayName("the block of an unnamed proxy names the setting too")
    void theBlockOfAnUnnamedProxyNamesTheSetting() {
        aRequestThroughAProxy();

        List<ILoggingEvent> errors = errorsOf(() -> aFailureAtTheCount(UNNAMED_PROXY, UNNAMED_PROXY_LIMIT));

        assertThat(errors).filteredOn(event -> event.getFormattedMessage().contains("blocked address")).hasSize(1);
        verify(addresses).blockIp(eq(UNNAMED_PROXY), any());
    }

    @Test
    @DisplayName("Q-24: without the header the address is the client's own, and the limit holds")
    void withoutTheHeaderTheLimitHolds() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().plusMinutes(10))));

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @Test
    @DisplayName("Q-24: with proxies named, a peer outside them is a client and the header says nothing: the limit holds")
    void aNamedProxyListKeepsTheLimit() {
        TieredStrategyProperties properties = proxies(true, "192.0.2.1");
        SessionFingerprintUtil.bindClientIpResolution(properties);
        try {
            aRequestThroughAProxy();
            aBlockOn(UNNAMED_PROXY);

            assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
        } finally {
            SessionFingerprintUtil.unbindClientIpResolution(properties);
        }
    }

    @Test
    @DisplayName("with proxies named, a private peer outside them gets the plain limit: nothing is in doubt")
    void aNamedProxyListGivesNoTenTimes() {
        TieredStrategyProperties properties = proxies(true, "192.0.2.1");
        SessionFingerprintUtil.bindClientIpResolution(properties);
        try {
            aRequestThroughAProxy();

            assertBlockedFrom(UNNAMED_PROXY, LIMIT);
        } finally {
            SessionFingerprintUtil.unbindClientIpResolution(properties);
        }
    }

    @Test
    @DisplayName("Q-24: with the proxy validation turned off the header is believed, and the limit holds on what it names")
    void validationOffKeepsTheLimit() {
        TieredStrategyProperties properties = proxies(false);
        SessionFingerprintUtil.bindClientIpResolution(properties);
        try {
            aRequestThroughAProxy();
            when(addresses.findByIpAddress(FORWARDED))
                    .thenReturn(Optional.of(row(FORWARDED, 30, LocalDateTime.now().plusMinutes(10))));

            assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
        } finally {
            SessionFingerprintUtil.unbindClientIpResolution(properties);
        }
    }

    @Test
    @DisplayName("a sign-in that succeeds leaves the address's count: an account of one's own would wipe the guesses at others")
    void aSuccessLeavesTheCount() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(12, null)));

        service.onLoginSuccess("admin", ADDRESS, "EVENT");

        verify(addresses, never()).resetWindow(any(), any(), any(), any());
    }

    /** The follow-up increment counts the attempt: a first row of one would count the first failure twice. */
    @Test
    @DisplayName("the first failure of an address counts once")
    void theFirstFailureCountsOnce() {
        LoginAttemptIpRepository repository = mock(LoginAttemptIpRepository.class);

        new LoginAttemptIpUpserter(repository).insertIfAbsent(ADDRESS, LocalDateTime.now(), "nobody");

        ArgumentCaptor<LoginAttemptIp> saved = ArgumentCaptor.forClass(LoginAttemptIp.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getFailedAttempts()).isZero();
    }
}
