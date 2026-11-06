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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.security.core.LoginAttemptIpUpserter;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-37: the login policy on the real queries. An attempt made during a lock, even with the right password, must not
 * move the lock's end, or anyone could keep an account locked by trying it from time to time.
 */
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.liquibase.enabled=false"
})
class LoginLockExpiryTest {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int LOCKOUT_MINUTES = 30;
    private static final String ALICE = "alice";
    private static final String ADDRESS = "203.0.113.10";

    @Autowired
    private UserRepository users;

    @Autowired
    private JdbcTemplate jdbc;

    private final LoginAttemptIpRepository addresses = mock(LoginAttemptIpRepository.class);
    private LoginPolicyService policy;

    @BeforeEach
    void setUp() {
        PasswordPolicyService policies = mock(PasswordPolicyService.class);
        when(policies.getCurrentPolicy()).thenReturn(PasswordPolicy.builder()
                .maxFailedAttempts(MAX_FAILED_ATTEMPTS)
                .lockoutDurationMinutes(LOCKOUT_MINUTES)
                .build());
        policy = new LoginPolicyService(users, addresses, policies, mock(LoginAttemptIpUpserter.class), null);
        users.saveAndFlush(Users.builder().username(ALICE).name(ALICE).password("encoded").build());
    }

    @AfterEach
    void clearRequestState() {
        LoginPolicyService.clearRequestState();
    }

    @Test
    @DisplayName("Reaching the limit locks the account for the lockout time")
    void reachingTheLimitLocks() {
        failTimes(MAX_FAILED_ATTEMPTS);

        assertThat(locked()).isTrue();
        assertThat(lockExpiresAt()).isBetween(LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES - 1),
                LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES));
    }

    @Test
    @DisplayName("An attempt during a lock leaves the lock's end where it was")
    void anAttemptDuringALockDoesNotMoveItsEnd() {
        failTimes(MAX_FAILED_ATTEMPTS);
        LocalDateTime lockEnd = setLockEnd(LocalDateTime.now().plusMinutes(10));

        failTimes(1);

        assertThat(locked()).isTrue();
        assertThat(lockExpiresAt()).isEqualTo(lockEnd);
    }

    @Test
    @DisplayName("Attempts made again and again cannot keep the account locked past the lock's end")
    void repeatedAttemptsDoNotKeepTheAccountLocked() {
        failTimes(MAX_FAILED_ATTEMPTS);
        LocalDateTime lockEnd = setLockEnd(LocalDateTime.now().plusMinutes(10));

        failTimes(20);
        assertThat(lockExpiresAt()).isEqualTo(lockEnd);

        setLockEnd(LocalDateTime.now().minusSeconds(1));
        assertThat(policy.checkAndUnlockIfExpired(ALICE)).isTrue();
        assertThat(locked()).isFalse();
    }

    @Test
    @DisplayName("When the lock has run out the count of failures starts over")
    void aLockThatRanOutClearsTheCount() {
        failTimes(MAX_FAILED_ATTEMPTS);
        setLockEnd(LocalDateTime.now().minusSeconds(1));

        failTimes(1);

        assertThat(locked()).isFalse();
        assertThat(lockExpiresAt()).isNull();
        assertThat(users.findFailedAttempts(ALICE)).contains(1);
    }

    @Test
    @DisplayName("After a lock has run out, reaching the limit again locks the account again")
    void anAccountCanBeLockedAgainAfterALockRanOut() {
        failTimes(MAX_FAILED_ATTEMPTS);
        setLockEnd(LocalDateTime.now().minusSeconds(1));

        failTimes(MAX_FAILED_ATTEMPTS);

        assertThat(locked()).isTrue();
        assertThat(lockExpiresAt()).isAfter(LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES - 1));
    }

    @Test
    @DisplayName("The address of an attempt during a lock is still counted")
    void theAddressOfAnAttemptDuringALockIsCounted() {
        PasswordPolicyService policies = mock(PasswordPolicyService.class);
        when(policies.getCurrentPolicy()).thenReturn(PasswordPolicy.builder()
                .maxFailedAttempts(MAX_FAILED_ATTEMPTS)
                .lockoutDurationMinutes(LOCKOUT_MINUTES)
                .ipMaxFailedAttempts(100)
                .build());
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), eq(ALICE))).thenReturn(1);
        policy = new LoginPolicyService(users, addresses, policies, mock(LoginAttemptIpUpserter.class), null);
        failTimes(MAX_FAILED_ATTEMPTS);

        failTimes(1);

        verify(addresses, times(MAX_FAILED_ATTEMPTS + 1)).incrementFailedAttempts(eq(ADDRESS), any(), eq(ALICE));
    }

    @Test
    @DisplayName("An administrator's release ends the lock before its time, and the count of failures with it")
    void anAdministratorsRelease() {
        failTimes(MAX_FAILED_ATTEMPTS);

        assertThat(users.clearLock(id())).isEqualTo(1);

        assertThat(locked()).isFalse();
        assertThat(lockExpiresAt()).isNull();
        assertThat(users.findFailedAttempts(ALICE)).contains(0);
    }

    @Test
    @DisplayName("It changes nothing on an account that stands under no lock, and says so")
    void aReleaseOfNoLock() {
        failTimes(1);

        assertThat(users.clearLock(id())).isZero();

        assertThat(users.findFailedAttempts(ALICE)).contains(1);
    }

    @Test
    @DisplayName("After an administrator's release the limit locks the account again")
    void lockedAgainAfterARelease() {
        failTimes(MAX_FAILED_ATTEMPTS);
        users.clearLock(id());

        failTimes(MAX_FAILED_ATTEMPTS);

        assertThat(locked()).isTrue();
    }

    private Long id() {
        return users.findByUsername(ALICE).orElseThrow().getId();
    }

    /** Each failure is its own request, as the filter that clears the request's state makes it in a running server. */
    private void failTimes(int times) {
        for (int attempt = 0; attempt < times; attempt++) {
            policy.onLoginFailure(ALICE, ADDRESS, "LockedException", "EVENT");
            LoginPolicyService.clearRequestState();
        }
    }

    private LocalDateTime setLockEnd(LocalDateTime lockEnd) {
        LocalDateTime exact = lockEnd.truncatedTo(ChronoUnit.SECONDS);
        jdbc.update("update ctxa_users set lock_expires_at = ? where username = ?", Timestamp.valueOf(exact), ALICE);
        return exact;
    }

    private LocalDateTime lockExpiresAt() {
        return jdbc.queryForObject("select lock_expires_at from ctxa_users where username = ?", LocalDateTime.class,
                ALICE);
    }

    private boolean locked() {
        return Boolean.TRUE.equals(jdbc.queryForObject("select account_locked from ctxa_users where username = ?",
                Boolean.class, ALICE));
    }

    @SpringBootConfiguration
    @EntityScan(basePackageClasses = Users.class)
    @EnableJpaRepositories(basePackageClasses = UserRepository.class,
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = UserRepository.class))
    static class Persistence {
    }
}
