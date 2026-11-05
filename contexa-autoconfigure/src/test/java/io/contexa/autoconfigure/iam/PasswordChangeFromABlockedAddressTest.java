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

import io.contexa.contexacommon.entity.LoginAttemptIp;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService.PasswordChangeException;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.security.core.LoginAttemptIpUpserter;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A blocked address on the real queries: the password page must not hand it the lock a sign-in denies it. A sign-in from
 * a blocked address says nothing about the account it names, and neither does a password change.
 */
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.liquibase.enabled=false"
})
class PasswordChangeFromABlockedAddressTest {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final String ALICE = "alice";
    private static final String CURRENT = "the-right-password";
    private static final String BLOCKED = "203.0.113.66";
    private static final String OPEN = "203.0.113.10";

    @Autowired
    private UserRepository users;

    @Autowired
    private JdbcTemplate jdbc;

    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    private PasswordChangeService service;

    @BeforeEach
    void setUp() {
        PasswordPolicyService policies = mock(PasswordPolicyService.class);
        when(policies.getCurrentPolicy()).thenReturn(PasswordPolicy.builder()
                .maxFailedAttempts(MAX_FAILED_ATTEMPTS)
                .lockoutDurationMinutes(30)
                .build());
        LoginAttemptIpRepository addresses = mock(LoginAttemptIpRepository.class);
        LoginAttemptIp blocked = mock(LoginAttemptIp.class);
        when(blocked.getBlockedUntil()).thenReturn(LocalDateTime.now().plusMinutes(10));
        when(addresses.findByIpAddress(BLOCKED)).thenReturn(Optional.of(blocked));
        when(addresses.findByIpAddress(OPEN)).thenReturn(Optional.empty());
        LoginPolicyService policy = new LoginPolicyService(users, addresses, policies,
                mock(LoginAttemptIpUpserter.class), null);
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("policy", policy);
        service = new PasswordChangeService(users, encoder, policies, beans.getBeanProvider(LoginPolicyHandler.class),
                beans.getBeanProvider(ZeroTrustActionRepository.class), () -> false,
                mock(ApplicationEventPublisher.class));
        users.saveAndFlush(Users.builder().username(ALICE).name(ALICE).password(encoder.encode(CURRENT)).build());
    }

    @Test
    @DisplayName("control: wrong passwords from an open address lock the account")
    void wrongPasswordsFromAnOpenAddressLock() {
        attempts("a-guess", OPEN, MAX_FAILED_ATTEMPTS);

        assertThat(failedAttempts()).isEqualTo(MAX_FAILED_ATTEMPTS);
        assertThat(locked()).isTrue();
    }

    @Test
    @DisplayName("wrong passwords from a blocked address count nothing against the owner")
    void wrongPasswordsFromABlockedAddressLockNobody() {
        attempts("a-guess", BLOCKED, MAX_FAILED_ATTEMPTS * 2);

        assertThat(failedAttempts()).isZero();
        assertThat(locked()).isFalse();
    }

    @Test
    @DisplayName("the right password from a blocked address is refused and counts nothing against the owner")
    void theRightPasswordFromABlockedAddressLocksNobody() {
        attempts(CURRENT, BLOCKED, MAX_FAILED_ATTEMPTS * 2);

        assertThat(failedAttempts()).isZero();
        assertThat(locked()).isFalse();
        assertThat(encoder.matches(CURRENT, users.findByUsername(ALICE).orElseThrow().getPassword())).isTrue();
    }

    private void attempts(String password, String address, int times) {
        for (int attempt = 0; attempt < times; attempt++) {
            assertThatThrownBy(() -> service.changePassword(ALICE, password, "New-Pass-1", "New-Pass-1", address))
                    .isInstanceOf(PasswordChangeException.class);
        }
    }

    private int failedAttempts() {
        return users.findFailedAttempts(ALICE).orElse(0);
    }

    private boolean locked() {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "select account_locked from ctxa_users where username = ?", Boolean.class, ALICE));
    }

    @SpringBootConfiguration
    @EntityScan(basePackageClasses = Users.class)
    @EnableJpaRepositories(basePackageClasses = UserRepository.class,
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = UserRepository.class))
    static class Persistence {
    }
}
