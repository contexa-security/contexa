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
package io.contexa.contexacore.autonomous.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.security.UserAccountDisabledEvent;
import io.contexa.contexacommon.security.UserAuthoritiesChangedEvent;
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.event.TransactionalEventListenerFactory;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Q-14: a change of accounts, once committed, reaches what is open. */
class UserAccountChangeListenerTest {

    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
    private final IForceLogoutService forceLogout = mock(IForceLogoutService.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(UserAccountChangeListener.class);

    @BeforeEach
    void listenToTheLog() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    private UserAccountChangeListener listener(boolean withForceLogout) {
        return listener(store, withForceLogout);
    }

    private UserAccountChangeListener listener(SecurityContextDataStore dataStore, boolean withForceLogout) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("store", dataStore);
        if (withForceLogout) {
            beans.addBean("forceLogout", forceLogout);
        }
        ObjectProvider<SecurityContextDataStore> stores = beans.getBeanProvider(SecurityContextDataStore.class);
        ObjectProvider<IForceLogoutService> logouts = beans.getBeanProvider(IForceLogoutService.class);
        return new UserAccountChangeListener(stores, logouts);
    }

    private long errorsLogged() {
        return logged.list.stream().filter(event -> event.getLevel() == Level.ERROR).count();
    }

    @Test
    @DisplayName("a change of rights moves the version on")
    void aChangeOfRights() {
        long before = store.authoritiesVersion();

        listener(true).onAuthoritiesChanged(new UserAuthoritiesChangedEvent());

        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("a disabled account is logged out everywhere the forced logout reaches, and the rest ends on its next request")
    void aDisabledAccount() {
        long before = store.authoritiesVersion();

        listener(true).onAccountDisabled(new UserAccountDisabledEvent("alice"));

        verify(forceLogout).forceLogoutByUserId("alice", "ACCOUNT_DISABLED");
        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("without a forced logout the version still moves on")
    void withoutAForcedLogout() {
        long before = store.authoritiesVersion();

        listener(false).onAccountDisabled(new UserAccountDisabledEvent("alice"));

        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("a forced logout that fails does not fail the administrator's change")
    void aFailingLogoutStaysAnError() {
        doThrow(new IllegalStateException("store down")).when(forceLogout).forceLogoutByUserId(anyString(), anyString());

        assertThatCode(() -> listener(true).onAccountDisabled(new UserAccountDisabledEvent("alice")))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a new password logs the account out everywhere the forced logout reaches, and the rest ends on its next request")
    void aNewPassword() {
        long before = store.authoritiesVersion();

        listener(true).onPasswordChanged(new UserPasswordChangedEvent("alice"));

        verify(forceLogout).forceLogoutByUserId("alice", "PASSWORD_CHANGED");
        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("where nothing logs out, as under HOST_OWNED, a new password still moves the version on")
    void aNewPasswordWithoutAForcedLogout() {
        long before = store.authoritiesVersion();

        listener(false).onPasswordChanged(new UserPasswordChangedEvent("alice"));

        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("a forced logout that fails is an error in the log, the password stays changed and the version moves on")
    void aNewPasswordWithAFailingLogout() {
        long before = store.authoritiesVersion();
        doThrow(new IllegalStateException("store down")).when(forceLogout).forceLogoutByUserId(anyString(), anyString());

        assertThatCode(() -> listener(true).onPasswordChanged(new UserPasswordChangedEvent("alice")))
                .doesNotThrowAnyException();

        assertThat(errorsLogged()).isEqualTo(1);
        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("a store that cannot move the version is an error in the log, and the forced logout still runs")
    void aNewPasswordWithAFailingVersion() {
        SecurityContextDataStore failing = mock(SecurityContextDataStore.class);
        doThrow(new IllegalStateException("store down")).when(failing).advanceAuthoritiesVersion();

        assertThatCode(() -> listener(failing, true).onPasswordChanged(new UserPasswordChangedEvent("alice")))
                .doesNotThrowAnyException();

        assertThat(errorsLogged()).isEqualTo(1);
        verify(forceLogout).forceLogoutByUserId("alice", "PASSWORD_CHANGED");
    }

    @Test
    @DisplayName("with Redis down the store of the version fails as the listener expects")
    @SuppressWarnings("unchecked")
    void aNewPasswordWithRedisDown() {
        RedisTemplate<String, Object> redis = mock(RedisTemplate.class);
        when(redis.opsForValue()).thenThrow(new RedisConnectionFailureException("redis down"));

        assertThatCode(() -> listener(new RedisSecurityContextDataStore(redis), false)
                .onPasswordChanged(new UserPasswordChangedEvent("alice"))).doesNotThrowAnyException();

        assertThat(errorsLogged()).isEqualTo(1);
    }

    @Test
    @DisplayName("nothing ends before the commit, and a change rolled back ends nothing")
    void onlyACommittedPasswordEndsAnything() {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean(TransactionalEventListenerFactory.class);
            context.registerBean(UserAccountChangeListener.class, () -> listener(true));
            context.refresh();
            TransactionTemplate transactions = new TransactionTemplate(new Transactions());

            transactions.executeWithoutResult(status -> {
                context.publishEvent(new UserPasswordChangedEvent("alice"));
                status.setRollbackOnly();
            });
            verify(forceLogout, never()).forceLogoutByUserId(anyString(), anyString());

            transactions.executeWithoutResult(status -> {
                context.publishEvent(new UserPasswordChangedEvent("alice"));
                verify(forceLogout, never()).forceLogoutByUserId(anyString(), anyString());
            });
            verify(forceLogout).forceLogoutByUserId("alice", "PASSWORD_CHANGED");
        }
    }

    /** Transactions without a resource: the synchronizations run as they do on a database. */
    private static final class Transactions extends AbstractPlatformTransactionManager {

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
        }
    }
}
