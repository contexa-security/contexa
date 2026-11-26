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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.security.ContexaUserStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-12 and R-17 of docs/agent/운영모드-정상화-구현계획.md: the copy of a user is skipped for one of Contexa's accounts only
 * where the application's users sign in as Contexa's accounts: FULL with CONTEXA_OWNED, and FULL with HOST_OWNED while the
 * application has no store of its own (Contexa's main chain then signs them in from Contexa's).
 */
@DisplayName("앱 사용자가 Contexa 계정으로 로그인하는지의 판단(R-12, R-17)")
class ApplicationsUsersAreContexaAccountsTest {

    private static final UserDetailsService CONTEXAS = username -> {
        throw new UsernameNotFoundException(username);
    };
    private static final UserDetailsService APPLICATIONS = username -> {
        throw new UsernameNotFoundException(username);
    };

    @Test
    @DisplayName("FULL + HOST_OWNED에서 앱 저장소가 있으면 앱 사용자는 Contexa 계정이 아니다")
    void fullWithHostOwnedAndAnApplicationsStore() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton(ContexaUserStore.BEAN_NAME, new HeldBean<>(CONTEXAS));
        beans.registerSingleton("applicationUsers", APPLICATIONS);

        assertThat(answer("FULL", SecurityOwnershipMode.HOST_OWNED, beans)).isFalse();
    }

    @Test
    @DisplayName("FULL + HOST_OWNED에서 앱 저장소가 없으면 Contexa 저장소가 로그인시키므로 Contexa 계정이다")
    void fullWithHostOwnedWithoutAnApplicationsStore() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton(ContexaUserStore.BEAN_NAME, CONTEXAS);

        assertThat(answer("FULL", SecurityOwnershipMode.HOST_OWNED, beans)).isTrue();
    }

    @Test
    @DisplayName("FULL + CONTEXA_OWNED는 앱 저장소가 있어도 Contexa 계정이다")
    void fullWithContexaOwned() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton(ContexaUserStore.BEAN_NAME, new HeldBean<>(CONTEXAS));
        beans.registerSingleton("applicationUsers", APPLICATIONS);

        assertThat(answer("FULL", SecurityOwnershipMode.CONTEXA_OWNED, beans)).isTrue();
    }

    @Test
    @DisplayName("SANDBOX는 앱이 로그인시키므로 Contexa 계정이 아니다")
    void sandbox() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton(ContexaUserStore.BEAN_NAME, new HeldBean<>(CONTEXAS));

        assertThat(answer("SANDBOX", SecurityOwnershipMode.CONTEXA_OWNED, beans)).isFalse();
        assertThat(answer("SANDBOX", SecurityOwnershipMode.HOST_OWNED, beans)).isFalse();
    }

    private static boolean answer(String mode, SecurityOwnershipMode ownership, DefaultListableBeanFactory beans) {
        BridgeProperties properties = new BridgeProperties();
        properties.setOwnership(ownership);
        properties.setEnvironment(new MockEnvironment()
                .withProperty(ContexaOperatingProfile.PROP_MODE, mode)
                .withProperty(ContexaOperatingProfile.PROP_OWNERSHIP, ownership.name()));
        return AiBridgeUserMirrorSyncAutoConfiguration.applicationsUsersAreContexaAccounts(properties, beans).getAsBoolean();
    }
}
