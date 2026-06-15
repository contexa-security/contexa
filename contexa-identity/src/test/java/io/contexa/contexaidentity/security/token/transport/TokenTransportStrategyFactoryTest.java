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
package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.enums.TokenTransportType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenTransportStrategyFactoryTest {

    @Mock
    private AuthContextProperties properties;

    @Test
    @DisplayName("Factory should return HeaderTokenStrategy for HEADER type")
    void factoryReturnsHeaderStrategy() {
        when(properties.getTokenTransportType()).thenReturn(TokenTransportType.HEADER);

        TokenTransportStrategy strategy = TokenTransportStrategyFactory.create(properties);

        assertThat(strategy).isInstanceOf(HeaderTokenStrategy.class);
    }

    @Test
    @DisplayName("Factory should return CookieTokenStrategy for COOKIE type")
    void factoryReturnsCookieStrategy() {
        when(properties.getTokenTransportType()).thenReturn(TokenTransportType.COOKIE);

        TokenTransportStrategy strategy = TokenTransportStrategyFactory.create(properties);

        assertThat(strategy).isInstanceOf(CookieTokenStrategy.class);
    }

    @Test
    @DisplayName("Factory should return HeaderCookieTokenStrategy for HEADER_COOKIE type")
    void factoryReturnsHeaderCookieStrategy() {
        when(properties.getTokenTransportType()).thenReturn(TokenTransportType.HEADER_COOKIE);

        TokenTransportStrategy strategy = TokenTransportStrategyFactory.create(properties);

        assertThat(strategy).isInstanceOf(HeaderCookieTokenStrategy.class);
    }
}
