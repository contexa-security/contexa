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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The decoder of a chain in the resource server mode, where Contexa's decoder is held (R-17 of
 * docs/agent/운영모드-정상화-구현계획.md): Spring Boot's authorization server configuration then makes a decoder of a key it
 * generates at the start, which verifies the tokens of no issuer and is not the application's decoder.
 */
class ResourceServerDecoderChoiceTest {

    private static final String BOOT_GENERATED_KEY_DECODERS =
            "org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration$JwtDecoderConfiguration";

    @Test
    @DisplayName("리소스 서버 모드에서 Spring Boot가 생성 키로 만든 해독기는 앱의 해독기로 보지 않고 Contexa 해독기를 쓴다")
    void springBootsDecoderOfAGeneratedKeyIsNotTakenForTheApplications() throws Exception {
        JwtDecoder contexas = mock(JwtDecoder.class);
        try (GenericApplicationContext context = context(contexas, true, mock(JwtDecoder.class))) {
            HttpSecurity http = mock(HttpSecurity.class);

            new OAuth2StateAdapter().apply(http, platform(context));

            verify(http).setSharedObject(JwtDecoder.class, contexas);
        }
    }

    @Test
    @DisplayName("리소스 서버 모드에서 앱이 둔 해독기 하나는 그대로 앱의 해독기로 쓴다")
    void theApplicationsOnlyDecoderStillServes() throws Exception {
        JwtDecoder applications = mock(JwtDecoder.class);
        try (GenericApplicationContext context = context(mock(JwtDecoder.class), false, applications)) {
            HttpSecurity http = mock(HttpSecurity.class);

            new OAuth2StateAdapter().apply(http, platform(context));

            verify(http).setSharedObject(JwtDecoder.class, applications);
        }
    }

    /** A context with Contexa's decoder held and one other decoder, Spring Boot's of a generated key or the application's. */
    private static GenericApplicationContext context(JwtDecoder contexas, boolean bootsGeneratedKey, JwtDecoder other) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setOauth2ServerMode(OAuth2ServerMode.RESOURCE_SERVER);
        GenericApplicationContext context = new GenericApplicationContext();
        context.registerBean(AuthContextProperties.class, () -> properties);
        context.registerBean("contexaObjectMapper", ObjectMapper.class, () -> new ObjectMapper());
        context.registerBean(JsonAuthResponseWriter.class, () -> mock(JsonAuthResponseWriter.class));
        context.registerBean(OAuth2StateAdapter.CONTEXA_JWT_DECODER, HeldBean.class, () -> new HeldBean<>(contexas));
        String factory = bootsGeneratedKey ? BOOT_GENERATED_KEY_DECODERS : "applicationDecoders";
        context.registerBean(factory, Decoders.class, () -> new Decoders(other));
        RootBeanDefinition decoder = new RootBeanDefinition();
        decoder.setFactoryBeanName(factory);
        decoder.setFactoryMethodName("jwtDecoder");
        context.registerBeanDefinition("jwtDecoder", decoder);
        context.refresh();
        return context;
    }

    private static PlatformContext platform(GenericApplicationContext context) {
        PlatformContext platform = mock(PlatformContext.class);
        when(platform.applicationContext()).thenReturn(context);
        return platform;
    }

    /** A configuration that makes one decoder, as Spring Boot's and an application's do. */
    static final class Decoders {

        private final JwtDecoder decoder;

        Decoders(JwtDecoder decoder) {
            this.decoder = decoder;
        }

        public JwtDecoder jwtDecoder() {
            return decoder;
        }
    }
}
