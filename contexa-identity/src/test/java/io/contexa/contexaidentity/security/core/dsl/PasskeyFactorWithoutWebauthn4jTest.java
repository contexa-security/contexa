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
package io.contexa.contexaidentity.security.core.dsl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.config.Customizer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An application that excludes webauthn4j runs without passkeys. Its MFA flows go on with their other factors; what
 * could not sign anybody in without a passkey is refused at start, with the reason, and not started without it.
 */
class PasskeyFactorWithoutWebauthn4jTest {

    private static final ClassLoader WITHOUT_WEBAUTHN4J = new FilteredClassLoader("com.webauthn4j");
    private static final ClassLoader WITHOUT_CBOR = new FilteredClassLoader("com.fasterxml.jackson.dataformat.cbor");

    private static IdentityDslRegistry<?> registry(ClassLoader loader) {
        ApplicationContext context = mock(ApplicationContext.class);
        when(context.getClassLoader()).thenReturn(loader);
        when(context.getBean(AuthUrlProvider.class)).thenReturn(new AuthUrlProvider(new AuthContextProperties()));
        when(context.getBean(AuthContextProperties.class)).thenReturn(new AuthContextProperties());
        when(context.getBean("contexaObjectMapper", ObjectMapper.class)).thenReturn(new ObjectMapper());
        ContexaOneTimeTokens tokens = mock(ContexaOneTimeTokens.class);
        when(tokens.service()).thenReturn(mock(EmailOneTimeTokenService.class));
        when(context.getBean(ContexaOneTimeTokens.BEAN_NAME, ContexaOneTimeTokens.class)).thenReturn(tokens);
        when(context.getEnvironment()).thenReturn(new MockEnvironment());
        return new IdentityDslRegistry<>(context);
    }

    private static PlatformConfig codeAndPasskey(ClassLoader loader, int required) throws Exception {
        return registry(loader).mfa(mfa -> mfa.requiredFactors(required)
                .primaryAuthentication(auth -> auth.formLogin(form -> form.loginPage("/login")))
                .passkey(Customizer.withDefaults())
                .ott(Customizer.withDefaults())).session(Customizer.withDefaults()).build();
    }

    @Test
    @DisplayName("with webauthn4j the MFA flow keeps its passkey factor, as before")
    void withTheLibraryThePasskeyStays() throws Exception {
        AuthenticationFlowConfig flow = codeAndPasskey(getClass().getClassLoader(), 1).getFlows().get(0);

        assertThat(flow.getRegisteredFactorOptions()).containsOnlyKeys(AuthType.MFA_PASSKEY, AuthType.MFA_OTT);
    }

    @Test
    @DisplayName("without webauthn4j the MFA flow goes on with the code and no passkey step")
    void withoutTheLibraryTheFlowGoesOnWithTheOtherFactors() throws Exception {
        AuthenticationFlowConfig flow = codeAndPasskey(WITHOUT_WEBAUTHN4J, 1).getFlows().get(0);

        assertThat(flow.getRegisteredFactorOptions()).containsOnlyKeys(AuthType.MFA_OTT);
        assertThat(flow.getStepConfigs()).extracting(step -> step.getType().toUpperCase())
                .doesNotContain("MFA_PASSKEY").contains("MFA_OTT");
    }

    @Test
    @DisplayName("without its CBOR codec webauthn4j cannot work, and the passkey is left out the same")
    void withoutTheCborCodecThePasskeyIsLeftOut() throws Exception {
        AuthenticationFlowConfig flow = codeAndPasskey(WITHOUT_CBOR, 1).getFlows().get(0);

        assertThat(flow.getRegisteredFactorOptions()).containsOnlyKeys(AuthType.MFA_OTT);
    }

    @Test
    @DisplayName("a flow that asks for more factors than remain is refused: the restriction is not lowered")
    void aFlowThatCannotBeSatisfiedIsRefused() {
        assertThatThrownBy(() -> codeAndPasskey(WITHOUT_WEBAUTHN4J, 2))
                .isInstanceOf(DslConfigurationException.class)
                .hasMessageContaining("webauthn4j");
    }

    @Test
    @DisplayName("a flow whose only factor is the passkey is refused with the reason")
    void aPasskeyOnlyFlowIsRefused() {
        assertThatThrownBy(() -> registry(WITHOUT_WEBAUTHN4J).mfa(mfa -> mfa
                .primaryAuthentication(auth -> auth.formLogin(form -> form.loginPage("/login")))
                .passkey(Customizer.withDefaults())))
                .isInstanceOf(DslConfigurationException.class)
                .hasMessageContaining("webauthn4j");
    }

    @Test
    @DisplayName("a sign-in by passkey alone is refused with the reason")
    void aPasskeySignInIsRefused() {
        assertThatThrownBy(() -> registry(WITHOUT_WEBAUTHN4J).passkey(Customizer.withDefaults()))
                .isInstanceOf(DslConfigurationException.class)
                .hasMessageContaining("webauthn4j");
    }

    @Test
    @DisplayName("the start-up notice names what is missing, and there is none when passkeys can work")
    void theNoticeNamesWhatIsMissing() {
        assertThat(PasskeyLibrary.unavailableNotice(getClass().getClassLoader())).isNull();
        assertThat(PasskeyLibrary.unavailableNotice(WITHOUT_WEBAUTHN4J)).startsWith("[Contexa] Passkeys are off")
                .contains(PasskeyLibrary.WEBAUTHN4J);
        assertThat(PasskeyLibrary.unavailableNotice(WITHOUT_CBOR)).contains(PasskeyLibrary.CBOR)
                .doesNotContain(PasskeyLibrary.WEBAUTHN4J);
    }
}
