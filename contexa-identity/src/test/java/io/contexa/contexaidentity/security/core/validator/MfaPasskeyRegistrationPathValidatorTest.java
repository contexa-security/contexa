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
package io.contexa.contexaidentity.security.core.validator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class MfaPasskeyRegistrationPathValidatorTest {

    private final MfaPasskeyRegistrationPathValidator validator = new MfaPasskeyRegistrationPathValidator();

    private Logger logger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void attachAppender() {
        logger = (Logger) LoggerFactory.getLogger(MfaPasskeyRegistrationPathValidator.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    @Test
    @DisplayName("Passkey-only MFA flow is reported as a warning with an error log, without a validation error")
    void passkeyOnlyFlowIsReported() {
        ValidationResult result = validator.validate(mfaFlow("mfa", AuthType.MFA_PASSKEY));

        assertThat(result.hasErrors()).isFalse();
        assertThat(result.getWarnings()).singleElement().asString()
                .contains("'mfa'")
                .contains("new users without a passkey cannot register one")
                .contains("Add the OTT factor");
        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage())
                    .contains("new users without a passkey cannot register one")
                    .contains("Add the OTT factor");
        });
    }

    @Test
    @DisplayName("MFA flow with both passkey and OTT factors is accepted silently")
    void passkeyWithOttIsAccepted() {
        ValidationResult result = validator.validate(mfaFlow("mfa", AuthType.MFA_PASSKEY, AuthType.MFA_OTT));

        assertThat(result.hasErrors()).isFalse();
        assertThat(result.hasWarnings()).isFalse();
        assertThat(appender.list).isEmpty();
    }

    @Test
    @DisplayName("MFA flow without the passkey factor and non-MFA flows are ignored")
    void flowsWithoutPasskeyAreIgnored() {
        assertThat(validator.validate(mfaFlow("mfa", AuthType.MFA_OTT)).hasWarnings()).isFalse();

        AuthenticationFlowConfig singlePasskey = AuthenticationFlowConfig.builder("passkey")
                .stepConfigs(List.of(new AuthenticationStepConfig("passkey", AuthType.PASSKEY.name(), 0, true)))
                .build();
        assertThat(validator.validate(singlePasskey).hasWarnings()).isFalse();
        assertThat(validator.validate(null).hasWarnings()).isFalse();
        assertThat(appender.list).isEmpty();
    }

    @Test
    @DisplayName("DslValidator collects the finding as a warning so that startup is not aborted")
    void dslValidatorCollectsWarning() {
        PlatformConfig platformConfig = mock(PlatformConfig.class);
        when(platformConfig.getFlows())
                .thenReturn(List.of(mfaFlow("mfa_admin", AuthType.MFA_PASSKEY)));
        DslValidator dslValidator = new DslValidator(List.of(), List.of(), List.of(validator), List.of());

        ValidationResult result = dslValidator.validate(platformConfig);

        assertThat(result.hasErrors()).isFalse();
        assertThat(result.getWarnings()).singleElement().asString().contains("'mfa_admin'");
    }

    private AuthenticationFlowConfig mfaFlow(String typeName, AuthType... factors) {
        List<AuthenticationStepConfig> steps = new ArrayList<>();
        steps.add(new AuthenticationStepConfig(typeName, AuthType.MFA_FORM.name(), 0, true));
        Map<AuthType, AuthenticationProcessingOptions> factorOptions = new LinkedHashMap<>();
        int order = 1;
        for (AuthType factor : factors) {
            steps.add(new AuthenticationStepConfig(typeName, factor.name(), order++, false));
            factorOptions.put(factor, mock(AuthenticationProcessingOptions.class));
        }
        return AuthenticationFlowConfig.builder(typeName)
                .primaryAuthenticationOptions(mock(PrimaryAuthenticationOptions.class))
                .stepConfigs(steps)
                .registeredFactorOptions(factorOptions)
                .build();
    }
}
