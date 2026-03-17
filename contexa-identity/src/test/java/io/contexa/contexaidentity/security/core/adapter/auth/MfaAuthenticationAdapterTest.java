package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaAuthenticationAdapterTest {

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private AdapterRegistry adapterRegistry;

    @Mock
    private ConfiguredFactorFilterProvider factorFilterProvider;

    @Mock
    private MfaPolicyProvider mfaPolicyProvider;

    @Mock
    private AuthContextProperties authContextProperties;

    @Mock
    private AuthResponseWriter responseWriter;

    @Mock
    private AuthUrlProvider authUrlProvider;

    @Mock
    private MfaFlowUrlRegistry mfaFlowUrlRegistry;

    @Mock
    private StateConfig stateConfig;

    private MfaAuthenticationAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new MfaAuthenticationAdapter(applicationContext);
    }

    @Nested
    @DisplayName("Constructor and identity tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with null ApplicationContext should throw NullPointerException")
        void constructorWithNullContextThrowsException() {
            assertThatThrownBy(() -> new MfaAuthenticationAdapter(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("ApplicationContext cannot be null");
        }

        @Test
        @DisplayName("Default constructor should create instance without exception")
        void defaultConstructorCreatesInstance() {
            assertThatCode(MfaAuthenticationAdapter::new)
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("getId should return 'mfa'")
        void getIdReturnsMfa() {
            assertThat(adapter.getId()).isEqualTo("mfa");
        }

        @Test
        @DisplayName("getOrder should return 10")
        void getOrderReturnsTen() {
            assertThat(adapter.getOrder()).isEqualTo(10);
        }
    }

    @Nested
    @DisplayName("Bean wiring validation tests")
    class BeanWiringTests {

        @Test
        @DisplayName("apply should skip when flow config is null")
        void applySkipsWhenFlowConfigIsNull() throws Exception {
            when(httpSecurity.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(null);

            adapter.apply(httpSecurity, Collections.emptyList(), stateConfig);

            // Should return early without interacting with context
            verify(applicationContext, never()).getBean(AdapterRegistry.class);
        }

        @Test
        @DisplayName("apply should skip when flow type is not 'mfa'")
        void applySkipsWhenFlowTypeIsNotMfa() throws Exception {
            AuthenticationFlowConfig nonMfaFlow = mock(AuthenticationFlowConfig.class);
            when(nonMfaFlow.getTypeName()).thenReturn("FORM");
            when(httpSecurity.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(nonMfaFlow);

            adapter.apply(httpSecurity, Collections.emptyList(), stateConfig);

            verify(applicationContext, never()).getBean(AdapterRegistry.class);
        }

        @Test
        @DisplayName("apply with default constructor should resolve ApplicationContext from HttpSecurity")
        void applyWithDefaultConstructorResolvesContextFromHttp() throws Exception {
            MfaAuthenticationAdapter defaultAdapter = new MfaAuthenticationAdapter();

            AuthenticationFlowConfig mfaFlow = mock(AuthenticationFlowConfig.class);
            when(mfaFlow.getTypeName()).thenReturn("mfa");
            when(mfaFlow.getRegisteredFactorOptions()).thenReturn(null);
            when(httpSecurity.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(mfaFlow);
            when(httpSecurity.getSharedObject(ApplicationContext.class)).thenReturn(null);

            // When ApplicationContext is null from both constructor and HttpSecurity,
            // Assert.notNull should throw
            assertThatThrownBy(() -> defaultAdapter.apply(httpSecurity, Collections.emptyList(), stateConfig))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ApplicationContext not found");
        }

        @Test
        @DisplayName("apply should throw when MfaPolicyProvider is missing")
        void applyThrowsWhenMfaPolicyProviderMissing() throws Exception {
            AuthenticationFlowConfig mfaFlow = mock(AuthenticationFlowConfig.class);
            when(mfaFlow.getTypeName()).thenReturn("mfa");
            when(httpSecurity.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(mfaFlow);
            when(httpSecurity.getSharedObject(MfaPolicyProvider.class)).thenReturn(null);

            when(applicationContext.getBean(AdapterRegistry.class)).thenReturn(adapterRegistry);
            when(applicationContext.getBean(ConfiguredFactorFilterProvider.class)).thenReturn(factorFilterProvider);
            when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(authContextProperties);
            when(applicationContext.getBean(AuthResponseWriter.class)).thenReturn(responseWriter);

            assertThatThrownBy(() -> adapter.apply(httpSecurity, Collections.emptyList(), stateConfig))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("MfaPolicyProvider not found");
        }
    }

    @Nested
    @DisplayName("Factor options validation tests")
    class FactorOptionsTests {

        @Test
        @DisplayName("apply should throw when no factor options are registered")
        void applyThrowsWhenNoFactorOptionsRegistered() throws Exception {
            AuthenticationFlowConfig mfaFlow = mockValidMfaFlow();
            when(mfaFlow.getRegisteredFactorOptions()).thenReturn(Collections.emptyMap());

            setupCommonBeans(mfaFlow);

            assertThatThrownBy(() -> adapter.apply(httpSecurity, Collections.emptyList(), stateConfig))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("No factor options registered")
                    .hasMessageContaining("at least one secondary factor");
        }

        @Test
        @DisplayName("apply should throw when registered factor options is null")
        void applyThrowsWhenFactorOptionsIsNull() throws Exception {
            AuthenticationFlowConfig mfaFlow = mockValidMfaFlow();
            when(mfaFlow.getRegisteredFactorOptions()).thenReturn(null);

            setupCommonBeans(mfaFlow);

            assertThatThrownBy(() -> adapter.apply(httpSecurity, Collections.emptyList(), stateConfig))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("No factor options registered");
        }
    }

    @Nested
    @DisplayName("RequestMatcher configuration tests")
    class RequestMatcherTests {

        @Test
        @DisplayName("Empty step configs should not cause matcher registration failure")
        void emptyStepConfigsProducesNoOpMatcher() throws Exception {
            AuthenticationFlowConfig mfaFlow = mockValidMfaFlow();
            Map<AuthType, AuthenticationProcessingOptions> factorOpts = new LinkedHashMap<>();
            factorOpts.put(AuthType.OTT, mock(AuthenticationProcessingOptions.class));
            when(mfaFlow.getRegisteredFactorOptions()).thenReturn(factorOpts);
            when(mfaFlow.getStepConfigs()).thenReturn(Collections.emptyList());
            when(mfaFlow.getPrimaryAuthenticationOptions()).thenReturn(null);
            when(mfaFlow.getMfaPageConfig()).thenReturn(null);

            setupCommonBeans(mfaFlow);


            // Should not throw - creates a no-op matcher when no processing URLs found
            assertThatCode(() -> adapter.apply(httpSecurity, Collections.emptyList(), stateConfig))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Steps with order > 0 and valid processing URL should produce factor matchers")
        void stepsWithValidProcessingUrlProduceMatchers() throws Exception {
            AuthenticationFlowConfig mfaFlow = mockValidMfaFlow();
            Map<AuthType, AuthenticationProcessingOptions> factorOpts = new LinkedHashMap<>();
            factorOpts.put(AuthType.OTT, mock(AuthenticationProcessingOptions.class));
            when(mfaFlow.getRegisteredFactorOptions()).thenReturn(factorOpts);
            when(mfaFlow.getPrimaryAuthenticationOptions()).thenReturn(null);
            when(mfaFlow.getMfaPageConfig()).thenReturn(null);

            AuthenticationProcessingOptions procOpts = mock(AuthenticationProcessingOptions.class);
            when(procOpts.getLoginProcessingUrl()).thenReturn("/mfa/ott/verify");

            AuthenticationStepConfig step = new AuthenticationStepConfig();
            step.setType("ott");
            step.getOptions().put("_options", procOpts);

            // Primary step (order 0) should be skipped for matcher
            AuthenticationStepConfig primaryStep = new AuthenticationStepConfig("form", 0);
            when(mfaFlow.getStepConfigs()).thenReturn(List.of(primaryStep, step));

            setupCommonBeans(mfaFlow);


            assertThatCode(() -> adapter.apply(httpSecurity, Collections.emptyList(), stateConfig))
                    .doesNotThrowAnyException();
        }
    }

    // -- helper methods --

    private AuthenticationFlowConfig mockValidMfaFlow() {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn("mfa");
        when(httpSecurity.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(flow);
        return flow;
    }

    private void setupCommonBeans(AuthenticationFlowConfig mfaFlow) {
        when(httpSecurity.getSharedObject(MfaPolicyProvider.class)).thenReturn(mfaPolicyProvider);
        when(applicationContext.getBean(AdapterRegistry.class)).thenReturn(adapterRegistry);
        when(applicationContext.getBean(ConfiguredFactorFilterProvider.class)).thenReturn(factorFilterProvider);
        when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(authContextProperties);
        when(applicationContext.getBean(AuthResponseWriter.class)).thenReturn(responseWriter);
        when(applicationContext.getBean(MfaFlowUrlRegistry.class)).thenReturn(mfaFlowUrlRegistry);
        when(mfaFlowUrlRegistry.createAndRegister(any(), any(), any(), any())).thenReturn(authUrlProvider);
        when(mfaFlowUrlRegistry.createAndRegister(any(), any(), any(), any(), any())).thenReturn(authUrlProvider);
    }
}
