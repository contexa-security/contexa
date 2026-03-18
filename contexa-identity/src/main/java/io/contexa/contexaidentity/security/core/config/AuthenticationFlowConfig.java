package io.contexa.contexaidentity.security.core.config;

import io.contexa.contexaidentity.security.core.asep.dsl.MfaAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.exceptionhandling.MfaAuthenticationEntryPoint;
import io.contexa.contexacommon.properties.MfaPageConfig;
import lombok.Getter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class AuthenticationFlowConfig {

    private final String typeName;
    private final int order;
    private final StateConfig stateConfig;
    private final Customizer<HttpSecurity> rawHttpCustomizer;

    private final PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthenticationFailureHandler mfaFailureHandler;
    private final AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptions;
    private final boolean defaultDeviceTrustEnabled;
    private final MfaAsepAttributes mfaAsepAttributes;
    private final MfaPageConfig mfaPageConfig;
    private final MfaAuthenticationEntryPoint mfaAuthenticationEntryPoint;
    private final List<AuthenticationStepConfig> stepConfigs;
    private final String urlPrefix;
    private final int requiredFactorCount;

    private AuthenticationFlowConfig(Builder builder) {
        this.typeName = builder.typeName;
        this.order = builder.order;
        this.stateConfig = builder.stateConfig;
        this.rawHttpCustomizer = builder.rawHttpCustomizer;
        this.primaryAuthenticationOptions = builder.primaryAuthenticationOptions;
        this.mfaPolicyProvider = builder.mfaPolicyProvider;
        this.mfaFailureHandler = builder.mfaFailureHandler;
        this.finalSuccessHandler = builder.finalSuccessHandler;
        this.registeredFactorOptions = builder.registeredFactorOptions != null ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.registeredFactorOptions)) : Collections.emptyMap();
        this.defaultDeviceTrustEnabled = builder.defaultDeviceTrustEnabled;
        this.mfaAsepAttributes = builder.mfaAsepAttributes;
        this.mfaPageConfig = builder.mfaPageConfig;
        this.mfaAuthenticationEntryPoint = builder.mfaAuthenticationEntryPoint;
        this.stepConfigs = builder.stepConfigs != null ?
                Collections.unmodifiableList(new ArrayList<>(builder.stepConfigs)) :
                Collections.emptyList();
        this.urlPrefix = builder.urlPrefix;
        this.requiredFactorCount = builder.requiredFactorCount;
    }

    public AuthenticationFlowConfig withTypeName(String newTypeName) {
        Builder builder = new Builder(newTypeName)
                .order(this.order)
                .rawHttpCustomizer(this.rawHttpCustomizer)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions)
                .mfaPolicyProvider(this.mfaPolicyProvider)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(this.registeredFactorOptions != null ? new LinkedHashMap<>(this.registeredFactorOptions) : null)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled)
                .mfaAsepAttributes(this.mfaAsepAttributes)
                .mfaPageConfig(this.mfaPageConfig)
                .mfaAuthenticationEntryPoint(this.mfaAuthenticationEntryPoint)
                .stepConfigs(this.stepConfigs != null ? new ArrayList<>(this.stepConfigs) : null)
                .stateConfig(this.stateConfig)
                .urlPrefix(this.urlPrefix)
                .requiredFactorCount(this.requiredFactorCount);
        AuthenticationFlowConfig newFlow = new AuthenticationFlowConfig(builder);
        // Regenerate stepIds with the new typeName
        if (newFlow.stepConfigs != null) {
            for (AuthenticationStepConfig step : newFlow.stepConfigs) {
                step.setStepId(AuthenticationStepConfig.generateId(newTypeName, step.getType(), step.getOrder()));
            }
        }
        return newFlow;
    }

    public AuthenticationFlowConfig withStateConfig(StateConfig newStateConfig) {
        Builder builder = new Builder(this.typeName)
                .order(this.order)
                .rawHttpCustomizer(this.rawHttpCustomizer)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions)
                .mfaPolicyProvider(this.mfaPolicyProvider)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(this.registeredFactorOptions != null ? new LinkedHashMap<>(this.registeredFactorOptions) : null)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled)
                .mfaAsepAttributes(this.mfaAsepAttributes)
                .mfaPageConfig(this.mfaPageConfig)
                .mfaAuthenticationEntryPoint(this.mfaAuthenticationEntryPoint)
                .stepConfigs(this.stepConfigs != null ? new ArrayList<>(this.stepConfigs) : null)
                .stateConfig(newStateConfig)
                .urlPrefix(this.urlPrefix)
                .requiredFactorCount(this.requiredFactorCount);
        return new AuthenticationFlowConfig(builder);
    }

    public static Builder builder(String typeName) {
        return new Builder(typeName);
    }

    public static class Builder {
        private String typeName;
        private int order = 0;
        private StateConfig stateConfig;
        private Customizer<HttpSecurity> rawHttpCustomizer = http -> {
        };

        private PrimaryAuthenticationOptions primaryAuthenticationOptions;
        private MfaPolicyProvider mfaPolicyProvider;
        private AuthenticationFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptions = new LinkedHashMap<>();
        private boolean defaultDeviceTrustEnabled;
        private MfaAsepAttributes mfaAsepAttributes;
        private MfaPageConfig mfaPageConfig;
        private MfaAuthenticationEntryPoint mfaAuthenticationEntryPoint;
        private List<AuthenticationStepConfig> stepConfigs = new ArrayList<>();
        private String urlPrefix;
        private int requiredFactorCount = -1;

        public Builder(String typeName) {
            Assert.hasText(typeName, "typeName cannot be empty");
            this.typeName = typeName;
        }

        public Builder typeName(String typeName) {
            Assert.hasText(typeName, "typeName cannot be empty");
            this.typeName = typeName;
            return this;
        }

        public Builder order(int order) {
            this.order = order;
            return this;
        }

        public Builder stateConfig(StateConfig stateConfig) {
            this.stateConfig = stateConfig;
            return this;
        }

        public Builder rawHttpCustomizer(Customizer<HttpSecurity> customizer) {
            this.rawHttpCustomizer = customizer;
            return this;
        }

        public Builder stepConfigs(List<AuthenticationStepConfig> steps) {
            this.stepConfigs = (steps != null) ? new ArrayList<>(steps) : Collections.emptyList();
            return this;
        }

        public Builder primaryAuthenticationOptions(PrimaryAuthenticationOptions opts) {
            this.primaryAuthenticationOptions = opts;
            return this;
        }

        public Builder registeredFactorOptions(Map<AuthType, AuthenticationProcessingOptions> options) {
            this.registeredFactorOptions = (options != null) ? new LinkedHashMap<>(options) : new LinkedHashMap<>();
            return this;
        }

        public Builder mfaPolicyProvider(MfaPolicyProvider provider) {
            this.mfaPolicyProvider = provider;
            return this;
        }

        public Builder mfaFailureHandler(AuthenticationFailureHandler handler) {
            this.mfaFailureHandler = handler;
            return this;
        }

        public Builder finalSuccessHandler(AuthenticationSuccessHandler handler) {
            this.finalSuccessHandler = handler;
            return this;
        }

        public Builder defaultDeviceTrustEnabled(boolean enabled) {
            this.defaultDeviceTrustEnabled = enabled;
            return this;
        }

        public Builder mfaAsepAttributes(MfaAsepAttributes attributes) {
            this.mfaAsepAttributes = attributes;
            return this;
        }

        public Builder mfaPageConfig(MfaPageConfig pageConfig) {
            this.mfaPageConfig = pageConfig;
            return this;
        }

        public Builder mfaAuthenticationEntryPoint(MfaAuthenticationEntryPoint entryPoint) {
            this.mfaAuthenticationEntryPoint = entryPoint;
            return this;
        }

        public Builder urlPrefix(String urlPrefix) {
            this.urlPrefix = urlPrefix;
            return this;
        }

        public Builder requiredFactorCount(int requiredFactorCount) {
            this.requiredFactorCount = requiredFactorCount;
            return this;
        }

        public AuthenticationFlowConfig build() {
            if (MfaFlowTypeUtils.isMfaFlow(typeName)) {
                Assert.notNull(primaryAuthenticationOptions, "PrimaryAuthenticationOptions must be set for MFA flow named '" + typeName + "'");

                Assert.isTrue(this.stepConfigs != null && this.stepConfigs.size() > 1, "MFA flow must have its primary and at least one secondary factor step configured in stepConfigs field.");
            } else {
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(),
                        "Non-MFA flow named '" + typeName + "' must have at least one step in stepConfigs.");
            }
            return new AuthenticationFlowConfig(this);
        }
    }
}

