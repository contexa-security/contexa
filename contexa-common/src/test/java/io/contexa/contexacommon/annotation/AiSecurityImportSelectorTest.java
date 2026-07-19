/* Copyright 2026 The Contexa Project */
package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.Map;
import org.springframework.core.type.AnnotationMetadata;

import static org.assertj.core.api.Assertions.assertThat;

class AiSecurityImportSelectorTest {

    @Test
    void shouldDefaultToSandboxModeInContextEnvironment() {
        StandardEnvironment environment = select(DefaultSandboxApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.SANDBOX.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION))
                .isEqualTo(AuthObjectLocation.AUTO.name());
        assertThat(System.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
    }

    @Test
    void shouldPropagateFullModeWhenDeclared() {
        StandardEnvironment environment = select(FullModeApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.FULL.name());
    }

    @Test
    void shouldDefaultSandboxToHostOwned() {
        StandardEnvironment environment = select(DefaultSandboxApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .isEqualTo(SecurityOwnershipMode.HOST_OWNED.name());
        assertThat(environment.getProperty(
                AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class))
                .isFalse();
    }

    @Test
    void shouldDefaultFullModeToContexaOwned() {
        StandardEnvironment environment = select(FullModeApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED.name());
        assertThat(environment.getProperty(
                AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class))
                .isTrue();
    }

    @Test
    void shouldPreserveExplicitOwnershipOverrides() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitOwnership",
                Map.of(
                        AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP,
                        SecurityOwnershipMode.HOST_OWNED.name(),
                        AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION,
                        false)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);
        selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .isEqualTo(SecurityOwnershipMode.HOST_OWNED.name());
        assertThat(environment.getProperty(
                AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class))
                .isFalse();
    }

    @Test
    void shouldPreserveExplicitContexaOwnershipForSandboxMode() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitOwnership",
                Map.of(
                        AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP,
                        SecurityOwnershipMode.CONTEXA_OWNED.name(),
                        AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION,
                        true)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);
        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.SANDBOX.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED.name());
        assertThat(environment.getProperty(
                AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class))
                .isTrue();
    }

    @Test
    void shouldPropagateAuthObjectHintsWhenDeclared() {
        StandardEnvironment environment = select(SessionHintApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION))
                .isEqualTo(AuthObjectLocation.SESSION.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE))
                .isEqualTo("legacyUser");
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_TYPE))
                .isEqualTo(LegacyUser.class.getName());
    }

    @Test
    void shouldNotLeakActivationAcrossContexts() {
        StandardEnvironment full = select(FullModeApplication.class);
        StandardEnvironment untouched = new StandardEnvironment();
        assertThat(full.getProperty(AiSecurityImportSelector.PROP_MODE)).isEqualTo("FULL");
        assertThat(untouched.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
    }

    @Test
    void shouldSkipImportWhenContexaIsExplicitlyDisabled() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("contexaDisabled",
                Map.of(AiSecurityImportSelector.PROP_ENABLED, false)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        String[] imports = selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class));

        assertThat(imports).isEmpty();
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP)).isNull();
    }

    private StandardEnvironment select(Class<?> applicationClass) {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);
        selector.selectImports(AnnotationMetadata.introspect(applicationClass));
        return environment;
    }

    @EnableAISecurity
    static class DefaultSandboxApplication {
    }

    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullModeApplication {
    }

    @EnableAISecurity(authObjectLocation = AuthObjectLocation.SESSION,
            authObjectAttribute = "legacyUser", authObjectType = LegacyUser.class)
    static class SessionHintApplication {
    }

    static class LegacyUser {
    }
}
