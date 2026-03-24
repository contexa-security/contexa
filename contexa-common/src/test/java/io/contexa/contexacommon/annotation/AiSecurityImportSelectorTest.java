package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.type.AnnotationMetadata;

import static org.assertj.core.api.Assertions.assertThat;

class AiSecurityImportSelectorTest {

    private final AiSecurityImportSelector selector = new AiSecurityImportSelector();

    @AfterEach
    void clearModeProperty() {
        System.clearProperty(AiSecurityImportSelector.PROP_MODE);
        System.clearProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION);
        System.clearProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE);
        System.clearProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_TYPE);
    }

    @Test
    void shouldDefaultToSandboxMode() {
        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(System.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.SANDBOX.name());
        assertThat(System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION))
                .isEqualTo(AuthObjectLocation.AUTO.name());
    }

    @Test
    void shouldPropagateFullModeWhenDeclared() {
        selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class));

        assertThat(System.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.FULL.name());
    }

    @Test
    void shouldPropagateAuthObjectHintsWhenDeclared() {
        selector.selectImports(AnnotationMetadata.introspect(SessionHintApplication.class));

        assertThat(System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION))
                .isEqualTo(AuthObjectLocation.SESSION.name());
        assertThat(System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE))
                .isEqualTo("legacyUser");
        assertThat(System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_TYPE))
                .isEqualTo(LegacyUser.class.getName());
    }

    @EnableAISecurity
    static class DefaultSandboxApplication {
    }

    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullModeApplication {
    }

    @EnableAISecurity(
            authObjectLocation = AuthObjectLocation.SESSION,
            authObjectAttribute = "legacyUser",
            authObjectType = LegacyUser.class
    )
    static class SessionHintApplication {
    }

    static class LegacyUser {
    }
}
