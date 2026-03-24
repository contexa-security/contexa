package io.contexa.contexacommon.annotation;

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
    }

    @Test
    void shouldDefaultToSandboxMode() {
        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(System.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.SANDBOX.name());
    }

    @Test
    void shouldPropagateFullModeWhenDeclared() {
        selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class));

        assertThat(System.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.FULL.name());
    }

    @EnableAISecurity
    static class DefaultSandboxApplication {
    }

    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullModeApplication {
    }
}
