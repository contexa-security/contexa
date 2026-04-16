package io.contexa.autoconfigure.core.std;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class CoreStdComponentsContextRetrieverGuardTest {

    @Test
    @DisplayName("contextRetriever does not require UnifiedVectorService directly")
    void contextRetrieverDoesNotRequireUnifiedVectorServiceDirectly() throws Exception {
        Method method = CoreStdComponentsAutoConfiguration.class.getDeclaredMethod(
                "contextRetriever",
                ObjectProvider.class,
                ContexaRagProperties.class,
                PromptContextAuthorizationService.class);

        assertThat(method.toGenericString()).contains("ObjectProvider<io.contexa.contexacore.std.rag.service.UnifiedVectorService>");
    }
}