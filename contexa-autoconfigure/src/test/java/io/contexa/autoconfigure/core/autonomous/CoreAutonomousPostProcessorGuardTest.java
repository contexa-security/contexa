package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class CoreAutonomousPostProcessorGuardTest {

    @Test
    @DisplayName("securityDecisionPostProcessor requires UnifiedVectorService")
    void securityDecisionPostProcessorRequiresUnifiedVectorService() throws Exception {
        Method method = CoreAutonomousAutoConfiguration.class
                .getDeclaredMethod("securityDecisionPostProcessor", SecurityContextDataStore.class, UnifiedVectorService.class);

        assertThat(method.getReturnType()).isEqualTo(SecurityDecisionPostProcessor.class);
        ConditionalOnBean annotation = method.getAnnotation(ConditionalOnBean.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.value()).containsExactly(UnifiedVectorService.class);
    }
}