/* Copyright 2026 The Contexa Project */
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.execution.ZeroTrustEnforcementExceptionResolver;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.servlet.HandlerExceptionResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** Q-9: the DispatcherServlet finds the resolver by type, an application's own lookup by type does not meet it. */
class ZeroTrustEnforcementResolverWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(CoreAutonomousAutoConfiguration.EnforcementAnswerConfiguration.class)
            .withBean(ZeroTrustExceptionHandler.class, ZeroTrustExceptionHandler::new);

    @Test
    void theDispatcherServletFindsTheResolver() {
        runner.run(context -> assertThat(context.getBeansOfType(HandlerExceptionResolver.class).values())
                .hasSize(1).first().isInstanceOf(ZeroTrustEnforcementExceptionResolver.class));
    }

    @Test
    void anApplicationThatLooksForItsResolverByTypeStillFindsItsOwn() {
        HandlerExceptionResolver ownResolver = mock(HandlerExceptionResolver.class);

        runner.withBean("applicationResolver", HandlerExceptionResolver.class, () -> ownResolver)
                .run(context -> assertThat(context.getBeanProvider(HandlerExceptionResolver.class).getIfUnique())
                        .isSameAs(ownResolver));
    }

    @Test
    void anApplicationWithoutSpringMvcLoadsNoneOfIt() {
        runner.withClassLoader(new FilteredClassLoader(HandlerExceptionResolver.class))
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean("contexaZeroTrustEnforcementExceptionResolver"));
    }
}
