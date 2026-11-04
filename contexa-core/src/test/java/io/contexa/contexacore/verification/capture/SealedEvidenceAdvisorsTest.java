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
package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.aop.Advisor;
import org.springframework.aop.AfterReturningAdvice;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SealedEvidenceAdvisorsTest {

    private static ListableBeanFactory beansWith(Class<?> aspect) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerBeanDefinition("aspect", new RootBeanDefinition(aspect));
        return beans;
    }

    private static Method evaluate(Class<?> strategy) {
        return Arrays.stream(strategy.getMethods())
                .filter(method -> method.getName().equals("evaluate") && method.getParameterCount() == 1)
                .findFirst().orElseThrow();
    }

    @Test
    @SuppressWarnings("unchecked")
    void eachAdvisorObservesItsOwnClassOnly() {
        PointcutAdvisor prompt = (PointcutAdvisor) SealedEvidenceAdvisors.promptCapture(
                beansWith(SealedEvidencePromptCaptureAspect.class), mock(ObjectProvider.class));
        PointcutAdvisor first = (PointcutAdvisor) SealedEvidenceAdvisors.layer1Completion(
                beansWith(SealedEvidenceLayer1CompletionAspect.class), mock(ObjectProvider.class));

        assertThat(prompt.getPointcut().getClassFilter().matches(PromptGenerator.class)).isTrue();
        assertThat(prompt.getPointcut().getClassFilter().matches(Layer1ContextualStrategy.class)).isFalse();
        assertThat(first.getPointcut().getClassFilter().matches(Layer1ContextualStrategy.class)).isTrue();
        assertThat(first.getPointcut().getClassFilter().matches(Layer2ExpertStrategy.class)).isFalse();
        assertThat(first.getPointcut().getMethodMatcher().matches(evaluate(Layer1ContextualStrategy.class),
                Layer1ContextualStrategy.class)).isTrue();
    }

    /** Without the capture nothing was proxied before, and nothing is now. */
    @Test
    @SuppressWarnings("unchecked")
    void withoutTheCaptureNothingIsProxied() {
        PointcutAdvisor advisor = (PointcutAdvisor) SealedEvidenceAdvisors.layer2Completion(
                new DefaultListableBeanFactory(), mock(ObjectProvider.class));

        assertThat(advisor.getPointcut().getClassFilter().matches(Layer2ExpertStrategy.class)).isFalse();
    }

    @Test
    void theCompletionReachesTheAspectWithTheEvent() throws Throwable {
        List<SecurityEvent> completed = new ArrayList<>();
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("aspect", new SealedEvidenceLayer2CompletionAspect(completed::add));
        Advisor advisor = SealedEvidenceAdvisors.layer2Completion(beans, beans.getBeanProvider(SealedEvidenceLayer2CompletionAspect.class));
        SecurityEvent event = SecurityEvent.builder().eventId("event-1").build();

        ((AfterReturningAdvice) advisor.getAdvice()).afterReturning(null, evaluate(Layer2ExpertStrategy.class),
                new Object[] {event}, null);

        assertThat(completed).containsExactly(event);
    }
}
