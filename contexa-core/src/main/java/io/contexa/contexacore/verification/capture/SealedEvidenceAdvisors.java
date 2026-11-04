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

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import org.springframework.aop.Advisor;
import org.springframework.aop.AfterReturningAdvice;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;

import java.lang.reflect.Method;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * What the sealed evidence observes, as advisors of Contexa's own classes.
 * <p>
 * As {@code @Aspect} classes these needed {@code @EnableAspectJAutoProxy}, which turned aspect proxying on for the whole
 * application: an application that set {@code spring.aop.auto=false} got its own {@code @Aspect} classes applied anyway.
 * An advisor of the infrastructure role is applied by the proxy creator transactions already bring, and touches nothing
 * else.
 */
public final class SealedEvidenceAdvisors {

    private SealedEvidenceAdvisors() {
    }

    @SuppressWarnings("unchecked")
    public static Advisor promptCapture(ListableBeanFactory beans, ObjectProvider<SealedEvidencePromptCaptureAspect> aspect) {
        return advisor(beans, SealedEvidencePromptCaptureAspect.class, PromptGenerator.class,
                method -> "generatePrompt".equals(method.getName()) && method.getParameterCount() == 3
                        && AIRequest.class.isAssignableFrom(method.getParameterTypes()[0]),
                (returnValue, method, args, target) -> aspect.ifAvailable(capture -> capture.capturePromptGenerationResult(
                        (AIRequest<? extends DomainContext>) args[0], (String) args[1], (String) args[2],
                        (PromptGenerationResult) returnValue)));
    }

    public static Advisor layer1Completion(ListableBeanFactory beans, ObjectProvider<SealedEvidenceLayer1CompletionAspect> aspect) {
        return evaluation(beans, SealedEvidenceLayer1CompletionAspect.class, Layer1ContextualStrategy.class,
                event -> aspect.ifAvailable(completion -> completion.completeAfterLayer1(event)));
    }

    public static Advisor layer2Completion(ListableBeanFactory beans, ObjectProvider<SealedEvidenceLayer2CompletionAspect> aspect) {
        return evaluation(beans, SealedEvidenceLayer2CompletionAspect.class, Layer2ExpertStrategy.class,
                event -> aspect.ifAvailable(completion -> completion.completeAfterLayer2(event)));
    }

    private static Advisor evaluation(ListableBeanFactory beans, Class<?> aspectType, Class<?> strategy,
                                      Consumer<SecurityEvent> completion) {
        return advisor(beans, aspectType, strategy,
                method -> "evaluate".equals(method.getName()) && method.getParameterCount() == 1
                        && SecurityEvent.class.equals(method.getParameterTypes()[0]),
                (returnValue, method, args, target) -> completion.accept((SecurityEvent) args[0]));
    }

    private static Advisor advisor(ListableBeanFactory beans, Class<?> aspectType, Class<?> target,
                                   Predicate<Method> observed, AfterReturningAdvice advice) {
        StaticMethodMatcherPointcut pointcut = new StaticMethodMatcherPointcut() {
            @Override
            public boolean matches(Method method, Class<?> targetClass) {
                return observed.test(method);
            }
        };
        // Asked when a bean is proxied, of the definitions: creating the aspect that early would take its store along.
        // Without the capture nothing is proxied, as before.
        pointcut.setClassFilter(type -> target.isAssignableFrom(type)
                && beans.getBeanNamesForType(aspectType, true, false).length > 0);
        return new DefaultPointcutAdvisor(pointcut, advice);
    }
}
