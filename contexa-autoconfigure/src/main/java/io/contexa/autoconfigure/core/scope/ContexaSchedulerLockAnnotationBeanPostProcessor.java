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
package io.contexa.autoconfigure.core.scope;

import net.javacrumbs.shedlock.core.ClockProvider;
import net.javacrumbs.shedlock.core.DefaultLockingTaskExecutor;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.autoproxy.AbstractBeanFactoryAwareAdvisingPostProcessor;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.function.SingletonSupplier;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

/**
 * ShedLock's {@code @SchedulerLock} for Contexa's own beans, in Contexa's own lock store, without
 * {@code @EnableSchedulerLock} for the application (R-9 of docs/agent/운영모드-정상화-구현계획.md).
 * <p>
 * {@code @EnableSchedulerLock} registers an advisor bean, which every auto-proxy creator of the context applies to every
 * bean, and it locks with the lock provider found by type. Switched on by Contexa, it brought the application's dormant
 * {@code @SchedulerLock} methods to life, and it locked Contexa's own methods in the application's store whenever the
 * application had a lock provider. The advisor of this processor is no bean: it reaches the classes of Contexa only
 * ({@link ContexaPackages}), and it locks with Contexa's lock provider, which it is given by name.
 * <p>
 * When the application turned ShedLock on itself, the application's advisor reaches Contexa's methods as well. This
 * advisor is then put in front of it on the same proxy, so that Contexa's lock is taken first, in Contexa's store, and
 * ShedLock's executor, which runs a task whose lock of the same name its thread already holds without taking it again,
 * never asks the application's store for it. To be in front, the processor runs after the auto-proxy creators (of the
 * highest precedence); it runs before the scheduling processors (of the lowest), so that a scheduled task calls the
 * locked proxy.
 */
public class ContexaSchedulerLockAnnotationBeanPostProcessor extends AbstractBeanFactoryAwareAdvisingPostProcessor {

    /** After the auto-proxy creators, before the scheduling processors. */
    public static final int ORDER = Ordered.LOWEST_PRECEDENCE - 1;

    private final SchedulerLockInterceptor interceptor;

    /**
     * @param lockProvider          Contexa's lock provider, asked for when a locked method is first called, so that
     *                              Contexa's data source is not made among the post processors
     * @param defaultLockAtMostFor  how long a lock whose annotation names no upper bound is held at most
     */
    public ContexaSchedulerLockAnnotationBeanPostProcessor(Supplier<LockProvider> lockProvider,
                                                           Duration defaultLockAtMostFor) {
        this.interceptor = new SchedulerLockInterceptor(
                SingletonSupplier.of(() -> new DefaultLockingTaskExecutor(lockProvider.get())),
                Objects.requireNonNull(defaultLockAtMostFor, "defaultLockAtMostFor"));
        this.advisor = new DefaultPointcutAdvisor(new AnnotationMatchingPointcut(null, SchedulerLock.class, true),
                interceptor);
        setBeforeExistingAdvisors(true);
        setOrder(ORDER);
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(beanFactory);
        if (beanFactory instanceof ConfigurableBeanFactory configurable) {
            interceptor.valueResolver = configurable::resolveEmbeddedValue;
        }
    }

    @Override
    protected boolean isEligible(Class<?> targetClass) {
        return ContexaPackages.owns(targetClass) && super.isEligible(targetClass);
    }

    /** Runs a locked method under its lock, read from its annotation as ShedLock reads it. */
    private static final class SchedulerLockInterceptor implements MethodInterceptor {

        private final Supplier<DefaultLockingTaskExecutor> executor;
        private final Duration defaultLockAtMostFor;
        private volatile UnaryOperator<String> valueResolver = UnaryOperator.identity();

        private SchedulerLockInterceptor(Supplier<DefaultLockingTaskExecutor> executor, Duration defaultLockAtMostFor) {
            this.executor = executor;
            this.defaultLockAtMostFor = defaultLockAtMostFor;
        }

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            Method method = invocation.getMethod();
            SchedulerLock lock = annotation(method, invocation.getThis());
            if (lock == null) {
                return invocation.proceed();
            }
            Class<?> returnType = method.getReturnType();
            if (returnType.isPrimitive() && !void.class.equals(returnType)) {
                throw new IllegalStateException("A method that returns a primitive value cannot be locked: " + method);
            }
            LockConfiguration configuration = new LockConfiguration(ClockProvider.now(), resolve(lock.name()),
                    duration(lock.lockAtMostFor(), defaultLockAtMostFor),
                    duration(lock.lockAtLeastFor(), Duration.ZERO));
            LockingTaskExecutor.TaskResult<Object> result = executor.get()
                    .executeWithLock(invocation::proceed, configuration);
            if (Optional.class.equals(returnType)) {
                return result.wasExecuted() ? result.getResult() : Optional.empty();
            }
            return result.getResult();
        }

        /** The annotation of the method, or of the method of the class behind a proxy. */
        private static SchedulerLock annotation(Method method, Object target) {
            SchedulerLock found = AnnotatedElementUtils.getMergedAnnotation(method, SchedulerLock.class);
            if (found != null || target == null) {
                return found;
            }
            Method specific = AopUtils.getMostSpecificMethod(method, AopUtils.getTargetClass(target));
            return specific != method ? AnnotatedElementUtils.getMergedAnnotation(specific, SchedulerLock.class) : null;
        }

        private String resolve(String value) {
            return valueResolver.apply(value);
        }

        private Duration duration(String value, Duration fallback) {
            String resolved = resolve(value);
            if (!StringUtils.hasText(resolved)) {
                return fallback;
            }
            Duration duration = DurationStyle.detectAndParse(resolved);
            if (duration.isNegative()) {
                throw new IllegalArgumentException("A lock cannot be held for a negative duration: " + value);
            }
            return duration;
        }
    }
}
