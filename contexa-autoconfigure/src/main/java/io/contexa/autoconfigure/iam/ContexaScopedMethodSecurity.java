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
package io.contexa.autoconfigure.iam;

import io.contexa.autoconfigure.core.scope.ContexaPackages;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.ClassFilter;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.context.ApplicationContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.function.SingletonSupplier;

import java.util.function.Supplier;

/**
 * {@code @PreAuthorize} for Contexa's own classes, without {@code @EnableMethodSecurity} for the application.
 * <p>
 * Contexa used to switch method security on for the whole application when it owns sign-in, which made the application's dormant
 * {@code @PreAuthorize} annotations start to deny calls, and gave every {@code @PreAuthorize} of the application Contexa's expression
 * handler. The advisor built here is Spring Security's own pre-authorization interceptor, narrowed to the classes of the Contexa libraries
 * and fitted with Contexa's handler only.
 */
final class ContexaScopedMethodSecurity {

    /** The bean Spring Security registers when an application enables method security (pre/post authorization). */
    static final String APPLICATION_INTERCEPTOR = "preAuthorizeAuthorizationMethodInterceptor";

    private ContexaScopedMethodSecurity() {
    }

    /**
     * @param handler the handler of Contexa's method policies; asked for on the first call that needs it, because the advisor is created
     *                before the beans the handler depends on
     */
    static DefaultPointcutAdvisor preAuthorizeAdvisor(Supplier<? extends DefaultMethodSecurityExpressionHandler> handler,
                                                      ApplicationContext applicationContext) {
        SingletonSupplier<DefaultMethodSecurityExpressionHandler> contexaHandler = SingletonSupplier.of(() -> {
            DefaultMethodSecurityExpressionHandler created = handler.get();
            created.setApplicationContext(applicationContext);
            return created;
        });
        PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
        manager.setExpressionHandler(new LazyExpressionHandler(contexaHandler));
        manager.setApplicationContext(applicationContext);
        AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor.preAuthorize(manager);
        // Asked at the time a bean is proxied: method security the application (or a later auto-configuration) switched on serves Contexa's classes
        ClassFilter contexaOnly = type -> ContexaPackages.owns(type)
                && !ContexaPackages.contextHas(applicationContext, APPLICATION_INTERCEPTOR);
        Pointcut pointcut = new ComposablePointcut(interceptor.getPointcut()).intersection(contexaOnly);
        DefaultPointcutAdvisor advisor = new DefaultPointcutAdvisor(pointcut, interceptor);
        advisor.setOrder(interceptor.getOrder());
        return advisor;
    }

    /** Hands every call to the handler once it exists. */
    static final class LazyExpressionHandler implements MethodSecurityExpressionHandler {

        private final Supplier<? extends MethodSecurityExpressionHandler> delegate;

        LazyExpressionHandler(Supplier<? extends MethodSecurityExpressionHandler> delegate) {
            this.delegate = delegate;
        }

        @Override
        public ExpressionParser getExpressionParser() {
            return delegate.get().getExpressionParser();
        }

        @Override
        @SuppressWarnings("deprecation")
        public EvaluationContext createEvaluationContext(Authentication authentication, MethodInvocation invocation) {
            return delegate.get().createEvaluationContext(authentication, invocation);
        }

        @Override
        public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation invocation) {
            return delegate.get().createEvaluationContext(authentication, invocation);
        }

        @Override
        public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext context) {
            return delegate.get().filter(filterTarget, filterExpression, context);
        }

        @Override
        public void setReturnObject(Object returnObject, EvaluationContext context) {
            delegate.get().setReturnObject(returnObject, context);
        }
    }
}
