/* Copyright 2026 The Contexa Project */
package io.contexa.contexaiam.security.xacml.pep.interceptor;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableLlmSuppressionWriter;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Q-10 (PR-61): a call with no user is no one's request, so there is nothing to decide. It runs and leaves a record. A call
 * that names a user is decided, with a request or without; a visitor who is known to be nobody stays refused.
 */
class ProtectableCallWithoutUserTest {

    private final ProtectableMethodAuthorizationManager policies = mock(ProtectableMethodAuthorizationManager.class);
    private final ProtectableRapidReentryGuard reentryGuard = mock(ProtectableRapidReentryGuard.class);
    private final ZeroTrustEventPublisher events = mock(ZeroTrustEventPublisher.class);
    private final SynchronousProtectableDecisionService decisions = mock(SynchronousProtectableDecisionService.class);
    private final ProtectableLlmSuppressionWriter records = mock(ProtectableLlmSuppressionWriter.class);
    private final MethodInvocation call = mock(MethodInvocation.class);
    private AuthorizationManagerMethodInterceptor interceptor;

    @BeforeEach
    void setUp() throws Throwable {
        interceptor = interceptor(new SecurityZeroTrustProperties());
        Method method = Work.class.getMethod("decided");
        when(call.getMethod()).thenReturn(method);
        when(call.getThis()).thenReturn(new Work());
        when(call.proceed()).thenReturn("done");
        when(reentryGuard.tryAcquire(any(), any(), anyString())).thenReturn(true);
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    private AuthorizationManagerMethodInterceptor interceptor(SecurityZeroTrustProperties properties) {
        AuthorizationManagerMethodInterceptor created =
                new AuthorizationManagerMethodInterceptor(mock(Pointcut.class), policies, reentryGuard);
        created.setZeroTrustEventPublisher(events);
        created.setSynchronousProtectableDecisionService(decisions);
        created.setProtectableLlmSuppressionWriter(records);
        created.setSecurityZeroTrustProperties(properties);
        return created;
    }

    private static void inARequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest("POST", "/transfer")));
    }

    private static void signedIn(Authentication authentication) {
        SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
    }

    private static Authentication user() {
        return UsernamePasswordAuthenticationToken.authenticated("kim", null, List.of());
    }

    private static Authentication visitor() {
        return new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    @Test
    void aCallWithNoUserAndNoRequestRunsAndNothingIsDecided() throws Throwable {
        assertThat(interceptor.invoke(call)).isEqualTo("done");

        verify(call).proceed();
        verifyNoInteractions(policies, decisions, events);
    }

    @Test
    void itLeavesARecord() throws Throwable {
        interceptor.invoke(call);

        verify(records).recordRanWithoutUser(call, "ENFORCE");
    }

    @Test
    void aRecordThatFailsDoesNotStopTheJob() throws Throwable {
        doThrow(new IllegalStateException("the database is gone")).when(records).recordRanWithoutUser(any(), any());

        assertThat(interceptor.invoke(call)).isEqualTo("done");
    }

    @Test
    void whatTheJobThrowsIsTheJobs() throws Throwable {
        IllegalArgumentException failure = new IllegalArgumentException("the job failed");
        when(call.proceed()).thenThrow(failure);

        assertThatThrownBy(() -> interceptor.invoke(call)).isSameAs(failure);
    }

    @Test
    void underShadowAJobRunsToo() throws Throwable {
        SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
        shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);

        assertThat(interceptor(shadow).invoke(call)).isEqualTo("done");

        verify(records).recordRanWithoutUser(call, "SHADOW");
    }

    /** With analysis off nothing was held back, so there is nothing to record; the job runs as every call does. */
    @Test
    void withAnalysisOffAJobRunsAndNothingIsRecorded() throws Throwable {
        SecurityZeroTrustProperties disabled = new SecurityZeroTrustProperties();
        disabled.setMode(SecurityZeroTrustProperties.EnforcementMode.DISABLED);

        assertThat(interceptor(disabled).invoke(call)).isEqualTo("done");

        verifyNoInteractions(records);
    }

    @Test
    void aWebRequestWithNoUserStaysRefused() throws Throwable {
        inARequest();

        assertThatThrownBy(() -> interceptor.invoke(call)).isInstanceOf(AuthenticationCredentialsNotFoundException.class);

        verify(call, never()).proceed();
    }

    @Test
    void anAnonymousVisitorStaysRefusedInARequest() throws Throwable {
        inARequest();
        signedIn(visitor());

        assertThatThrownBy(() -> interceptor.invoke(call)).isInstanceOf(AuthenticationCredentialsNotFoundException.class);

        verify(call, never()).proceed();
    }

    /** The visitor's context came along: this is a known nobody, not a call without a user. */
    @Test
    void anAnonymousVisitorStaysRefusedWithoutARequest() throws Throwable {
        signedIn(visitor());

        assertThatThrownBy(() -> interceptor.invoke(call)).isInstanceOf(AuthenticationCredentialsNotFoundException.class);

        verify(call, never()).proceed();
    }

    @Test
    void aUserCarriedIntoABackgroundCallIsDecided() throws Throwable {
        Authentication carried = user();
        signedIn(carried);
        when(decisions.asyncGate(any(), any())).thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);

        assertThat(interceptor.invoke(call)).isEqualTo("done");

        verify(policies).protectable(any(), eq(call));
        verify(decisions).asyncGate(call, carried);
        verifyNoInteractions(records);
    }

    @Test
    void aRestrictionOnTheUserCarriedIntoABackgroundCallStopsIt() throws Throwable {
        signedIn(user());
        when(decisions.asyncGate(any(), any()))
                .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.restricted(ZeroTrustAction.BLOCK));

        assertThatThrownBy(() -> interceptor.invoke(call)).isInstanceOf(ZeroTrustAccessDeniedException.class);

        verify(call, never()).proceed();
    }

    /** The two ways the measurement failed, on the real proxies and threads of @Scheduled and @Async. */
    @Test
    void scheduledAndAsynchronousMethodsRunOnTheirOwnThreads() throws Exception {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean(AuthorizationManagerMethodInterceptor.class, () -> advisor(new SecurityZeroTrustProperties()));
            context.register(Jobs.class);
            context.refresh();
            Work work = context.getBean(Work.class);

            assertThat(work.later().get(10, TimeUnit.SECONDS)).isEqualTo("later");

            Job job = context.getBean(Job.class);
            await().atMost(10, TimeUnit.SECONDS).until(() -> job.runs.get() >= 2);
            assertThat(job.failures).hasValue(0);
        }
    }

    @Test
    void aUserCarriedByTheExecutorIsDecidedOnItsThread() throws Exception {
        Authentication carried = user();
        when(decisions.asyncGate(any(), any()))
                .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.restricted(ZeroTrustAction.BLOCK));
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean(AuthorizationManagerMethodInterceptor.class, () -> advisor(new SecurityZeroTrustProperties()));
            context.register(CarryingJobs.class);
            context.refresh();
            signedIn(carried);

            CompletableFuture<String> later = context.getBean(Work.class).later();

            assertThatThrownBy(() -> later.get(10, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class)
                    .hasCauseInstanceOf(ZeroTrustAccessDeniedException.class);
            assertThat(context.getBean(Work.class).timesRun()).isZero();
        }
    }

    private AuthorizationManagerMethodInterceptor advisor(SecurityZeroTrustProperties properties) {
        AuthorizationManagerMethodInterceptor created = new AuthorizationManagerMethodInterceptor(
                new AnnotationMatchingPointcut(null, Protectable.class, true), policies, reentryGuard);
        created.setZeroTrustEventPublisher(events);
        created.setSynchronousProtectableDecisionService(decisions);
        created.setProtectableLlmSuppressionWriter(records);
        created.setSecurityZeroTrustProperties(properties);
        return created;
    }

    /**
     * As Spring Boot proxies by default: of the bean's class, and first, so the advisor of @Async goes ahead of Contexa's
     * and the protected call runs on the executor's thread, as it did in the measurement.
     */
    private static DefaultAdvisorAutoProxyCreator classProxies() {
        DefaultAdvisorAutoProxyCreator proxies = new DefaultAdvisorAutoProxyCreator();
        proxies.setProxyTargetClass(true);
        proxies.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return proxies;
    }

    public static class Work {

        private final AtomicInteger ran = new AtomicInteger();

        public int timesRun() {
            return ran.get();
        }

        @Protectable(verificationRequired = false)
        public String decided() {
            ran.incrementAndGet();
            return "done";
        }

        @Async
        @Protectable(verificationRequired = false)
        public CompletableFuture<String> later() {
            ran.incrementAndGet();
            return CompletableFuture.completedFuture("later");
        }
    }

    public static class Job {

        final AtomicInteger runs = new AtomicInteger();
        final AtomicInteger failures = new AtomicInteger();
        private final Work work;

        public Job(Work work) {
            this.work = work;
        }

        @Scheduled(fixedDelay = 20)
        public void run() {
            try {
                work.decided();
                runs.incrementAndGet();
            } catch (RuntimeException failed) {
                failures.incrementAndGet();
            }
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAsync(proxyTargetClass = true)
    @EnableScheduling
    static class Jobs {

        @Bean
        static DefaultAdvisorAutoProxyCreator proxies() {
            return classProxies();
        }

        @Bean
        Work work() {
            return new Work();
        }

        @Bean
        Job job(Work work) {
            return new Job(work);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAsync(proxyTargetClass = true)
    static class CarryingJobs {

        @Bean
        static DefaultAdvisorAutoProxyCreator proxies() {
            return classProxies();
        }

        @Bean
        Work work() {
            return new Work();
        }

        @Bean
        DelegatingSecurityContextAsyncTaskExecutor taskExecutor() {
            return new DelegatingSecurityContextAsyncTaskExecutor(new SimpleAsyncTaskExecutor());
        }
    }
}
