package com.legacyshop.proxytest;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** A legacy application (a package that is not Contexa's): a final class behind an interface, advised by its own aspect. */
@Configuration(proxyBeanMethods = false)
public class LegacyApplication {

    public interface Port {
        String run();
    }

    /** Final: only a JDK proxy (the application's choice) can wrap it. */
    public static final class FinalPort implements Port {
        @Override
        public String run() {
            return "ran";
        }
    }

    @Aspect
    public static class EveryCall {
        @Around("execution(* com.legacyshop.proxytest.LegacyApplication.Port.run(..)) "
                + "|| execution(* io.contexa.autoconfigure.core.proxytest.ContexaSideBean.work(..))")
        public Object around(ProceedingJoinPoint joinPoint) throws Throwable {
            return joinPoint.proceed();
        }
    }

    @Bean
    Port port() {
        return new FinalPort();
    }

    @Bean
    EveryCall everyCall() {
        return new EveryCall();
    }
}
