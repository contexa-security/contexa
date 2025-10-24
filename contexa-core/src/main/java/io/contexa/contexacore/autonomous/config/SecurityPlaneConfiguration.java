package io.contexa.contexacore.autonomous.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Security Plane Agent 전용 설정 클래스
 * CGLIB 프록시를 강제로 사용하여 클래스 기반 프록시 생성
 */
@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true, exposeProxy = true)
@EnableScheduling
@EnableAsync
public class SecurityPlaneConfiguration {
    
    /**
     * CGLIB 프록시 설정
     * - proxyTargetClass = true: 인터페이스가 없어도 클래스 기반 프록시 생성
     * - exposeProxy = true: 프록시 객체를 ThreadLocal에 노출
     */
    
}