package io.contexa.contexaiam.aiam.config;

import io.contexa.contexacore.simulation.interceptor.SimulationModeInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 시뮬레이션 웹 설정
 *
 * SimulationModeInterceptor를 등록하여 모든 요청에서
 * 시뮬레이션 모드를 감지하고 ThreadLocal에 설정합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Configuration
@RequiredArgsConstructor
public class SimulationWebConfig implements WebMvcConfigurer {

    private final SimulationModeInterceptor simulationModeInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 시뮬레이션 인터셉터를 모든 경로에 적용
        registry.addInterceptor(simulationModeInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                    "/css/**",
                    "/js/**",
                    "/images/**",
                    "/fonts/**",
                    "/favicon.ico"
                );
    }
}