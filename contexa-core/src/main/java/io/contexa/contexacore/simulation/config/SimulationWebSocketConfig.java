package io.contexa.contexacore.simulation.config;

import io.contexa.contexacore.simulation.websocket.SimulationWebSocketHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * WebSocket 설정 - 시뮬레이션 실시간 모니터링
 * 
 * 공격 시뮬레이션 결과를 실시간으로 모니터링하기 위한 WebSocket 설정입니다.
 */
@Configuration
@EnableWebSocket
public class SimulationWebSocketConfig implements WebSocketConfigurer {
    
   /* private final SimulationWebSocketHandler simulationWebSocketHandler;
    
    public SimulationWebSocketConfig(SimulationWebSocketHandler simulationWebSocketHandler) {
        this.simulationWebSocketHandler = simulationWebSocketHandler;
    }*/
    
    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        /*// 시뮬레이션 WebSocket 엔드포인트 등록
        registry.addHandler(simulationWebSocketHandler, "/ws/simulation")
                .setAllowedOrigins("*");  // 개발환경용, 프로덕션에서는 특정 도메인만 허용
        
        // SockJS 폴백 지원 (WebSocket을 지원하지 않는 브라우저용)
        registry.addHandler(simulationWebSocketHandler, "/ws/simulation-sockjs")
                .setAllowedOrigins("*")
                .withSockJS();*/
    }
}