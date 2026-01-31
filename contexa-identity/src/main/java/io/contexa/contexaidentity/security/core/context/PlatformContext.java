package io.contexa.contexaidentity.security.core.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;

public interface PlatformContext {

    void addAuthConfig(AuthenticationStepConfig config);

    List<AuthenticationStepConfig> getAuthConfigs();

    <T> void share(Class<T> clz, T obj);

    <T> T getShared(Class<T> clz);

    void registerHttp(AuthenticationFlowConfig flow, HttpSecurity http);

    HttpSecurity http(AuthenticationFlowConfig flow);

    List<FlowContext> flowContexts();

    void flowContexts(List<FlowContext> flowContexts);

    HttpSecurity newHttp();

    void registerChain(String id, SecurityFilterChain chain);

    Map<String, SecurityFilterChain> getChains();

    ApplicationContext applicationContext();
}

