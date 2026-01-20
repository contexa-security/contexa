package io.contexa.contexaidentity.security.core.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class DefaultPlatformContext implements PlatformContext{

    private final ApplicationContext applicationContext;
    private List<FlowContext> flowContexts;
    private final ObjectProvider<HttpSecurity> httpProvider;
    private final List<AuthenticationStepConfig> authConfigs = new ArrayList<>();
    private final Map<Class<?>, Object> shared = new HashMap<>();
    private final Map<String, SecurityFilterChain> chains = new HashMap<>();
    private final Map<AuthenticationFlowConfig, HttpSecurity> flowHttpMap = new HashMap<>();

    public DefaultPlatformContext(ApplicationContext applicationContext, ObjectProvider<HttpSecurity> httpProvider) {
        this.applicationContext = applicationContext;
        this.httpProvider = httpProvider;
    }

    @Override
    public void addAuthConfig(AuthenticationStepConfig config) {
        this.authConfigs.add(config);
    }

    @Override
    public List<AuthenticationStepConfig> getAuthConfigs() {
        return List.copyOf(authConfigs);
    }

    @Override
    public <T> void share(Class<T> clz, T obj) {
        shared.put(clz, obj);
    }

    @Override
    public <T> T getShared(Class<T> clz) {
        return (T) shared.get(clz);
    }

    @Override
    public void registerHttp(AuthenticationFlowConfig flow, HttpSecurity http) {
        flowHttpMap.put(flow, http);
    }

    @Override
    public HttpSecurity http(AuthenticationFlowConfig flow) {
        return flowHttpMap.get(flow);
    }

    public List<FlowContext> flowContexts() {
        return flowContexts;
    }

    public void flowContexts(List<FlowContext> flowContexts) {
        this.flowContexts = flowContexts;
    }

    @Override
    public HttpSecurity newHttp() {
        return httpProvider.getObject();
    }

    @Override
    public void registerChain(String id, SecurityFilterChain chain) {
        chains.put(id, chain);
    }

    @Override
    public Map<String, SecurityFilterChain> getChains() {
        return Map.copyOf(chains);
    }

    @Override
    public ApplicationContext applicationContext() {
        return applicationContext;
    }
}

