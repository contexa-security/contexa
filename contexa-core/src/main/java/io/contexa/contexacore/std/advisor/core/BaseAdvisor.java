package io.contexa.contexacore.std.advisor.core;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisor;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisorChain;
import reactor.core.publisher.Flux;

import java.util.Map;

@Slf4j
@Getter
public abstract class BaseAdvisor implements CallAdvisor, StreamAdvisor {

    protected final String domain;

    protected final String name;

    protected final int order;

    protected boolean enabled = true;

    protected BaseAdvisor(String domain, String name, int order) {
        this.domain = domain;
        this.name = name;
        this.order = order;
    }

    @Override
    public String getName() {
        return String.format("%s.%s", domain, name);
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        if (!enabled) {
            return chain.nextCall(request);
        }

        long startTime = System.currentTimeMillis();

        try {
            request = beforeCall(request);

            enrichContext(request.context());

            ChatClientResponse response = chain.nextCall(request);

            response = afterCall(response, request);

            return response;

        } catch (AdvisorException e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[{}] Advisor error after {}ms: {}", getName(), duration, e.getMessage());

            if (e.isBlocking()) {
                return handleBlockingError(e, request);
            } else {
                return chain.nextCall(request);
            }

        } catch (Exception e) {
            log.error("[{}] Unexpected error", getName(), e);

            request.context().put(getName() + ".error", e.getMessage());
            return chain.nextCall(request);
        }
    }

    @Override
    public Flux<ChatClientResponse> adviseStream(ChatClientRequest request, StreamAdvisorChain chain) {
        if (!enabled) {
            return chain.nextStream(request);
        }

        try {
            ChatClientRequest finalRequest = beforeStream(request);

            enrichContext(finalRequest.context());

            Flux<ChatClientResponse> responses = chain.nextStream(finalRequest);

            return responses
                    .doOnNext(response -> afterStream(response, finalRequest))
                    .doOnError(error -> log.error("[{}] Stream error", getName(), error));

        } catch (Exception e) {
            log.error("[{}] Stream start error", getName(), e);
            return chain.nextStream(request);
        }
    }

    protected abstract ChatClientRequest beforeCall(ChatClientRequest request);

    protected abstract ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request);

    protected ChatClientRequest beforeStream(ChatClientRequest request) {
        return beforeCall(request);
    }

    protected void afterStream(ChatClientResponse response, ChatClientRequest request) {
    }

    protected void enrichContext(Map<String, Object> context) {
        context.put("advisor.domain", domain);
        context.put("advisor.name", getName());
        context.put("advisor.timestamp", System.currentTimeMillis());
    }

    protected ChatClientResponse handleBlockingError(AdvisorException e, ChatClientRequest request) {
        request.context().put("advisor.error", true);
        request.context().put("advisor.error.message", e.getMessage());
        request.context().put("advisor.error.domain", domain);
        request.context().put("advisor.blocked.by", getName());

        throw e;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean validate() {
        if (domain == null || domain.isEmpty()) {
            log.error("Domain is required for advisor");
            return false;
        }
        if (name == null || name.isEmpty()) {
            log.error("Name is required for advisor");
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return String.format("Advisor[%s, order=%d, enabled=%s]", getName(), order, enabled);
    }
}
