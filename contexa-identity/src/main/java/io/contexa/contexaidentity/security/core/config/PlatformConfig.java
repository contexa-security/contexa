package io.contexa.contexaidentity.security.core.config;


import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public final class PlatformConfig {
    private final SafeHttpCustomizer<HttpSecurity> globalCustomizer;
    private final List<AuthenticationFlowConfig> flows;
    private PlatformContext platformContext;

    private PlatformConfig(Builder builder) {
        this.globalCustomizer = builder.globalCustomizer;
        this.flows = List.copyOf(builder.flows);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private SafeHttpCustomizer<HttpSecurity> globalCustomizer = http -> {};
        private final List<AuthenticationFlowConfig> flows = new ArrayList<>();

        public Builder global(SafeHttpCustomizer<HttpSecurity> globalCustomizer) {
            this.globalCustomizer = globalCustomizer;
            return this;
        }

        /**
         * 이미 완전히 빌드된 AuthenticationFlowConfig 객체를 추가합니다.
         */
        public Builder addFlow(AuthenticationFlowConfig flow) {
            Assert.notNull(flow, "AuthenticationFlowConfig cannot be null");
            this.flows.add(flow);
            return this;
        }

        /**
         * 내부 flows 리스트에 직접 접근할 수 있도록 제공 (주의해서 사용).
         * AbstractFlowRegistrar의 replaceLastState에서 사용됩니다.
         * @return 수정 가능한 flows 리스트
         */
        public List<AuthenticationFlowConfig> getModifiableFlows() {
            return this.flows;
        }

        /**
         * 마지막으로 추가된 Flow를 주어진 Flow로 교체합니다.
         * 이 메소드는 AbstractFlowRegistrar에서 사용됩니다.
         * @param flow 교체할 AuthenticationFlowConfig 객체
         */
        public Builder replaceLastFlow(AuthenticationFlowConfig flow) {
            if (!this.flows.isEmpty()) {
                this.flows.set(this.flows.size() - 1, flow);
            }
            return this;
        }

        public PlatformConfig build() {
            // 이제 여기서 AuthenticationFlowConfig.Builder.build()를 호출하지 않음.
            // 이미 AuthenticationFlowConfig 객체들이 flows 리스트에 저장되어 있음.
            return new PlatformConfig(this); // PlatformConfig 생성자는 List<AuthenticationFlowConfig>를 받음
        }
    }
}
