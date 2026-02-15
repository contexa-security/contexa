package io.contexa.contexamcp;

import lombok.RequiredArgsConstructor;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableAspectJAutoProxy
@EnableJpaAuditing
@EnableJpaRepositories(basePackages = {"io.contexa.contexacommon.repository"})
@EntityScan(basePackages = {"io.contexa.contexacommon.entity"})
// Security is handled by contexa-identity module via ZeroTrust filter chain.
// This module (MCP server) has no spring-security dependency by design.
// AnthropicChatAutoConfiguration excluded: MCP server uses tool callbacks, not chat model.
@SpringBootApplication(exclude = {
        SecurityAutoConfiguration.class,
        UserDetailsServiceAutoConfiguration.class,
        AnthropicChatAutoConfiguration.class
})
@RequiredArgsConstructor
public class ContexaMcpApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaMcpApplication.class, args);
    }

}
