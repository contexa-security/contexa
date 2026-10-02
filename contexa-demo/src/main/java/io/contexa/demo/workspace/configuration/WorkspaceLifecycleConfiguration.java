package io.contexa.demo.workspace.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "lab.workspace.enabled", havingValue = "true")
@EnableScheduling
public class WorkspaceLifecycleConfiguration {

}
