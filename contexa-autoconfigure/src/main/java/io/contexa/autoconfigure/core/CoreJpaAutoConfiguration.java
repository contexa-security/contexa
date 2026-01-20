package io.contexa.autoconfigure.core;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;


@AutoConfiguration
@ConditionalOnClass(name = "jakarta.persistence.EntityManager")
@EnableJpaRepositories(basePackages = {
    "io.contexa.contexacommon.repository",
    "io.contexa.contexacore.repository",
    "io.contexa.contexaiam.repository"
})
@EntityScan(basePackages = {
    "io.contexa.contexacommon.entity",
    "io.contexa.contexacore.domain.entity",
    "io.contexa.contexaiam.domain.entity"
})
public class CoreJpaAutoConfiguration {

    public CoreJpaAutoConfiguration() {
        
        
        
        
        
    }
}
