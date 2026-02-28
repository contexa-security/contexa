package io.contexa.contexaiam.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "contexa.iam.admin")
public class IamAdminProperties {
    private String restDocsPath = "/docs/index.html";
}
