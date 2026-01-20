package io.contexa.contexaidentity.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

@Slf4j
public class PlatformContextInitializer {

    private final PlatformContext platformContext;
    private final AuthContextProperties authContextProperties;
    private final ObjectMapper objectMapper;

    public PlatformContextInitializer(PlatformContext platformContext,
                                      AuthContextProperties authContextProperties,
                                      ObjectMapper objectMapper) { 
        this.platformContext = Objects.requireNonNull(platformContext, "platformContext cannot be null");
        this.authContextProperties = Objects.requireNonNull(authContextProperties, "authContextProperties cannot be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper cannot be null");
    }

    public void initializeSharedObjects() {
        log.debug("Initializing global shared objects in PlatformContext.");
        platformContext.share(AuthContextProperties.class, authContextProperties);
        platformContext.share(ObjectMapper.class, objectMapper);
        log.info("Global shared objects (AuthContextProperties, ObjectMapper) registered in PlatformContext.");
    }
}
