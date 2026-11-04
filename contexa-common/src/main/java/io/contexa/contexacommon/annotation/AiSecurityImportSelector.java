/* Copyright 2026 The Contexa Project */
package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootVersion;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.type.AnnotationMetadata;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/** Loads the Contexa configuration and publishes annotation values into this context's Environment. */
public class AiSecurityImportSelector implements ImportSelector, EnvironmentAware {

    public static final String PROP_ENABLED = "contexa.enabled";
    public static final String PROP_MODE = ContexaOperatingProfile.PROP_MODE;
    public static final String PROP_AUTH_OBJECT_LOCATION = "contexa.ai.security.auth-object.location";
    public static final String PROP_AUTH_OBJECT_ATTRIBUTE = "contexa.ai.security.auth-object.attribute";
    public static final String PROP_AUTH_OBJECT_TYPE = "contexa.ai.security.auth-object.type";
    public static final String PROP_BRIDGE_OWNERSHIP = ContexaOperatingProfile.PROP_OWNERSHIP;
    public static final String PROP_CONTEXA_OWNED_APPLICATION =
            ContexaOperatingProfile.PROP_APPLICATION_DATA;
    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";
    private final Function<Environment, String> databaseProblem;
    private final Function<Environment, String> redisProblem;
    private ConfigurableEnvironment environment;

    public AiSecurityImportSelector() {
        this(new ContexaDatabaseProbe()::problem);
    }

    AiSecurityImportSelector(Function<Environment, String> databaseProblem) {
        this(databaseProblem, new ContexaRedisProbe()::problem);
    }

    AiSecurityImportSelector(Function<Environment, String> databaseProblem, Function<Environment, String> redisProblem) {
        this.databaseProblem = databaseProblem;
        this.redisProblem = redisProblem;
    }

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        if (environment != null && !environment.getProperty(PROP_ENABLED, Boolean.class, true)) {
            return new String[0];
        }

        String version = SpringBootVersion.getVersion();
        if (version.startsWith("4.")) {
            LoggerFactory.getLogger(AiSecurityImportSelector.class)
                    .error("Contexa does not support Spring Boot 4.x. Current version: {}. Please downgrade to Spring Boot 3.x.", version);
            throw new IllegalStateException("Spring Boot 4.x is not supported by Contexa. Current version: " + version);
        }

        Map<String, Object> attributes = importingClassMetadata
                .getAnnotationAttributes(EnableAISecurity.class.getName(), false);
        SecurityMode mode = SecurityMode.SANDBOX;
        AuthObjectLocation location = AuthObjectLocation.AUTO;
        String attribute = "";
        String type = Object.class.getName();
        if (attributes != null) {
            if (attributes.get("mode") instanceof SecurityMode declaredMode) {
                mode = declaredMode;
            }
            if (attributes.get("authObjectLocation") instanceof AuthObjectLocation declaredLocation) {
                location = declaredLocation;
            }
            if (attributes.get("authObjectAttribute") instanceof String declaredAttribute) {
                attribute = declaredAttribute;
            }
            if (attributes.get("authObjectType") instanceof Class<?> declaredType) {
                type = declaredType.getName();
            }
        }

        if (environment == null) {
            return new String[]{AI_SECURITY_CONFIGURATION};
        }
        ContexaOperatingProfile.refuseReactive(environment);
        ContexaOperatingProfile.refuseDistributedWithoutRedis(environment, getClass().getClassLoader());
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(ContexaOperatingProfile.modeSet(environment, mode), environment);
        if (staysOffWithoutItsDatabase(profile)) {
            return new String[0];
        }

        Map<String, Object> activation = new LinkedHashMap<>();
        activation.put(PROP_MODE, profile.mode().name());
        activation.put(PROP_AUTH_OBJECT_LOCATION, environment.getProperty(PROP_AUTH_OBJECT_LOCATION, location.name()));
        activation.put(PROP_AUTH_OBJECT_ATTRIBUTE, environment.getProperty(PROP_AUTH_OBJECT_ATTRIBUTE, attribute != null ? attribute : ""));
        activation.put(PROP_AUTH_OBJECT_TYPE, environment.getProperty(PROP_AUTH_OBJECT_TYPE, type != null ? type : Object.class.getName()));
        // what is published is the one spelling, so whatever reads these settings later reads the same value
        activation.put(PROP_BRIDGE_OWNERSHIP, profile.ownership().name());
        activation.put(PROP_CONTEXA_OWNED_APPLICATION, profile.contexaOwnsApplicationData());
        // First, for the one spelling. Every value above already gave way to what an operator set, as with any Spring setting.
        environment.getPropertySources().addFirst(new MapPropertySource("contexaAiSecurityAnnotation", activation));
        return new String[]{AI_SECURITY_CONFIGURATION};
    }

    /**
     * An application that keeps its own sign-in runs without Contexa rather than not at all: with Contexa's database down it
     * starts exactly as it does with Contexa off. Where Contexa owns the sign-in nobody could sign in without it, so that
     * application fails to start, as it always did.
     */
    private boolean staysOffWithoutItsDatabase(ContexaOperatingProfile profile) {
        if (profile.ownership() != SecurityOwnershipMode.HOST_OWNED) {
            return false;
        }
        String redis = redisProblem.apply(environment);
        if (redis != null) {
            LoggerFactory.getLogger(AiSecurityImportSelector.class).error(
                    "Contexa's Redis cannot be reached ({}): the application starts without Contexa, and nothing of it is active. "
                            + "Restart the application once Redis is back.", redis);
            return true;
        }
        String problem = databaseProblem.apply(environment);
        if (problem == null) {
            return false;
        }
        LoggerFactory.getLogger(AiSecurityImportSelector.class).error(
                "Contexa's database cannot be reached ({}): the application starts without Contexa, and nothing of it is active. "
                        + "Restart the application once the database is back.", problem);
        return true;
    }

    @Override
    public void setEnvironment(Environment environment) {
        if (environment instanceof ConfigurableEnvironment configurableEnvironment) {
            this.environment = configurableEnvironment;
        }
    }
}
