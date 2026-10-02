package io.contexa.demo.workspace.slot.service.impl;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.slot.service.WorkspaceGenerationFence;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Service
public class DefaultWorkspaceGenerationFence implements WorkspaceGenerationFence {

    private static final byte[] STORAGE_MARKER = "lab:workspace:storage-generation".getBytes(StandardCharsets.UTF_8);
    private final WorkspaceAccessProperties properties;
    private final LabProperties lab;
    private final Environment environment;
    private final ObjectProvider<RedisConnectionFactory> redis;

    public DefaultWorkspaceGenerationFence(WorkspaceAccessProperties properties, LabProperties lab,
            Environment environment, ObjectProvider<RedisConnectionFactory> redis) {
        this.properties = properties;
        this.lab = lab;
        this.environment = environment;
        this.redis = redis;
    }

    @Override
    public void requireReady() {
        if (properties.workerSlotId().isBlank() || properties.workerGeneration() == null) {
            throw new IllegalStateException("Public workspace worker binding is missing");
        }
        String generation = properties.workerGeneration().toString().replace("-", "");
        requireDatabase("spring.datasource.url", generation);
        String cookie = environment.getRequiredProperty("server.servlet.session.cookie.name").replace("-", "").toLowerCase();
        if (!cookie.contains(generation) || !cookie.contains(lab.role())) {
            throw new IllegalStateException("Public workspace session cookie must identify generation and role");
        }
        if ("contexa".equals(lab.role())) {
            requireDatabase("contexa.datasource.url", generation);
            if ("distributed".equals(environment.getProperty("contexa.infrastructure.mode"))) {
                requireRedisGeneration();
            }
        }
    }

    private void requireDatabase(String property, String generation) {
        String value = environment.getRequiredProperty(property);
        if (!value.startsWith("jdbc:postgresql:") || !URI.create(value.substring(5)).getPath().contains(generation)) {
            throw new IllegalStateException("Public workspace database must identify the configured generation");
        }
    }

    private void requireRedisGeneration() {
        Integer database = environment.getProperty("spring.data.redis.database", Integer.class, 0);
        RedisConnectionFactory factory = redis.getIfAvailable();
        if (database < 1 || factory == null) {
            throw new IllegalStateException("Public distributed workspace requires an isolated non-default Redis database");
        }
        byte[] generation = properties.workerGeneration().toString().getBytes(StandardCharsets.UTF_8);
        try (RedisConnection connection = factory.getConnection()) {
            connection.stringCommands().setNX(STORAGE_MARKER, generation);
            if (!Arrays.equals(connection.stringCommands().get(STORAGE_MARKER), generation)) {
                throw new IllegalStateException("Redis contains a different workspace generation");
            }
        }
    }
}
