package io.contexa.demo.readiness.client;

import io.contexa.demo.readiness.dto.WorkerReadiness;

import java.net.URI;
import java.util.concurrent.CompletableFuture;

public interface WorkerReadinessClient {

    CompletableFuture<WorkerReadiness> inspect(String role, URI endpoint);
}
