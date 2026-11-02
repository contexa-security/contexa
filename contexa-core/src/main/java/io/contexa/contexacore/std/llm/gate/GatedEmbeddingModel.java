/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.llm.gate;

import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.BatchingStrategy;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingOptions;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;

import java.util.List;
import java.util.function.Supplier;

/**
 * The embedding model Contexa's vector store embeds with, each call through the gate of its model server (O-1), so an
 * embedding goes in before the chats waiting for the same server instead of queueing behind all of them there.
 */
public final class GatedEmbeddingModel implements EmbeddingModel {

    private final EmbeddingModel delegate;
    private final ModelServerGates gates;
    private final String modelName;

    public GatedEmbeddingModel(EmbeddingModel delegate, ModelServerGates gates) {
        this.delegate = delegate;
        this.gates = gates;
        this.modelName = gates != null ? gates.embeddingModelName(delegate) : CallKind.EMBEDDING.name();
    }

    /** The embedding model the calls go to. */
    public EmbeddingModel delegate() {
        return delegate;
    }

    @Override
    public EmbeddingResponse call(EmbeddingRequest request) {
        return gated(() -> delegate.call(request));
    }

    @Override
    public float[] embed(Document document) {
        return gated(() -> delegate.embed(document));
    }

    @Override
    public String getEmbeddingContent(Document document) {
        return delegate.getEmbeddingContent(document);
    }

    @Override
    public float[] embed(String text) {
        return gated(() -> delegate.embed(text));
    }

    @Override
    public List<float[]> embed(List<String> texts) {
        return gated(() -> delegate.embed(texts));
    }

    @Override
    public List<float[]> embed(List<Document> documents, EmbeddingOptions options, BatchingStrategy batchingStrategy) {
        return gated(() -> delegate.embed(documents, options, batchingStrategy));
    }

    @Override
    public EmbeddingResponse embedForResponse(List<String> texts) {
        return gated(() -> delegate.embedForResponse(texts));
    }

    @Override
    public int dimensions() {
        return gated(delegate::dimensions);
    }

    private <T> T gated(Supplier<T> call) {
        ModelServerGate gate = gates != null ? gates.gateFor(delegate, CallKind.EMBEDDING) : null;
        if (gate == null) {
            return call.get();
        }
        ModelCallTimer timer = ModelCallTimer.current();
        ModelServerGate.Permit permit;
        try {
            permit = gate.enter(CallKind.EMBEDDING, modelName, gates.maxWaitMs(timer), timer);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for model server " + gate.server().key(),
                    interrupted);
        }
        try (permit) {
            return permit.scope(call::get).call();
        } catch (RuntimeException failure) {
            if (ModelServerSignals.isOverload(failure)) {
                permit.overloaded();
            }
            throw failure;
        } catch (Exception unreachable) {
            // The embedding call throws no checked exception.
            throw new IllegalStateException(unreachable);
        }
    }
}
