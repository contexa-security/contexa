package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.core.llm.runtime.SpringModelServerResolver;
import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.ModelServerGateProperties;
import io.contexa.contexacore.std.llm.gate.CallKind;
import io.contexa.contexacore.std.llm.gate.GatedEmbeddingModel;
import io.contexa.contexacore.std.llm.gate.ModelServer;
import io.contexa.contexacore.std.llm.gate.ModelServerGate;
import io.contexa.contexacore.std.llm.gate.ModelServerGates;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * O-1 wiring: which server a model calls, the gate a self-hosted and a remote server get, and the embedding model of
 * Contexa's vector store passing its server's gate.
 */
class ModelServerGateWiringTest {

    @Test
    void aModelContexaBuiltCallsTheAddressItWasBuiltWith() {
        SpringModelServerResolver resolver = new SpringModelServerResolver(new MockEnvironment());
        OllamaChatModel chat = mock(OllamaChatModel.class);
        OllamaEmbeddingModel embedding = mock(OllamaEmbeddingModel.class);
        resolver.register(chat, "ollama", "http://localhost:11434/", "qwen3:8b");
        resolver.register(embedding, "ollama", "http://127.0.0.1:11434", "mxbai-embed-large");

        assertThat(resolver.resolve(chat, CallKind.CHAT)).isEqualTo(new ModelServer("ollama",
                "http://localhost:11434", true));
        assertThat(resolver.resolve(embedding, CallKind.EMBEDDING).address()).isEqualTo("http://127.0.0.1:11434");
        assertThat(resolver.embeddingModelName(embedding)).isEqualTo("mxbai-embed-large");
    }

    @Test
    void anyOtherModelCallsItsProvidersConfiguredOrPublicAddress() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.ai.ollama.base-url", "http://gpu-box:11434")
                .withProperty("spring.ai.ollama.embedding.options.model", "nomic-embed-text");
        SpringModelServerResolver resolver = new SpringModelServerResolver(environment);

        ModelServer ollama = resolver.resolve(mock(OllamaChatModel.class), CallKind.CHAT);
        ModelServer openAi = resolver.resolve(mock(OpenAiChatModel.class), CallKind.CHAT);
        ModelServer anthropic = resolver.resolve(mock(AnthropicChatModel.class), CallKind.CHAT);

        assertThat(ollama).isEqualTo(new ModelServer("ollama", "http://gpu-box:11434", true));
        assertThat(openAi).isEqualTo(new ModelServer("openai", "https://api.openai.com:443", false));
        assertThat(anthropic).isEqualTo(new ModelServer("anthropic", "https://api.anthropic.com:443", false));
        assertThat(resolver.embeddingModelName(mock(OllamaEmbeddingModel.class))).isEqualTo("nomic-embed-text");
    }

    @Test
    void aSelfHostedServerTakesTwoCallsAndOneModelAtATimeARemoteOneSixteen() {
        ModelServerGates gates = new ModelServerGates(new SpringModelServerResolver(new MockEnvironment()),
                new ModelServerGateProperties(), 180_000L);

        ModelServerGate local = gates.gateFor(mock(OllamaChatModel.class), CallKind.CHAT);
        ModelServerGate remote = gates.gateFor(mock(OpenAiChatModel.class), CallKind.CHAT);

        assertThat(local.maxConcurrent()).isEqualTo(2);
        assertThat(local.oneModelAtATime()).isTrue();
        assertThat(remote.maxConcurrent()).isEqualTo(16);
        assertThat(remote.oneModelAtATime()).isFalse();
        // The chat and the embedding model of one Ollama share its gate.
        assertThat(gates.gateFor(mock(OllamaEmbeddingModel.class), CallKind.EMBEDDING)).isSameAs(local);
    }

    @Test
    void aServerCanBeGivenItsOwnSettingsAndTheGatesTurnedOff() {
        ModelServerGateProperties properties = new ModelServerGateProperties();
        ModelServerGateProperties.Server server = new ModelServerGateProperties.Server();
        server.setBaseUrl("http://localhost:11434");
        server.setMaxConcurrent(4);
        server.setOneModelAtATime(false);
        properties.getServers().put("big-gpu", server);
        ModelServerGates gates = new ModelServerGates(new SpringModelServerResolver(new MockEnvironment()),
                properties, 180_000L);

        ModelServerGate local = gates.gateFor(mock(OllamaChatModel.class), CallKind.CHAT);
        assertThat(local.maxConcurrent()).isEqualTo(4);
        assertThat(local.oneModelAtATime()).isFalse();

        properties.setEnabled(false);
        assertThat(gates.gateFor(mock(OllamaChatModel.class), CallKind.CHAT)).isNull();
    }

    @Test
    void contexasVectorStoreEmbedsThroughTheGate() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ReflectionTestUtils.setField(configuration, "contexaProperties", new ContexaProperties());
        ContexaLlmSelectionProperties selection = new ContexaLlmSelectionProperties();
        selection.getEmbedding().setPriority("ollama");
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selection);
        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        EmbeddingModel ollama = mock(OllamaEmbeddingModel.class);
        when(catalog.resolvePrimaryEmbeddingModel("ollama")).thenReturn(Optional.of(ollama));
        ModelServerGates gates = new ModelServerGates(new SpringModelServerResolver(new MockEnvironment()),
                new ModelServerGateProperties(), 180_000L);

        EmbeddingModel primary = configuration.fixedPrimaryEmbeddingModel(catalog, providing(gates));

        assertThat(primary).isInstanceOf(GatedEmbeddingModel.class);
        assertThat(((GatedEmbeddingModel) primary).delegate()).isSameAs(ollama);
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<ModelServerGates> providing(ModelServerGates gates) {
        ObjectProvider<ModelServerGates> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(gates);
        return provider;
    }
}
