package io.contexa.autoconfigure.llm;

import io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.openai.OpenAiEmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CoreLLMTieredAutoConfigurationEmbeddingTest {

    @Test
    void shouldSelectOllamaEmbeddingModelByDefaultPriority() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ReflectionTestUtils.setField(configuration, "embeddingModelPriority", "ollama,openai");

        OllamaEmbeddingModel ollamaEmbeddingModel = mock(OllamaEmbeddingModel.class);
        OpenAiEmbeddingModel openAiEmbeddingModel = mock(OpenAiEmbeddingModel.class);
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("ollamaEmbeddingModel", ollamaEmbeddingModel);
        beanFactory.registerSingleton("openAiEmbeddingModel", openAiEmbeddingModel);

        ObjectProvider<OllamaEmbeddingModel> ollamaProvider = beanFactory.getBeanProvider(OllamaEmbeddingModel.class);
        ObjectProvider<OpenAiEmbeddingModel> openAiProvider = beanFactory.getBeanProvider(OpenAiEmbeddingModel.class);

        EmbeddingModel selected = configuration.primaryEmbeddingModel(ollamaProvider, openAiProvider);

        assertThat(selected).isSameAs(ollamaEmbeddingModel);
    }

    @Test
    void shouldSelectOpenAiEmbeddingModelWhenPriorityChanges() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ReflectionTestUtils.setField(configuration, "embeddingModelPriority", "openai,ollama");

        OllamaEmbeddingModel ollamaEmbeddingModel = mock(OllamaEmbeddingModel.class);
        OpenAiEmbeddingModel openAiEmbeddingModel = mock(OpenAiEmbeddingModel.class);
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("ollamaEmbeddingModel", ollamaEmbeddingModel);
        beanFactory.registerSingleton("openAiEmbeddingModel", openAiEmbeddingModel);

        ObjectProvider<OllamaEmbeddingModel> ollamaProvider = beanFactory.getBeanProvider(OllamaEmbeddingModel.class);
        ObjectProvider<OpenAiEmbeddingModel> openAiProvider = beanFactory.getBeanProvider(OpenAiEmbeddingModel.class);

        EmbeddingModel selected = configuration.primaryEmbeddingModel(ollamaProvider, openAiProvider);

        assertThat(selected).isSameAs(openAiEmbeddingModel);
    }
}