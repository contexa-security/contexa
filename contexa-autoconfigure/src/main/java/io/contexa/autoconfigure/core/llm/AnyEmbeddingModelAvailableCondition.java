package io.contexa.autoconfigure.core.llm;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class AnyEmbeddingModelAvailableCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        if (!(context.getBeanFactory() instanceof ListableBeanFactory beanFactory)) {
            return false;
        }

        return hasBean(beanFactory, "org.springframework.ai.ollama.OllamaEmbeddingModel")
                || hasBean(beanFactory, "org.springframework.ai.openai.OpenAiEmbeddingModel");
    }

    private boolean hasBean(ListableBeanFactory beanFactory, String className) {
        try {
            Class<?> beanType = Class.forName(className);
            return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, beanType, true, false).length > 0;
        }
        catch (ClassNotFoundException ignored) {
            return false;
        }
    }
}