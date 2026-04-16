package io.contexa.autoconfigure.core.llm;

import org.springframework.ai.embedding.EmbeddingModel;
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
        return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, EmbeddingModel.class, true, false).length > 0;
    }
}