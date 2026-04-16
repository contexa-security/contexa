package io.contexa.autoconfigure.core.llm;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class AnyChatModelAvailableCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        if (!(context.getBeanFactory() instanceof ListableBeanFactory beanFactory)) {
            return false;
        }
        return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, ChatModel.class, true, false).length > 0;
    }
}