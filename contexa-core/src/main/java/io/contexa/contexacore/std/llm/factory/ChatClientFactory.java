package io.contexa.contexacore.std.llm.factory;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;


public interface ChatClientFactory {
    
    
    ChatClient createChatClient(ChatModel chatModel, ExecutionContext context);
    
    
    ChatClient createDefaultChatClient(ChatModel chatModel);
    
    
    ChatClient getCachedChatClient(String cacheKey);
    
    
    void cacheChatClient(String cacheKey, ChatClient chatClient);
    
    
    void clearCache();
}