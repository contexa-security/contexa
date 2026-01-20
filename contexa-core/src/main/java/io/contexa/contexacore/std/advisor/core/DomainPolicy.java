package io.contexa.contexacore.std.advisor.core;

import org.springframework.ai.chat.client.ChatClientRequest;


public interface DomainPolicy {
    
    
    String getName();
    
    
    boolean isEnabled();
    
    
    ChatClientRequest apply(ChatClientRequest request);
    
    
    boolean validate(ChatClientRequest request);
    
    
    String getDescription();
}