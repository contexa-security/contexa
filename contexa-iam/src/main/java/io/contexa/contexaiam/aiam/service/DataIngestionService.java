package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.common.event.dto.DomainEvent;


public interface DataIngestionService {

    
    void ingestEvent(DomainEvent event);

    
    void initialIndexing();
}