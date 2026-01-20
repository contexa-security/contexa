package io.contexa.contexaiam.resource.scanner;

import io.contexa.contexacommon.entity.ManagedResource;

import java.util.List;


public interface ResourceScanner {
    
    List<ManagedResource> scan();
}