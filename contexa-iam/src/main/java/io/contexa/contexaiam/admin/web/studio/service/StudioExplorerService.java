package io.contexa.contexaiam.admin.web.studio.service;

import io.contexa.contexaiam.admin.web.studio.dto.ExplorerItemDto;
import java.util.List;
import java.util.Map;


public interface StudioExplorerService {
    
    Map<String, List<ExplorerItemDto>> getExplorerItems();
}