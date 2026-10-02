package io.contexa.demo.comparison.manifest.source;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

public interface PolicyConfigurationQuery {

    Map<String, JsonNode> capture();
}
