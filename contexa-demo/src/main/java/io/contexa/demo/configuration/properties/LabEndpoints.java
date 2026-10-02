package io.contexa.demo.configuration.properties;

import java.net.URI;

public record LabEndpoints(
        URI baseline,
        URI contexa
) {

}
