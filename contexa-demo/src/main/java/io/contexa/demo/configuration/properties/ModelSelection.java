package io.contexa.demo.configuration.properties;

public record ModelSelection(
        String provider,
        String model,
        Integer dimensions
) {

}
