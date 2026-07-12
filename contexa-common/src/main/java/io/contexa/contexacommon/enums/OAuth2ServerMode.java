/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexacommon.enums;

/**
 * Selects which OAuth2 server responsibilities Contexa owns for an enabled OAuth2 state flow.
 */
public enum OAuth2ServerMode {
    RESOURCE_SERVER,
    AUTHORIZATION_SERVER,
    COMBINED;

    public boolean includesResourceServer() {
        return this == RESOURCE_SERVER || this == COMBINED;
    }

    public boolean includesAuthorizationServer() {
        return this == AUTHORIZATION_SERVER || this == COMBINED;
    }
}
