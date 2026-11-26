/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.contexa.contexacommon.security.bridge;

/**
 * Declares how Contexa settles with the security components an application brings itself. It is a separate setting from
 * {@link SecurityMode}, every pair of the two is valid, and neither value turns a feature of Contexa off.
 */
public enum SecurityOwnershipMode {

    /**
     * The application's own components win where it has them: its UserDetailsService, authentication providers, security
     * context repository, JwtDecoder and the like keep serving its requests. Contexa's own components still run, for
     * Contexa's own paths and Contexa's own work, and Contexa's administrators sign in apart from the application's users.
     */
    HOST_OWNED,

    /**
     * Contexa's components may serve the application as well, where the application has none of its own. With mode FULL
     * the application's users and Contexa's administrators then sign in on the one main chain.
     */
    CONTEXA_OWNED
}
