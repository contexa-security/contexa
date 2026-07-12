/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.contexa.contexacommon.security.bridge;

/**
 * Declares which system owns authentication state for a bridge integration.
 */
public enum SecurityOwnershipMode {

    /** The host owns authentication; Contexa may only read bridge evidence. */
    HOST_OWNED,

    /** Contexa owns authentication and may create and persist its security context. */
    CONTEXA_OWNED
}
