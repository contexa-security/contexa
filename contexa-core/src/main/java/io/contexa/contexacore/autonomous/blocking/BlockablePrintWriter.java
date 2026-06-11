/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.blocking;

import java.io.PrintWriter;

/**
 * PrintWriter wrapper that checks BlockingSignalBroadcaster before every write.
 * Throws ResponseBlockedException (RuntimeException) on block detection,
 * bypassing PrintWriter's internal IOException suppression.
 */
public class BlockablePrintWriter extends PrintWriter {

    private final BlockingSignalBroadcaster registry;
    private final String userId;

    public BlockablePrintWriter(PrintWriter delegate,
                                BlockingSignalBroadcaster registry,
                                String userId) {
        super(delegate, true);
        this.registry = registry;
        this.userId = userId;
    }

    @Override
    public void write(int c) {
        checkBlocked();
        super.write(c);
    }

    @Override
    public void write(char[] buf, int off, int len) {
        if (buf == null || len == 0) {
            return;
        }
        checkBlocked();
        super.write(buf, off, len);
    }

    @Override
    public void write(String s, int off, int len) {
        if (s == null || len == 0) {
            return;
        }
        checkBlocked();
        super.write(s, off, len);
    }

    @Override
    public void flush() {
        checkBlocked();
        super.flush();
    }

    private void checkBlocked() {
        if (registry != null && registry.isBlocked(userId)) {
            throw new ResponseBlockedException(
                    "Response aborted: user " + userId + " blocked by security decision");
        }
    }
}
