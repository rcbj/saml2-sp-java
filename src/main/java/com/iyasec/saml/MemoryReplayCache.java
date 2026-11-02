// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/** Remembers which assertions have been accepted, so none is accepted twice. */
public final class MemoryReplayCache {
    private final Map<String, Long> entries = new LinkedHashMap<>();
    private final int max;
    private final Object lock = new Object();

    public MemoryReplayCache() { this(10_000); }

    public MemoryReplayCache(int max) { this.max = max; }

    /** @return true when this assertion was already accepted and is still live */
    public boolean checkAndRecord(String assertionId, Instant expiresAt) {
        long now = Instant.now().toEpochMilli();
        synchronized (lock) {
            Long until = entries.get(assertionId);
            if (until != null && until > now) return true;
            if (entries.size() >= max) {
                var expired = new ArrayList<String>();
                entries.forEach((key, value) -> { if (value <= now) expired.add(key); });
                expired.forEach(entries::remove);
                if (entries.size() >= max) {
                    throw new IllegalStateException("the replay cache holds " + max + " live assertions and cannot record another");
                }
            }
            entries.put(assertionId, expiresAt.toEpochMilli());
            return false;
        }
    }
}
