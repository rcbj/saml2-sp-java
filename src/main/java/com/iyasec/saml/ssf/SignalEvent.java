// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.ssf;

import java.util.List;
import java.util.Map;

/** One event inside a verified Security Event Token. */
public class SignalEvent {
    public String type;
    public Map<String, Object> payload = Map.of();
    public Map<String, String> subject = Map.of();
    public String jti;
    public List<String> sessions = List.of();
    public boolean ended;
    public Double iat;
    public String txn;
}
