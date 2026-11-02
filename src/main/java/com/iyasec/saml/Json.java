// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/** JSON objects and arrays through the parser Nimbus already ships. */
public final class Json {
    private Json() {}

    public static Object parse(String text) {
        String trimmed = text == null ? "" : text.strip();
        try {
            if (trimmed.startsWith("[")) return JSONObjectUtils.parse("{\"v\":" + trimmed + "}").get("v");
            if (trimmed.startsWith("{")) return new LinkedHashMap<>(JSONObjectUtils.parse(trimmed));
        } catch (ParseException err) {
            throw new IllegalArgumentException(err);
        }
        throw new IllegalArgumentException("not JSON");
    }

    public static String stringify(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> typed = new LinkedHashMap<>();
            map.forEach((key, item) -> typed.put(String.valueOf(key), item));
            return JSONObjectUtils.toJSONString(typed);
        }
        Map<String, Object> wrapped = new LinkedHashMap<>();
        wrapped.put("v", value);
        String json = JSONObjectUtils.toJSONString(wrapped);
        return json.substring(json.indexOf(':') + 1, json.length() - 1);
    }
}
