// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

/**
 * Records a caught exception before the caller throws it again or recovers.
 * java.lang.System.Logger is in the JDK, so this adds no library. The
 * platform's default finder writes through java.util.logging, and the
 * exception's stack is part of the record.
 */
public final class Caught {
    private Caught() {}

    /** The failure leaves this method, usually as this library's own error. */
    public static void error(Throwable err) {
        emit(System.Logger.Level.ERROR, err);
    }

    /**
     * The method keeps going: a later attempt, a retry, or a result of
     * false. The exception is still recorded.
     */
    public static void warn(Throwable err) {
        emit(System.Logger.Level.WARNING, err);
    }

    private static void emit(System.Logger.Level level, Throwable err) {
        String detail;
        if (err == null || err.getMessage() == null
                || err.getMessage().isBlank()) {
            detail = String.valueOf(err);
        } else {
            detail = err.getMessage();
        }
        StackWalker.StackFrame frame = StackWalker.getInstance().walk(
                stream -> stream.skip(2).findFirst().orElseThrow());
        System.getLogger(frame.getClassName()).log(
                level,
                "Caught in " + frame.getMethodName() + "(): " + detail,
                err);
    }
}
