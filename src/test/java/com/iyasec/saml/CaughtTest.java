// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CaughtTest {
    @Test
    void errorRecordsTheCatchSiteAndTheException() {
        assertRecorded(Level.SEVERE, System.Logger.Level.ERROR);
    }

    @Test
    void warnRecordsARecoveredException() {
        assertRecorded(Level.WARNING, System.Logger.Level.WARNING);
    }

    private static void assertRecorded(Level jul, System.Logger.Level level) {
        Logger logger = Logger.getLogger(CaughtTest.class.getName());
        Level old = logger.getLevel();
        boolean useParent = logger.getUseParentHandlers();
        Memory memory = new Memory();
        logger.addHandler(memory);
        logger.setLevel(Level.ALL);
        logger.setUseParentHandlers(false);
        IllegalStateException err = new IllegalStateException("boom");
        try {
            if (level == System.Logger.Level.ERROR) Caught.error(err);
            else Caught.warn(err);
        } finally {
            logger.removeHandler(memory);
            logger.setLevel(old);
            logger.setUseParentHandlers(useParent);
        }
        assertEquals(1, memory.records.size(), recordText(memory));
        LogRecord record = memory.records.get(0);
        assertEquals(jul, record.getLevel());
        assertTrue(record.getMessage().contains("Caught in assertRecorded()"), record.getMessage());
        assertTrue(record.getMessage().contains("boom"), record.getMessage());
        assertSame(err, record.getThrown());
    }

    private static String recordText(Memory memory) {
        if (memory.records.isEmpty()) return "no record";
        LogRecord record = memory.records.get(0);
        return record.getLevel() + " " + record.getMessage();
    }

    private static final class Memory extends Handler {
        private final List<LogRecord> records = new ArrayList<>();

        public void publish(LogRecord record) {
            records.add(record);
        }

        public void flush() {}

        public void close() {}
    }
}
