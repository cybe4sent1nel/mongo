<?php
/**
 * Round 17: direct unit-level adversarial probing of WP_MySQL_On_SQLite's
 * query translator -- the MySQL-string-literal -> SQLite-string-literal
 * re-quoting path is the classic bug class for MySQL-on-SQLite shims
 * (MySQL allows backslash-escapes inside quoted strings; standard SQLite
 * does not -- a re-quoter that doesn't fully decode before re-emitting can
 * let a "safely escaped" MySQL value break out of its SQLite string).
 *
 * Runs directly against the driver class (no full WP bootstrap needed --
 * it's a self-contained PDO subclass), so failures are cheap to iterate.
 */

require_once '/home/user/drivers/sqlite-database-integration/packages/mysql-on-sqlite/src/load.php';

$dbfile = '/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/probe.sqlite';
@unlink($dbfile);

$pdo = new WP_MySQL_On_SQLite("mysql-on-sqlite:path={$dbfile};dbname=probe");

$pdo->query("CREATE TABLE probe (id INT PRIMARY KEY AUTO_INCREMENT, val TEXT, secret TEXT)");
$pdo->query("INSERT INTO probe (val, secret) VALUES ('placeholder', 'TOP_SECRET_VALUE')");

function try_query($pdo, $label, $sql) {
    echo "--- $label ---\n";
    echo "SQL: $sql\n";
    try {
        $stmt = $pdo->query($sql);
        if ($stmt) {
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo "OK, rows: " . json_encode($rows) . "\n";
        } else {
            echo "OK, no result set\n";
        }
    } catch (Throwable $e) {
        echo "EXCEPTION: " . get_class($e) . ": " . $e->getMessage() . "\n";
    }
    echo "\n";
}

// Baseline: normal escaped quote (MySQL backslash-escape style), should just
// insert the literal value "it's a test" -- confirms basic behavior.
try_query($pdo, "baseline backslash-quote", "INSERT INTO probe (val) VALUES ('it\\'s a test')");

// Attempt 1: classic backslash-quote-mismatch injection.
// In MySQL: 'x\' OR '1'='1' -- decodes to the single string  x' OR '1'='1
// (backslash escapes the quote, rest is literal text, not new SQL).
// If the translator's decode+requote pipeline is correct, this must land
// as an inert string value. If it instead treats \' the way SQLite would
// (backslash not an escape char) it will terminate the string early and
// " OR '1'='1" becomes live SQL -- a classic tautology injection.
try_query($pdo, "backslash-quote tautology attempt",
    "SELECT * FROM probe WHERE val = 'x\\' OR '1'='1'");

// Attempt 2: use the mismatch to try to exfiltrate the secret column via
// an injected UNION, entirely inside what should be one string literal.
try_query($pdo, "backslash-quote UNION exfiltration attempt",
    "SELECT val FROM probe WHERE val = 'nomatch\\' UNION SELECT secret FROM probe -- '");

// Attempt 3: trailing-backslash-before-closing-quote edge case -- a value
// that is JUST a backslash. MySQL: '\\\\' is one backslash. If mishandled,
// an odd number of trailing backslashes could shift which quote the
// translator treats as the closing one.
try_query($pdo, "trailing single backslash value",
    "INSERT INTO probe (val) VALUES ('\\\\')");
try_query($pdo, "trailing backslash then injection",
    "SELECT * FROM probe WHERE val = '\\\\' OR '1'='1'");

// Attempt 4: double single-quote (ANSI-style) escaping mixed with backslash
// in the same literal.
try_query($pdo, "mixed doubled-quote + backslash",
    "SELECT * FROM probe WHERE val = 'a''b\\'c'");

// Attempt 5: NUL byte plus injection payload immediately after (checking
// the CAST(x'...' AS TEXT) path for null bytes doesn't reintroduce a
// mis-parse when the payload contains further quotes after the null byte).
try_query($pdo, "null byte followed by injection tail",
    "SELECT * FROM probe WHERE val = 'a\\0' OR '1'='1'");

// Attempt 6: stacked query via semicolon (should be rejected/ignored by
// PDO::query which only executes a single statement, but confirm).
try_query($pdo, "stacked query attempt",
    "SELECT * FROM probe WHERE id = 1; DROP TABLE probe");

// Verify probe table + secret still intact after all attempts.
try_query($pdo, "final state check", "SELECT * FROM probe");
