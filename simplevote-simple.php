<?php
//ini_set('display_errors', 1);
//error_reporting(E_ALL);

// === DB SETUP ===
$db = new PDO('sqlite:' . __DIR__ . '/database.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


// Create tables if not exist
$db->exec("
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    voted_for INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    action TEXT NOT NULL, -- 'login' or 'vote'
    attempt_time INTEGER NOT NULL
);
");
define('RATE_LIMIT_WINDOW', 300); // seconds (e.g. 5 minutes)
define('RATE_LIMIT_MAX', 5);      // max attempts in window

function too_many_attempts($db, $ip, $action) {
    $now = time();
    $stmt = $db->prepare("SELECT COUNT(*) FROM ip_attempts 
                          WHERE ip = ? AND action = ? AND attempt_time > ?");
    $stmt->execute([$ip, $action, $now - RATE_LIMIT_WINDOW]);
    return $stmt->fetchColumn() >= RATE_LIMIT_MAX;
}

function log_attempt($db, $ip, $action) {
    $stmt = $db->prepare("INSERT INTO ip_attempts (ip, action, attempt_time) VALUES (?, ?, ?)");
    $stmt->execute([$ip, $action, time()]);
}



// Auto-login via cookie if valid
if (!isset($_SESSION)) session_start();

if (!isset($_SESSION['admin']) && isset($_COOKIE['admin_auth'])) {
    $cookie_user = $_COOKIE['admin_auth'];

    $stmt = $db->prepare("SELECT * FROM admin WHERE username = ?");
    $stmt->execute([$cookie_user]);
    if ($stmt->fetch()) {
        $_SESSION['admin'] = $cookie_user; // Rehydrate session
    }
}

// === Add default admin on first run ===
$stmt = $db->query("SELECT COUNT(*) FROM admin");
if ($stmt->fetchColumn() == 0) {
    $db->prepare("INSERT INTO admin (username, password_hash) VALUES (?, ?)")
       ->execute(['admin', password_hash('admin123', PASSWORD_DEFAULT)]);
}

// === HANDLE ADMIN LOGIN ===
if (isset($_POST['login'])) {
    $stmt = $db->prepare("SELECT * FROM admin WHERE username = ?");
    $stmt->execute([$_POST['username']]);
    $admin = $stmt->fetch();
    
    $ip = $_SERVER['REMOTE_ADDR'];

if (too_many_attempts($db, $ip, 'login')) {
    die("Too many login attempts. Please try again later.");
}
$db->exec("DELETE FROM ip_attempts WHERE attempt_time < " . (time() - 86400)); // 1-day cleanup


    if ($admin && password_verify($_POST['password'], $admin['password_hash'])) {
        setcookie('admin_auth', $admin['username'], time() + (86400 * 7), "/"); // 7-day login
$_SESSION['admin'] = $admin['username'];

    } else {
        echo "<p style='color:red;'>Login failed</p>";
        log_attempt($db, $ip, 'login');
    }
}

// === HANDLE ADMIN LOGOUT ===
if (isset($_GET['logout'])) {
setcookie('admin_auth', '', time() - 3600, "/"); // Remove cookie
session_destroy();
header("Location: index.php");
exit;
}

// === HANDLE TOKEN GENERATION ===
if (isset($_POST['generate_tokens']) && isset($_SESSION['admin'])) {
    $amount = (int)$_POST['amount'];
    $pool_size = max(10000, $amount * 2);
    $token_pool = [];

    while (count($token_pool) < $pool_size) {
        $token = bin2hex(random_bytes(10));
        $token_pool[$token] = true; // ensure uniqueness
    }

    $unique_tokens = array_keys($token_pool);
    shuffle($unique_tokens);

    $generated = array_slice($unique_tokens, 0, $amount);

    // Save tokens to DB and collect for CSV
    $csv = fopen(__DIR__ . "/generated_tokens.csv", "w");
    fputcsv($csv, ['Token']);

    foreach ($generated as $token) {
        $hash = password_hash($token, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO tokens (token_hash) VALUES (?)");
        $stmt->execute([$hash]);
        fputcsv($csv, [$token]);
    }

    fclose($csv);

    echo "<h3>Generated $amount Tokens</h3>";
    echo "<p><a href='generated_tokens.csv' download>Download CSV</a></p>";
    echo "<ul>";
    foreach ($generated as $token) {
        echo "<li>$token</li>";
    }
    echo "</ul><hr>";
}



// === HANDLE ADD CANDIDATE ===
if (isset($_POST['add_candidate']) && isset($_SESSION['admin'])) {
    $stmt = $db->prepare("INSERT INTO candidates (name) VALUES (?)");
    $stmt->execute([trim($_POST['candidate_name'])]);
}

// === HANDLE VOTE ===
if (isset($_POST['vote'])) {
    $token_input = $_POST['token'];
    $candidate_id = $_POST['candidate'];
    
$ip = $_SERVER['REMOTE_ADDR'];

if (too_many_attempts($db, $ip, 'vote')) {
    die("<p style='color:red;'>Too many failed attempts. Try again later.</p>");
}
$db->exec("DELETE FROM ip_attempts WHERE attempt_time < " . (time() - 86400)); // 1-day cleanup

    $stmt = $db->query("SELECT * FROM tokens WHERE used = 0");
    $found = false;
    foreach ($stmt as $row) {
        if (password_verify($token_input, $row['token_hash'])) {
            $found = true;
            $stmt2 = $db->prepare("UPDATE tokens SET used = 1, voted_for = ? WHERE id = ?");
            $stmt2->execute([$candidate_id, $row['id']]);
            echo "<p style='color:green;'>Vote cast successfully!</p>";
            break;
        }
    }
    if (!$found) {
        echo "<p style='color:red;'>Invalid or used token.</p>";
        log_attempt($db, $ip, 'vote');
    }
}

// === HTML ===
?>
<!DOCTYPE html>
<html>
<head><title>Voting App</title></head>
<body style="font-family:sans-serif;">
<h2>Simple Voting App</h2>

<?php if (isset($_SESSION['admin'])): ?>
    <p>Logged in as <strong><?=htmlspecialchars($_SESSION['admin'])?></strong> | <a href="?logout=1">Logout</a></p>

    <h3>Generate Tokens</h3>
    <form method="POST">
        <input type="number" name="amount" required min="1" placeholder="How many?">
        <button type="submit" name="generate_tokens">Generate</button>
    </form>

    <h3>Add Candidate</h3>
    <form method="POST">
        <input type="text" name="candidate_name" required placeholder="Candidate Name">
        <button type="submit" name="add_candidate">Add</button>
    </form>
    
<h3>Candidates</h3>
<table border="1" cellpadding="5" cellspacing="0">
<tr>
    <th>Name</th>
    <th>Votes</th>
    <th>Action</th>
</tr>
<?php
$candidates = $db->query("SELECT * FROM candidates")->fetchAll();
foreach ($candidates as $cand):
    $stmt = $db->prepare("SELECT COUNT(*) FROM tokens WHERE voted_for = ?");
    $stmt->execute([$cand['id']]);
    $count = $stmt->fetchColumn();
?>
<tr>
    <td><?=htmlspecialchars($cand['name'])?></td>
    <td><?=$count?></td>
    <td>
        <a href="?delete_candidate=<?=$cand['id']?>" onclick="return confirm('Delete this candidate?');">🗑️</a>
    </td>
</tr>
<?php endforeach; ?>
</table>

<?php elseif (!isset($_SESSION['admin']) && isset($_GET['admin'])): ?>
    <h3>Admin Login</h3>
    <form method="POST">
        <input type="text" name="username" placeholder="admin"><br>
        <input type="password" name="password" placeholder="admin123"><br>
        <button type="submit" name="login">Login</button>
    </form>
    <p>Default: admin / admin123</p>

<?php else: ?>
    <h3>Vote Here</h3>
    <form method="POST">
        <input type="text" name="token" required placeholder="Enter your token"><br><br>
        <select name="candidate" required>
            <option value="">-- Select Candidate --</option>
            <?php
                $candidates = $db->query("SELECT * FROM candidates")->fetchAll();
                foreach ($candidates as $cand) {
                    echo "<option value='{$cand['id']}'>".htmlspecialchars($cand['name'])."</option>";
                }
            ?>
        </select><br><br>
        <button type="submit" name="vote">Cast Vote</button>
    </form>

    <p><a href="?admin=1">Admin Login</a></p>
<?php endif; ?>
</body>
</html>
