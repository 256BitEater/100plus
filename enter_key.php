<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
session_start();

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $csrf_token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        die("Invalid CSRF token.");
    }

    $encryption_key = trim($_POST['encryption_key']);
    if (strlen($encryption_key) < 8) {
        die("Encryption key too short.");
    }

    $_SESSION['encryption_key'] = $encryption_key;
    session_regenerate_id(true);
    header("Location: index.php");
    exit;
}

$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html>
<head>
    <title>Enter Encryption Key</title>
</head>
<body>
    <h2>Enter Your Encryption Key</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <input type="password" name="encryption_key" placeholder="Encryption Key" required autocomplete="off">
        <br>
        <button type="submit">Submit</button>
    </form>
</body>
</html>
