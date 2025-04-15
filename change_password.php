<?php
session_start();
require 'db.php';

if (!isset($_SESSION['loggedin'])) {
    header("Location: login.php");
    exit;
}

$success = '';
$error = '';

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Check CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        die("Invalid CSRF token.");
    }

    $old1 = $_POST['old_password1'] ?? '';
    $old2 = $_POST['old_password2'] ?? '';
    $new1 = $_POST['new_password1'] ?? '';
    $new2 = $_POST['new_password2'] ?? '';

    if (strlen($new1) < 8 || strlen($new2) < 8) {
        $error = "New passwords must be at least 8 characters long.";
    } elseif ($new1 !== $new2) {
        $error = "New passwords do not match.";
    } else {
        // Fetch user data
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['userid']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (
            $user &&
            password_verify($old1, $user['password1']) &&
            password_verify($old2, $user['password2'])
        ) {
            // Avoid re-using same password
            if (password_verify($new1, $user['password1']) || password_verify($new2, $user['password2'])) {
                $error = "New passwords must be different from the old ones.";
            } else {
                $hashed1 = password_hash($new1, PASSWORD_DEFAULT);
                $hashed2 = password_hash($new2, PASSWORD_DEFAULT);

                $update = $pdo->prepare("UPDATE users SET password1 = ?, password2 = ? WHERE id = ?");
                $update->execute([$hashed1, $hashed2, $user['id']]);

                $success = "Password changed successfully!";
            }
        } else {
            $error = "Current passwords are incorrect.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Change Password</title>
</head>
<body>

<h2>Change Password</h2>

<?php if ($success): ?>
    <p style="color:green;"><?= htmlspecialchars($success) ?></p>
<?php elseif ($error): ?>
    <p style="color:red;"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<form method="post">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

    Old Password 1: <input type="password" name="old_password1" required><br>
    Old Password 2: <input type="password" name="old_password2" required><br><br>

    New Password 1 (min 8 chars): <input type="password" name="new_password1" required><br>
    New Password 2 (repeat): <input type="password" name="new_password2" required><br><br>

    <input type="submit" value="Change Password">
</form>

<br>
<a href="index.php">Back</a>

</body>
</html>
