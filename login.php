<?php
session_start();
require 'db.php';

$error = "";
$maxAttempts = 6;

// Initialize login attempt counter
$_SESSION['login_attempts'] = $_SESSION['login_attempts'] ?? 0;

// If over limit, block login
if ($_SESSION['login_attempts'] >= $maxAttempts) {
    die("Too many login attempts. Please try again later.");
}

// Generate CAPTCHA
if (!isset($_SESSION['captcha_question'])) {
    $a = rand(1, 10);
    $b = rand(1, 10);
    $_SESSION['captcha_answer'] = $a + $b;
    $_SESSION['captcha_question'] = "What is $a + $b?";
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'] ?? '';
    $password1 = $_POST['password1'] ?? '';
    $password2 = $_POST['password2'] ?? '';
    $captcha = (int) ($_POST['captcha'] ?? -1);

    // Check CAPTCHA
    if ($captcha !== $_SESSION['captcha_answer']) {
        $error = "Incorrect CAPTCHA.";
        $_SESSION['login_attempts']++;
    } else {
        // Fetch user from the 'users' table
        $stmt = $pdo->prepare("SELECT * FROM users WHERE user = :username");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (
            $user &&
            password_verify($password1, $user['password1']) &&
            password_verify($password2, $user['password2'])
        ) {
            session_regenerate_id(true);
            $_SESSION['loggedin'] = true;
            $_SESSION['username'] = htmlspecialchars($username);
            $_SESSION['userid'] = $user['id'];

            // Reset attempts and CAPTCHA
            $_SESSION['login_attempts'] = 0;
            unset($_SESSION['captcha_question'], $_SESSION['captcha_answer']);

            header("Location: enter_key.php");
            exit;
        } else {
            $error = "Invalid credentials. Please try again.";
            $_SESSION['login_attempts']++;
        }
    }

    // Refresh CAPTCHA
    $a = rand(1, 10);
    $b = rand(1, 10);
    $_SESSION['captcha_answer'] = $a + $b;
    $_SESSION['captcha_question'] = "What is $a + $b?";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>

<h2>Login</h2>

<?php if (!empty($error)): ?>
    <p class="error" style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<form method="post">
    <label>Username:</label>
    <input type="text" name="username" value="<?= htmlspecialchars($username ?? '') ?>" required><br>

    <label>Password 1:</label>
    <input type="password" name="password1" required><br>

    <label>Password 2:</label>
    <input type="password" name="password2" required><br>

    <label><?= $_SESSION['captcha_question'] ?>:</label>
    <input type="text" name="captcha" required><br><br>

    <input type="submit" value="Login">
</form>

</body>
</html>
