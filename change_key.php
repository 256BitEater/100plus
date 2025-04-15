<?php
session_start();
require 'db.php';

// Make sure user is logged in and encryption key is set
if (!isset($_SESSION['loggedin']) || !isset($_SESSION['encryption_key'])) {
    header("Location: login.php");
    exit;
}

function decrypt_text($encrypted, $key)
{
    $key = hash('sha256', $key);
    $data = base64_decode($encrypted);
    $iv = substr($data, 0, 16);
    $cipher = substr($data, 16);
    return openssl_decrypt($cipher, 'AES-256-CBC', $key, 0, $iv);
}

function encrypt_text($plaintext, $key)
{
    $key = hash('sha256', $key);
    $iv = openssl_random_pseudo_bytes(16);
    $cipher = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $cipher);
}

// CSRF helper
function generate_csrf_token()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        die("Invalid CSRF token.");
    }

    $currentKey = $_POST['current_key'] ?? '';
    $newKey = $_POST['new_key'] ?? '';
    $confirmKey = $_POST['confirm_key'] ?? '';

    if (strlen($newKey) < 8) {
        $message = "New key must be at least 8 characters long.";
    } elseif ($newKey !== $confirmKey) {
        $message = "New key and confirmation do not match.";
    } else {
        $stmt = $pdo->query("SHOW TABLES");
        $tables = array_filter($stmt->fetchAll(PDO::FETCH_COLUMN), fn($t) => $t !== 'users');

        try {
            $pdo->beginTransaction();

            $sampleTable = reset($tables);
            $sample = $pdo->query("SELECT * FROM `$sampleTable` LIMIT 1")->fetch(PDO::FETCH_ASSOC);
            if ($sample && !ctype_print(decrypt_text($sample['word'], $currentKey))) {
                throw new Exception("Invalid current key.");
            }

            foreach ($tables as $table) {

                $stmtRows = $pdo->query("SELECT * FROM `$table`");
                $rows = $stmtRows->fetchAll(PDO::FETCH_ASSOC);

                foreach ($rows as $row) {
                    $decryptedWord = decrypt_text($row['word'], $currentKey);
                    $decryptedTranslation = decrypt_text($row['translation'], $currentKey);
                    $decryptedExplanation = decrypt_text($row['explanation'], $currentKey);

                    if (
                        $decryptedWord === false || $decryptedTranslation === false || 
                        $decryptedExplanation === false
                    ) {
                        throw new Exception("Failed to decrypt data in table `$table`. Check your current key.");
                    }

                    $encryptedWord = encrypt_text($decryptedWord, $newKey);
                    $encryptedTranslation = encrypt_text($decryptedTranslation, $newKey);
                    $encryptedExplanation = encrypt_text($decryptedExplanation, $newKey);

                    $stmtUpdate = $pdo->prepare("UPDATE `$table` SET word = ?, translation = ?, explanation = ? WHERE id = ?");
                    $stmtUpdate->execute([
                        $encryptedWord,
                        $encryptedTranslation,
                        $encryptedExplanation,
                        $row['id']
                    ]);
                }
            }

            $pdo->commit();
            $_SESSION['encryption_key'] = $newKey;
            $message = "Encryption key updated successfully.";
        } catch (Exception $e) {
            $pdo->rollBack();
            $message = "Error: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Change Encryption Key</title>
</head>
<body>
    <h2>Change Your Encryption Key</h2>

    <?php if ($message): ?>
        <p style="color:<?= str_starts_with($message, 'Error') ? 'red' : 'green' ?>">
            <?= htmlspecialchars($message) ?>
        </p>
    <?php endif; ?>

    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>">

        <label>Current Key:</label><br>
        <input type="password" name="current_key" required><br><br>

        <label>New Key (min 8 characters):</label><br>
        <input type="password" name="new_key" required><br><br>

        <label>Confirm New Key:</label><br>
        <input type="password" name="confirm_key" required><br><br>

        <input type="submit" value="Change Key">
    </form>
    <br>
    <a href="index.php">Back to Dashboard</a>
</body>
</html>
