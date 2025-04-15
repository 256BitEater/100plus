<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1); // Only if using HTTPS
ini_set('session.use_strict_mode', 1);
session_start();
session_regenerate_id(true);

require 'db.php';

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log($e->getMessage());
    die("A database error occurred.");
}

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

function generate_csrf_token()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token)
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function get_user_key()
{
    if (!isset($_SESSION['encryption_key'])) {
        die('Encryption key not set. Please re-login.');
    }
    return hash('sha256', $_SESSION['encryption_key']);
}

function encrypt_text($plaintext)
{
    $key = get_user_key();
    $iv = openssl_random_pseudo_bytes(16);
    $cipher = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $cipher);
}

function decrypt_text($encrypted)
{
    $key = get_user_key();
    $data = base64_decode($encrypted);
    $iv = substr($data, 0, 16);
    $cipher = substr($data, 16);
    return openssl_decrypt($cipher, 'AES-256-CBC', $key, 0, $iv);
}

$allowedTables = ['words1', 'words2', 'words3'];

$currentTable = $_GET['table'] ?? $_SESSION['current_table'] ?? null;
if ($currentTable && in_array($currentTable, $allowedTables)) {
    $_SESSION['current_table'] = $currentTable;
} else {
    $currentTable = null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        die("Invalid CSRF token.");
    }

    if (isset($_POST['edit_word']) && $currentTable) {
        $id = $_POST['id'];
        $word = trim($_POST['word'] ?? '');
        $translation = trim($_POST['translation'] ?? '');
        $explanation = trim($_POST['explanation'] ?? '');

        if (is_numeric($id) && $word && $translation && $explanation) {
            $stmt = $pdo->prepare("UPDATE `$currentTable` SET word=?, translation=?, explanation=? WHERE id=?");
            $stmt->execute([
                encrypt_text($word),
                encrypt_text($translation),
                encrypt_text($explanation),
                $id
            ]);
        }
    }

    if (isset($_POST['add_word']) && $currentTable) {
        $word = trim($_POST['word'] ?? '');
        $translation = trim($_POST['translation'] ?? '');
        $explanation = trim($_POST['explanation'] ?? '');
        if ($word && $translation && $explanation) {
            $stmt = $pdo->prepare("INSERT INTO `$currentTable` (word, translation, explanation) VALUES (?, ?, ?)");
            $stmt->execute([
                encrypt_text($word),
                encrypt_text($translation),
                encrypt_text($explanation)
            ]);
        }
    }
}

if (isset($_GET['delete']) && $currentTable && is_numeric($_GET['delete'])) {
    $stmt = $pdo->prepare("DELETE FROM `$currentTable` WHERE id = ?");
    $stmt->execute([$_GET['delete']]);
    header("Location: index.php?table=$currentTable");
    exit;
}

$sort = $_GET['sort'] ?? 'id_asc';
$data = [];
$sortMap = [
    'id_asc' => 'id ASC',
    'id_desc' => 'id DESC',
    'word_asc' => 'word ASC',
    'word_desc' => 'word DESC',
    'translation_asc' => 'translation ASC',
    'translation_desc' => 'translation DESC',
    'explanation_asc' => 'explanation ASC',
    'explanation_desc' => 'explanation DESC'
];

if ($currentTable) {
    $sortSql = $sortMap[$sort] ?? 'id ASC';
    $data = $pdo->query("SELECT * FROM `$currentTable` ORDER BY $sortSql")->fetchAll(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>English Word Manager</title>
    <style>
        * {
            font-family: Arial, sans-serif;
        }

        table,
        td,
        th {
            border: 1px solid #ccc;
            border-collapse: collapse;
            padding: 6px;
        }

        td[contenteditable="true"] {
            background-color: #ffffcc;
        }
    </style>
</head>

<body>
    <h2>Welcome, <?= htmlspecialchars($_SESSION['username']) ?>!</h2>
    <a href="change_password.php">Change Password</a> |
    <a href="logout.php">Logout</a> |
    <a href="change_key.php">Change Encryption Key</a>
    <hr>

    <form method="get">
        <select name="table" onchange="this.form.submit()">
            <option value="">-- Select Table --</option>
            <?php foreach ($allowedTables as $tbl): ?>
                <option value="<?= htmlspecialchars($tbl) ?>" <?= $tbl === $currentTable ? 'selected' : '' ?>>
                    <?= htmlspecialchars($tbl) ?>
                </option>
            <?php endforeach; ?>
        </select>
    </form>

    <?php if ($currentTable): ?>
        <h3>Add New Word to "<?= htmlspecialchars($currentTable) ?>"</h3>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>">
            <input name="word" placeholder="Word">
            <input name="translation" placeholder="Translation">
            <input name="explanation" placeholder="Explanation">
            <button name="add_word">Add Word</button>
        </form>
        <hr>

        <form method="get">
            <input type="hidden" name="table" value="<?= htmlspecialchars($currentTable) ?>">
            <label>Sort by: </label>
            <select name="sort" onchange="this.form.submit()">
                <?php foreach ($sortMap as $key => $label): ?>
                    <option value="<?= $key ?>" <?= $sort == $key ? 'selected' : '' ?>>
                        <?= ucwords(str_replace('_', ' ', $key)) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </form>

        <div class="filters">
            <input onkeyup="filterTable(0)" placeholder="Search ID">
            <input onkeyup="filterTable(1)" placeholder="Search Word">
            <input onkeyup="filterTable(2)" placeholder="Search Translation">
            <input onkeyup="filterTable(3)" placeholder="Search Explanation">
        </div>

        <table id="wordTable">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Word</th>
                    <th>Translation</th>
                    <th>Explanation</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($data as $row): ?>
                    <tr>
                        <td><?= $row['id'] ?></td>
                        <td contenteditable="false"><?= htmlspecialchars(decrypt_text($row['word'])) ?></td>
                        <td contenteditable="false"><?= htmlspecialchars(decrypt_text($row['translation'])) ?></td>
                        <td contenteditable="false"><?= htmlspecialchars(decrypt_text($row['explanation'])) ?></td>
                        <td>
                            <form method="post">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>">
                                <input type="hidden" name="id" value="<?= $row['id'] ?>">
                                <input type="hidden" name="word">
                                <input type="hidden" name="translation">
                                <input type="hidden" name="explanation">
                                <button type="button" onclick="toggleEdit(this)">Edit</button>
                                <input type="hidden" name="edit_word" value="1">
                            </form>
                            <a href="index.php?table=<?= urlencode($currentTable) ?>&delete=<?= $row['id'] ?>"
                                onclick="return confirm('Are you sure you want to delete this word?');">
                                Delete
                            </a>
                        </td>

                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <script>
        function toggleEdit(button) {
            const row = button.closest('tr');
            const form = button.closest('form');
            const cells = row.querySelectorAll('td');

            if (button.textContent === 'Edit') {
                // Switch to editable mode
                for (let i = 1; i <= 3; i++) {
                    cells[i].setAttribute('contenteditable', 'true');
                }
                button.textContent = 'Save';
            } else {
                // Save edits
                for (let i = 1; i <= 3; i++) {
                    cells[i].setAttribute('contenteditable', 'false');
                }

                form.word.value = cells[1].textContent.trim();
                form.translation.value = cells[2].textContent.trim();
                form.explanation.value = cells[3].textContent.trim();
                button.textContent = 'Edit';
                form.submit();
            }
        }

        function filterTable(colIndex) {
            const inputFields = document.querySelectorAll(".filters input");
            const table = document.getElementById("wordTable");
            const rows = table.querySelectorAll("tbody tr");

            rows.forEach(row => {
                let visible = true;
                inputFields.forEach((input, i) => {
                    const val = input.value.toLowerCase();
                    const cell = row.cells[i]?.textContent.toLowerCase() || '';
                    if (val && !cell.includes(val)) visible = false;
                });
                row.style.display = visible ? "" : "none";
            });
        }
    </script>

</body>

</html>