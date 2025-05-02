<style>
#bannerimage {
  width: 300px;
  background-image: url('banner.png');
  height: 100px;
  background-position: center;
}
body {
  background-image: url('background.png');
}
</style>
<?php
session_start();
//ini_set('display_errors', 1);
//error_reporting(E_ALL);

// Database setup
$db = new SQLite3('ideas.db');
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
$db->exec("CREATE TABLE IF NOT EXISTS ideas (id INTEGER PRIMARY KEY, title TEXT, description TEXT, votes INTEGER DEFAULT 0, user_id INTEGER)");
$db->exec("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, idea_id INTEGER, user_id INTEGER, comment TEXT)");
$db->exec("CREATE TABLE IF NOT EXISTS votes (user_id INTEGER, idea_id INTEGER, UNIQUE(user_id, idea_id))");

// Handle user registration
if (isset($_POST['register'])) {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindValue(':username', $username);
    $stmt->bindValue(':password', $password);
    $stmt->execute();
    header("Location: ?");
    exit();
}

// Handle user login
if (isset($_POST['login'])) {
    $stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->bindValue(':username', $_POST['username']);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($result && password_verify($_POST['password'], $result['password'])) {
        $_SESSION['user'] = $result['username'];
        $_SESSION['user_id'] = $result['id'];
        header("Location: ?");
        exit();
    } else {
        $login_error = "Invalid login credentials.";
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit();
}

// Handle idea submission
if (isset($_POST['title']) && isset($_SESSION['user'])) {
    $stmt = $db->prepare("INSERT INTO ideas (title, description, votes, user_id) VALUES (:title, :description, 0, :user_id)");
    $stmt->bindValue(':title', $_POST['title']);
    $stmt->bindValue(':description', $_POST['description']);
    $stmt->bindValue(':user_id', $_SESSION['user_id']);
    $stmt->execute();
    header("Location: ?");
    exit();
}

// Handle voting
if (isset($_GET['vote']) && isset($_SESSION['user'])) {
    $idea_id = intval($_GET['vote']);
    $user_id = $_SESSION['user_id'];
    $stmt = $db->prepare("INSERT OR IGNORE INTO votes (user_id, idea_id) VALUES (:user_id, :idea_id)");
    $stmt->bindValue(':user_id', $user_id);
    $stmt->bindValue(':idea_id', $idea_id);
    if ($stmt->execute()) {
        $db->exec("UPDATE ideas SET votes = votes + 1 WHERE id = $idea_id");
    }
    header("Location: ?");
    exit();
}

// Handle deleting ideas/comments
if (isset($_GET['delete_idea']) && isset($_SESSION['user'])) {
    $id = intval($_GET['delete_idea']);
    $user_id = $_SESSION['user_id'];
    $db->exec("DELETE FROM ideas WHERE id = $id AND user_id = $user_id");
    $db->exec("DELETE FROM comments WHERE idea_id = $id");
    $db->exec("DELETE FROM votes WHERE idea_id = $id");
    header("Location: ?");
    exit();
}
if (isset($_GET['delete_comment']) && isset($_SESSION['user'])) {
    $id = intval($_GET['delete_comment']);
    $user_id = $_SESSION['user_id'];
    $db->exec("DELETE FROM comments WHERE id = $id AND user_id = $user_id");
    header("Location: ?");
    exit();
}

// Handle commenting
if (isset($_POST['comment']) && isset($_SESSION['user']) && isset($_POST['idea_id'])) {
    $stmt = $db->prepare("INSERT INTO comments (idea_id, user_id, comment) VALUES (:idea_id, :user_id, :comment)");
    $stmt->bindValue(':idea_id', $_POST['idea_id']);
    $stmt->bindValue(':user_id', $_SESSION['user_id']);
    $stmt->bindValue(':comment', $_POST['comment']);
    $stmt->execute();
    header("Location: ?");
    exit();
}

// Search functionality
$searchQuery = isset($_GET['search']) ? $_GET['search'] : '';
$ideas = $db->query("
    SELECT ideas.*, users.username 
    FROM ideas 
    JOIN users ON ideas.user_id = users.id 
    WHERE title LIKE '%$searchQuery%' OR description LIKE '%$searchQuery%' 
    ORDER BY votes DESC
");
?>
<!DOCTYPE html>
<html>
<head>
    <title>Open Research Hub</title>
</head>
<body>
    <h1>Open Research Hub</h1>

    <?php if (!isset($_SESSION['user'])): ?>
        <h2>Register</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="register">Register</button>
        </form>

        <h2>Login</h2>
        <?php if (isset($login_error)) echo "<p style='color:red;'>$login_error</p>"; ?>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="login">Login</button>
        </form>
    <?php else: ?>
        <p>Welcome, <?= $_SESSION['user'] ?>! <a href="?logout=1">Logout</a></p>

        <h2>Submit a New Idea</h2>
        <form method="post">
            <input type="text" name="title" placeholder="Idea title" required>
            <textarea name="description" placeholder="Describe your idea" required></textarea>
            <button type="submit">Submit</button>
        </form>
<?php endif; ?>
        <h2>Search Ideas</h2>
        <form method="get">
            <input type="text" name="search" placeholder="Search for ideas" value="<?= htmlspecialchars($searchQuery) ?>">
            <button type="submit">Search</button>
        </form>

        <h2>Top Ideas</h2>
        <ul>
            <?php while ($row = $ideas->fetchArray()): ?>
                <li>
                    <strong><?= htmlspecialchars($row['title']) ?></strong> (<?= $row['votes'] ?> votes)
                    <br><?= htmlspecialchars($row['description']) ?>
                    <em>Posted by <?= htmlspecialchars($row['username']) ?></em><br>
                    <br><a href="?vote=<?= $row['id'] ?>">Vote</a>
                    <?php if ($row['user_id'] == $_SESSION['user_id']): ?>
                        | <a href="?delete_idea=<?= $row['id'] ?>" onclick="return confirm('Delete this idea?')">Delete</a>
                    <?php endif; ?>

                    <h3>Comments</h3>
                    <ul>
                        <?php 
$comments = $db->query("
    SELECT comments.*, users.username 
    FROM comments 
    JOIN users ON comments.user_id = users.id 
    WHERE idea_id = " . intval($row['id'])
);
                        while ($comment = $comments->fetchArray()): ?>
                            <li>
<strong><?= htmlspecialchars($comment['username']) ?>:</strong> <?= htmlspecialchars($comment['comment']) ?>
                                <?php if ($comment['user_id'] == $_SESSION['user_id']): ?>
                                    <a href="?delete_comment=<?= $comment['id'] ?>" onclick="return confirm('Delete this comment?')">[delete]</a>
                                <?php endif; ?>
                            </li>
                        <?php endwhile; ?>
                    </ul>

                    <form method="post">
                        <input type="hidden" name="idea_id" value="<?= $row['id'] ?>">
                        <input type="text" name="comment" placeholder="Add a comment" required>
                        <button type="submit">Comment</button>
                    </form>
                </li>
            <?php endwhile; ?>
        </ul>
    <?php// endif; ?>
    <a href="https://github.com/netpipe/researchHub">🕸Project Page🕸</a>
</body>
</html>
