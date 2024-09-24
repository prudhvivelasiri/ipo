<?php
session_start();
if (!isset($_SESSION['username'])) {
    header("Location: index.html");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Support - Wanderlust Travels</title>
</head>
<body>
    <h1>Customer Support</h1>
    <p>Contact us for any support you need. We're here to help 24/7.</p>
    <form action="send_support_query.php" method="POST">
        <label for="query">Describe your issue:</label><br>
        <textarea id="query" name="query" rows="6" cols="40" required></textarea><br><br>
        <button type="submit">Submit Query</button>
    </form>
</body>
</html>
