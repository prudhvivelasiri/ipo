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
    <title>Payment Options - Wanderlust Travels</title>
</head>
<body>
    <h1>Payment Options</h1>
    <p>Select a payment method:</p>

    <form action="process_payment.php" method="POST">
        <label for="payment_method">Choose a payment method:</label><br><br>
        <input type="radio" id="credit_card" name="payment_method" value="Credit Card" required>
        <label for="credit_card">Credit Card</label><br>
        <input type="radio" id="paypal" name="payment_method" value="PayPal" required>
        <label for="paypal">PayPal</label><br>
        <input type="radio" id="bank_transfer" name="payment_method" value="Bank Transfer" required>
        <label for="bank_transfer">Bank Transfer</label><br><br>
        <button type="submit">Submit Payment</button>
    </form>
</body>
</html>
