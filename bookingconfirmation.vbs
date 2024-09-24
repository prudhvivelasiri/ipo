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
    <title>Booking Confirmations - Wanderlust Travels</title>
</head>
<body>
    <h1>Booking Confirmations</h1>
    <p>Here are your recent bookings:</p>

    <!-- Example booking details -->
    <table border="1">
        <tr>
            <th>Booking ID</th>
            <th>Destination</th>
            <th>Date</th>
            <th>Status</th>
        </tr>
        <tr>
            <td>12345</td>
            <td>Paris</td>
            <td>2024-10-15</td>
            <td>Confirmed</td>
        </tr>
        <tr>
            <td>67890</td>
            <td>Tokyo</td>
            <td>2024-11-20</td>
            <td>Confirmed</td>
        </tr>
    </table>
</body>
</html>
