<?php
include 'process.php'; // Include database connection

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare and bind
    $stmt = $conn->prepare("SELECT password FROM travelers WHERE username = ?");
    $stmt->bind_param("s", $username);
    
    // Execute the statement
    $stmt->execute();
    $stmt->store_result();

    // Check if the username exists
    if ($stmt->num_rows > 0) {
        // Fetch the hashed password
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Verify the password
        if (password_verify($password, $hashed_password)) {
            // Start session and redirect to explore page
            session_start();
            $_SESSION['username'] = $username;
            header("Location: explore.php"); // Redirect to your explore page
            exit();
        } else {
            echo "<script>alert('Invalid username or password.'); window.location.href='login.php';</script>";
        }
    } else {
        echo "<script>alert('No user found with that username. Please register.'); window.location.href='register.php';</script>";
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();
}
?>
