<?php
// functions.php

// 1. Function to sanitize user input (preventing XSS attacks)
function sanitize_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// 2. Function to validate email format
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// 3. Function to hash passwords securely using bcrypt
function hash_password($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

// 4. Function to check if the provided password matches the hash
function verify_password($password, $hashed_password) {
    return password_verify($password, $hashed_password);
}

// 5. Function to redirect to another page
function redirect($url) {
    header("Location: $url");
    exit();
}

// 6. Function to start a session if not already started
function start_session() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
}

// 7. Function to set a session variable
function set_session_variable($key, $value) {
    $_SESSION[$key] = $value;
}

// 8. Function to get a session variable
function get_session_variable($key) {
    return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
}

// 9. Function to unset a session variable
function unset_session_variable($key) {
    if (isset($_SESSION[$key])) {
        unset($_SESSION[$key]);
    }
}

// 10. Function to check if a user is logged in (using session)
function is_logged_in() {
    return isset($_SESSION['user_id']);
}

// 11. Function to create a database connection (PDO example)
function get_db_connection() {
    $host = 'localhost'; // change to your database host
    $dbname = 'your_database'; // change to your database name
    $username = 'your_username'; // change to your database username
    $password = 'your_password'; // change to your database password

    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        echo "Connection failed: " . $e->getMessage();
        return null;
    }
}

// 12. Function to escape output for HTML (to prevent XSS)
function escape_html($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

// 13. Function to log out the user
function logout() {
    session_start();
    session_unset();
    session_destroy();
    redirect('login.php'); // Redirect to login page after logout
}

// 14. Function to display a flash message
function flash_message($message, $type = 'success') {
    $_SESSION['flash_message'] = ['message' => $message, 'type' => $type];
}

// 15. Function to retrieve and clear a flash message
function get_flash_message() {
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        unset($_SESSION['flash_message']);
        return $message;
    }
    return null;
}

// 16. Function to validate if a user has the correct role (admin, user, etc.)
function has_role($role) {
    return isset($_SESSION['role']) && $_SESSION['role'] === $role;
}

?>
