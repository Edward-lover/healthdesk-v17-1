<?php

require_once "db.php";

// Only allow form submissions
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: index.html");
    exit();
}


// Get the information from the signup form
$first_name = trim($_POST["first_name"] ?? "");
$last_name = trim($_POST["last_name"] ?? "");
$student_id = trim($_POST["student_id"] ?? "");
$email = trim($_POST["email"] ?? "");
$username = trim($_POST["username"] ?? "");
$password = $_POST["password"] ?? "";
$confirm_password = $_POST["confirm_password"] ?? "";


// Check if all fields are filled
if (
    $first_name === "" ||
    $last_name === "" ||
    $student_id === "" ||
    $email === "" ||
    $username === "" ||
    $password === "" ||
    $confirm_password === ""
) {
    die("Please fill in all fields.");
}


// Check email
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Please enter a valid email address.");
}


// Check password length
if (strlen($password) < 6) {
    die("Password must be at least 6 characters.");
}


// Check if passwords match
if ($password !== $confirm_password) {
    die("Passwords do not match.");
}


// Check if Student ID already exists
$checkStudent = $conn->prepare(
    "SELECT id FROM users WHERE student_id = ? LIMIT 1"
);

$checkStudent->bind_param("s", $student_id);
$checkStudent->execute();

$studentResult = $checkStudent->get_result();

if ($studentResult->num_rows > 0) {
    die("This Student ID is already registered.");
}

$checkStudent->close();


// Check if email already exists
$checkEmail = $conn->prepare(
    "SELECT id FROM users WHERE email = ? LIMIT 1"
);

$checkEmail->bind_param("s", $email);
$checkEmail->execute();

$emailResult = $checkEmail->get_result();

if ($emailResult->num_rows > 0) {
    die("This email is already registered.");
}

$checkEmail->close();


// Check if username already exists
$checkUsername = $conn->prepare(
    "SELECT id FROM users WHERE username = ? LIMIT 1"
);

$checkUsername->bind_param("s", $username);
$checkUsername->execute();

$usernameResult = $checkUsername->get_result();

if ($usernameResult->num_rows > 0) {
    die("This username is already taken.");
}

$checkUsername->close();


// Securely hash the password
$hashedPassword = password_hash(
    $password,
    PASSWORD_DEFAULT
);


// New accounts are active by default
$status = "active";


// Insert the new user
$stmt = $conn->prepare(
    "INSERT INTO users
    (
        first_name,
        last_name,
        student_id,
        email,
        username,
        password,
        status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)"
);

$stmt->bind_param(
    "sssssss",
    $first_name,
    $last_name,
    $student_id,
    $email,
    $username,
    $hashedPassword,
    $status
);


// Save the account
if ($stmt->execute()) {

    echo "
    <script>
        alert('Account created successfully!');
        window.location.href = 'index.html';
    </script>
    ";

} else {

    echo "
    <script>
        alert('Something went wrong while creating your account.');
        window.location.href = 'index.html';
    </script>
    ";
}


$stmt->close();
$conn->close();

?>