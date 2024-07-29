<?php
session_start();

include 'database_connection/database_connection.php';

// Initialize session variables
$_SESSION["wrong_password"] = "";

// Function to sanitize input
function sanitize_input($data) {
    return htmlspecialchars(trim($data));
}

if (isset($_POST["btn_signin"])) {
    $login_index_number = sanitize_input($_POST["txtusername"]);
    $login_password = sanitize_input($_POST["txtpassword"]);

    // Prepare statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT * FROM registered_students WHERE index_number = ? AND password = ? LIMIT 1");
    $stmt->bind_param("ss", $login_index_number, $login_password);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows == 1) {
        $get_detail = $result->fetch_assoc();

        $user_first_name = $get_detail["first_name"];
        $user_last_name = $get_detail["last_name"];

        // Set cookies
        setcookie("student_first_name", $user_first_name, time() + (86400 * 30), "/");
        setcookie("student_last_name", $user_last_name, time() + (86400 * 30), "/");
        setcookie("student_index_number", $login_index_number, time() + (86400 * 30), "/");

        // Redirect to instructions page
        header("Location: instructions_page/instructions_page.php");
        exit(); // Ensure no further code is executed after redirect
    } else {
        $_SESSION["wrong_password"] = "Wrong Username or Password";
    }

    $stmt->close();
}

if (isset($_POST["btn_signup"])) {
    $reg_first_name = sanitize_input($_POST["txt_signup_firstname"]);
    $reg_last_name = sanitize_input($_POST["txt_signup_lastname"]);
    $reg_index_number = sanitize_input($_POST["txt_signup_indexnumber"]);
    $reg_password = sanitize_input($_POST["txt_signup_password"]);

    if ($reg_first_name != "" && $reg_last_name != "" && $reg_index_number != "" && $reg_password != "") {
        // Check for existing index number
        $stmt = $conn->prepare("SELECT * FROM registered_students WHERE index_number = ?");
        $stmt->bind_param("s", $reg_index_number);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $message = "Sorry, Account Already Exists";
            echo "<script>alert('$message');</script>";
        } else {
            // Register new student
            $stmt = $conn->prepare("INSERT INTO registered_students (first_name, last_name, index_number, password) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $reg_first_name, $reg_last_name, $reg_index_number, $reg_password);

            if ($stmt->execute()) {
                // Set cookies
                setcookie("student_first_name", $reg_first_name, time() + (86400 * 30), "/");
                setcookie("student_last_name", $reg_last_name, time() + (86400 * 30), "/");
                setcookie("student_index_number", $reg_index_number, time() + (86400 * 30), "/");

                // Redirect to instructions page
                header("Location: instructions_page/instructions_page.php");
                exit(); // Ensure no further code is executed after redirect
            } else {
                $error_message = "Unable to register due to errors";
                echo "<script>alert('$error_message');</script>";
            }

            $stmt->close();
        }
    } else {
        $fill_spaces_message = "Provide Details For All Spaces";
        echo "<script>alert('$fill_spaces_message');</script>";
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="css/style.css">
    <script type="text/javascript" src="js/jquery-3.1.1.min.js"></script>
    <script type="text/javascript" src="js/bootstrap.min.js"></script>
</head>
<body>
    <div class="login-wrap">
        <div class="login-html">
            <div id="text_holder">
                <h2><span style="color:rgba(255, 152, 0, 0.91);text-align:center;font-family:sans">ATTACHMENT <br><br>MANAGEMENT SYSTEM</span></h2>
            </div>
            <input id="tab-1" type="radio" name="tab" class="sign-in" checked><label for="tab-1" class="tab">Sign In</label>
            <input id="tab-2" type="radio" name="tab" class="sign-up"><label for="tab-2" class="tab">Sign Up</label>
            <div class="login-form">
                <form method="post" action="">
                    <div class="sign-in-htm">
                        <div class="group">
                            <label for="user" class="label">Username</label>
                            <input id="user" type="text" class="input" name="txtusername">
                        </div>
                        <div class="group">
                            <label for="pass" class="label">Password</label>
                            <input id="pass" type="password" class="input" data-type="password" name="txtpassword">
                        </div>
                        <div class="group">
                            <input id="check" type="checkbox" class="check" checked>
                            <label for="check"><span class="icon"></span> Keep me Signed in</label>
                        </div>
                        <div class="group">
                            <input type="submit" class="button" value="Sign In" name="btn_signin" id="btn_signin"/>
                        </div>
                        <div class="group" style="text-align: center">
                            <a href="admin/index.php"><u style="color:#26e2f7">Administrator</u></a>
                        </div>
                        <div class="hr"></div>
                        <div class="error_message_holder"><span><?php echo htmlspecialchars($_SESSION["wrong_password"]); ?></span></div>
                    </div>
                </form>
                <form method="post" action="">
                    <div class="sign-up-htm">
                        <div class="group">
                            <label for="firstname" class="label">First Name</label>
                            <input id="firstname" type="text" class="input" name="txt_signup_firstname">
                        </div>
                        <div class="group">
                            <label for="lastname" class="label">Last Name</label>
                            <input id="lastname" type="text" class="input" name="txt_signup_lastname">
                        </div>
                        <div class="group">
                            <label for="index_number" class="label">Index Number</label>
                            <input id="index_number" type="text" class="input" name="txt_signup_indexnumber">
                        </div>
                        <div class="group">
                            <label for="pass" class="label">Password</label>
                            <input id="pass" type="password" class="input" data-type="password" name="txt_signup_password">
                        </div>
                        <div class="group">
                            <input type="submit" class="button" value="Sign Up" name="btn_signup" id="btn_signup"/>
                        </div>
                        <div class="hr"></div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
