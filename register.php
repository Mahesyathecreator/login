<?php
include 'config.php';
session_start();

// Jika sudah login, redirect ke halaman utama
if (isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}

$username = $email = ""; // Variabel untuk menyimpan inputan
$error = ""; // Menampung pesan error

if (isset($_POST['submit'])) {
    // Validasi dan sanitasi input
    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);
    $cpassword = mysqli_real_escape_string($conn, $_POST['cpassword']);

    // Hashing password menggunakan SHA-256
    $password = hash('sha256', $password);
    $cpassword = hash('sha256', $cpassword);

    // Cek apakah password dan confirm password cocok
    if ($password == $cpassword) {
        // Cek apakah email sudah terdaftar
        $sql = "SELECT * FROM users WHERE email=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $error = "Ups, email sudah terdaftar.";
        } else {
            // Insert data ke database
            $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sss", $username, $email, $password);
            
            if ($stmt->execute()) {
                // Redirect atau feedback sukses
                echo "<script>alert('Selamat, pendaftaran berhasil!')</script>";
                $username = $email = ""; // Reset inputan
            } else {
                $error = "Maaf, terjadi kesalahan saat mendaftar.";
            }
        }
    } else {
        $error = "Password dan konfirmasi password tidak sesuai.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" type="text/css" href="style.css">
    <title>Daftar Akun Hostinger</title>
</head>
<body>
    <div class="container">
        <form action="" method="POST" class="login-email">
            <p class="login-text" style="font-size: 2rem; font-weight: 800;">Gabung Hostinger</p>

            <!-- Tampilkan pesan error jika ada -->
            <?php if ($error): ?>
                <div class="error-message" style="color: red; text-align: center; font-size: 1rem; margin-bottom: 10px;">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>

            <div class="input-group">
                <input type="text" placeholder="Username" name="username" value="<?php echo htmlspecialchars($username); ?>" required>
            </div>
            <div class="input-group">
                <input type="email" placeholder="Email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
            </div>
            <div class="input-group">
                <input type="password" placeholder="Password" name="password" required>
            </div>
            <div class="input-group">
                <input type="password" placeholder="Confirm Password" name="cpassword" required>
            </div>
            <div class="input-group">
                <button name="submit" class="btn">Daftar</button>
            </div>
            <p class="login-register-text">Sudah punya akun? <a href="index.php">Login</a>.</p>
        </form>
    </div>
</body>
</html>
