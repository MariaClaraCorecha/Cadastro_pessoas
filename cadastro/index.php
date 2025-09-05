<?php 
$host = 'localhost';      
$db   = 'meubanco';        
$user = 'root';     
$pass = '';    

$dsn = "mysql:host=$host;dbname=$db;charset=UTF8";
try {
    $pdo = new PDO($dsn, $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Erro na conexão: " . $e->getMessage();
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitizar entradas
    $nome = filter_input(INPUT_POST, 'nome',    FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $senha = $_POST['senha']; // senha não sanitizamos para não alterar os caracteres

    if ($nome && $email && $senha) {
        // Hashear a senha
        $senhaHash = password_hash($senha, PASSWORD_DEFAULT);

        $sql = "INSERT INTO pessoas (nome, email, senha) VALUES (:nome, :email, :senha)";
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':nome', $nome);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':senha', $senhaHash);

        if ($stmt->execute()) {
            echo "<script>alert('Cadastro realizado com sucesso!');</script>";
        } else {
            echo "<script>alert('Erro ao cadastrar. Tente novamente.');</script>";
        }
    } else {
        echo "<script>alert('Por favor, preencha os campos corretamente.');</script>";
    }
}
?>