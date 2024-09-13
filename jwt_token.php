<?php
require 'vendor/autoload.php';
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

session_start();
error_reporting(E_ALL & ~E_NOTICE);

// db connection
$connection = mysqli_connect("localhost", "root", "", "php_jwt_token");

if (!$connection) {
    die("Connection failed: " . mysqli_connect_error());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postdata = file_get_contents("php://input");
    $_POST = json_decode($postdata, true);
}

$key = "abcdef";

/********* generate jwt token *********/
function generateToken($key, $userId, $action, $connection) {
    $chk_query = "select * from jwt_token;";
    $chk_res = mysqli_query($connection, $chk_query);

    if (mysqli_num_rows($chk_res) > 0) {
        $delete_query = "delete from jwt_token where create_date <= DATE_SUB(NOW(), INTERVAL 1 HOUR)";
        mysqli_query($connection, $delete_query);
        if (mysqli_error($connection)) {
            echo "Delete failed";
            exit;
        }
    }

    $uniqueId = bin2hex(random_bytes(16)); // generate unique ID for the token
    $payload = [
        'iss' => "localhost",
        'aud' => "localhost",
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + 3600, // token expires in 1 hour
        'data' => [
            'userId' => $userId,
            'tokenId' => $uniqueId,
            'action' => $action 
        ]
    ];
    $gen_token = JWT::encode($payload, $key, 'HS256');
    $insert_query = "insert into jwt_token set token = '" . mysqli_real_escape_string($connection, $gen_token) . "'";
    mysqli_query($connection, $insert_query);

    if (mysqli_error($connection)) {
        echo "Insert failed";
        exit;
    }
    return $gen_token;
}

/******* validate token ****/
function validateToken($key, $token, $action, $connection) {
    $tokens = [];
    $get_query = "select * from jwt_token;";
    $res = mysqli_query($connection, $get_query);

    if (mysqli_error($connection)) {
        echo mysqli_error($connection);
        exit;
    }

    while ($row = mysqli_fetch_assoc($res)) {
        if ($row['token'] === $token) {
            try {
                $decoded = JWT::decode($token, new Key($key, 'HS256'));
                
                if ($decoded->exp < time()) {
                    return ['status' => false, 'error' => 'Token has expired'];
                }
                
                if ($row['status'] === '1') {
                    return ['status' => false, 'error' => 'Token has already been used'];
                }
                
                if ($decoded->data->action !== $action) {
                    return ['status' => false, 'error' => 'Invalid token action'];
                }
                
                $update_query = "update jwt_token set status = '1' where id = " . $row['id'];
                mysqli_query($connection, $update_query);

                if (mysqli_error($connection)) {
                    echo "Update failed";
                    exit;
                }
                return ['status' => true, 'data' => $decoded];
            } catch (Exception $e) {
                return ['status' => false, 'error' => 'Invalid token'];
            }
        }
    }
    return ['status' => false, 'error' => 'Token not found'];
}

if (isset($_POST['action']) && $_POST['action'] == 'login') {
    $userId = 1;
    $token_check = isset($_POST['token']) && $_POST['token'] ? validateToken($key, $_POST['token'], 'login', $connection) : false;

    if (!$token_check['status']) {
        echo json_encode([
            "status" => "fail",
            "error" => $token_check['error'],
            "token" => generateToken($key, $userId, 'login', $connection),
        ], JSON_PRETTY_PRINT);
        exit;
    }

    if (isset($_POST['username']) && isset($_POST['password'])) {
        $token = generateToken($key, $userId, 'login', $connection);
        $username = $_POST['username'];
        $password = $_POST['password'];

        // checking credentials
        if ($username === 'test' && $password === 'test') {
            echo json_encode([
                "status" => "success",
                "token" => $token,
                "message" => 'Login successful'
            ], JSON_PRETTY_PRINT);
        } else {
            echo json_encode([
                "status" => "fail",
                "token" => $token,
                "message" => "Invalid credentials"
            ], JSON_PRETTY_PRINT);
        }
        exit;
    } else {
        echo json_encode([
            "status" => "fail",
            "message" => "Post data not found"
        ], JSON_PRETTY_PRINT);
        exit;
    }
}

if (isset($_POST['action']) && $_POST['action'] == 'dynamic_token_generate') {
    $userId = "1";
    $token = generateToken($key, $userId, 'login', $connection);

    echo json_encode([
        "status" => "success",
        "token" => $token,
    ], JSON_PRETTY_PRINT);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT Demo</title>
    <script src="https://cdn.jsdelivr.net/npm/vue@3"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
</head>
<body>
    <div id="app">
        <form @submit.prevent="login">
            <input type="text" v-model="username" placeholder="Username" required>
            <input type="password" v-model="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>        
        <p>{{ message }}</p>
    </div>

    <script>
        var jwt_token = Vue.createApp({
            data() {
                return {
                    username: "",
                    password: "",
                    message: "",
                    token: ""
                }
            },
            mounted() {
                //this.get_token('login');
            },
            methods: {
                login() {
                    if (!this.token) {
                        this.get_token('login');
                        return;
                    }
                    axios.post("", {
                        "action": "login",
                        "username": this.username,
                        "password": this.password,
                        "token": this.token
                    }).then(response => {
                        try {
                            if (response.status == 200) {
                                if (response.data['status'] == "success") {
                                    this.token = response.data.token;
                                    this.message = response.data.message;
                                } else if (response.data['status'] == "fail") {
                                    if (response.data['message'] == 'Invalid credentials') {
                                        this.message = 'Invalid credentials';
                                    } else if (response.data['error'] == 'Invalid token') {
                                        this.token = response.data['token'];
                                        this.login();
                                    }
                                } else {
                                    console.log('Login failed: Incorrect response');
                                    this.message = 'Incorrect response';
                                }
                            } else {
                                console.log('Login failed: Incorrect response');
                                this.message = 'Incorrect response';
                            }
                        } catch (error) {
                            console.log('Login failed: ' + error);
                            this.message = 'Login failed';
                        }
                    });
                },
                get_token(postaction) {
                    axios.post("", {
                        "action": "dynamic_token_generate",
                        "postaction": postaction
                    }).then(response => {
                        if (response.status == 200) {
                            if (response.data['status'] == "success") {
                                this.token = response.data['token'];
                                this[postaction]();
                            } else if (response.data["status"] == "fail") {
                                this.message = "Token is not generated";
                            }
                        } else {
                            this.message = "There was an error: Incorrect response for dynamic token";
                        }
                    });
                }
            }
        });
        jwt_token.mount('#app');
    </script>
</body>
</html>