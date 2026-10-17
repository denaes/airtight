<?php
$db->query("SELECT * FROM users WHERE id = " . $id);
$pdo->exec('DELETE FROM sessions WHERE token = ' . $token);
DB::raw("SELECT * FROM orders WHERE status = '" . $status . "'");
$conn->query("SELECT name FROM accounts WHERE user_id = $userId");
