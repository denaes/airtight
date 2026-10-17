<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$db->query("SELECT * FROM users WHERE active = 1");
$res = DB::table('users')->where('id', $id)->first();
$pdo->exec("INSERT INTO logs (event) VALUES ('heartbeat')");
$stmt->execute([':id' => $id]);
// $db->query("SELECT * FROM users WHERE id = " . $id);
