<?php
$data = unserialize($payload);
$obj = unserialize($_COOKIE['session']);
$user = unserialize(base64_decode($_POST['data']));
$profile = unserialize(file_get_contents($tmpFile));
