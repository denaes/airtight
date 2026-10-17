<?php
$data = json_decode($jsonString, true);
$data = unserialize($safeData, ['allowed_classes' => false]);
$allowed = [User::class];
// unserialize($commented);
$encoded = serialize($data);
