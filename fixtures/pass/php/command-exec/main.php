<?php
exec("git status", $output);
system("uptime");
$safe = escapeshellarg($host);
shell_exec("whoami");
passthru("php -v");
// system("rm -rf " . $dir);
