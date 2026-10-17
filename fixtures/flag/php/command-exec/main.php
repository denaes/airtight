<?php
system("ping -c 1 " . $host);
$out = exec("ls " . $dir);
$res = shell_exec("cat " . $filePath);
passthru("/usr/bin/convert $inputFile $outputFile");
