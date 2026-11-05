<?php
// Synthetic, inert fixture of the "fake 403 password gate" shape. No functionality.
$gate = 'd41d8cd98f00b204e9800998ecf8427e';
if (!isset($_POST['k']) || md5($_POST['k']) !== $gate) {
    header('HTTP/1.1 403 Forbidden');
    echo '<h1>403 Forbidden</h1>';
    exit;
}
/* b374k shell 3.2.3 fixture marker https://malicious-loader.example/s.txt */
$payload = 'ZWNobyAnJzs=';
