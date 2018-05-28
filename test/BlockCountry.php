<?php

include '../vendor/autoload.php';
include '../src/BlockCountry.php';
include '../src/CloudFlareIP.php';
include '../src/Error503.php';

$_SERVER['HTTP_CLIENT_IP'] = '14.162.144.110'; // VN
$_SERVER['HTTP_CLIENT_IP'] = '100.36.147.143'; // US
$_SERVER['HTTP_CLIENT_IP'] = '2001:df2:d900:0:103:102:129:9'; // VN
$_SERVER['HTTP_CLIENT_IP'] = '2600:1700:e841:1f20:e97f:7793:82f6:9f11'; // US
$flag = \TMT\CL\BlockCountry::isVN();

if (!$flag) die(new \TMT\CL\Error503());
