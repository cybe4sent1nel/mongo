<?php
$data = file_get_contents($argv[1]);
echo "loaded " . strlen($data) . " bytes\n";
$doc = MongoDB\BSON\Document::fromBSON($data);
echo "Document::fromBSON ok, calling toPHP()...\n";
$arr = $doc->toPHP();
echo "toPHP() completed without crashing. Result type: " . gettype($arr) . "\n";
