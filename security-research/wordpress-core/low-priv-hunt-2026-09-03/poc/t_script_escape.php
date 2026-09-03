<?php
define('ABSPATH', '/home/user/wpaudit/wordpress/');
$_SERVER['HTTP_HOST']='localhost';
require ABSPATH.'wp-load.php';

$payloads = [
 'plain'                => 'console.log(1);',
 'basic_close'          => 'a</script><script>alert(1)</script>',
 'basic_close_upper'    => 'a</SCRIPT><script>alert(1)</script>',
 'basic_close_mixed'    => 'a</ScRiPt><script>alert(2)</script>',
 'open_tag'              => 'a<script>alert(3)</script>',
 'no_delim_after'        => 'a</scriptx>b',            // should NOT be touched (not a real closer)
 'slash_delim'           => 'a</script/foo>',
 'gt_delim'              => 'a</script>foo',
 'tab_delim'             => "a</script\tfoo",
 'ff_delim'              => "a</script\x0cfoo",
 'cr_delim'              => "a</script\rfoo",
 'ends_with_close_notrail'=> 'trailingcase</script',   // ends exactly at closer, no delimiter after (edge case)
 'null_byte_split'       => "a</scr\x00ipt>b",
 'double_slash_close'    => 'a<//script>b',
 'unicode_lookalike_s'   => "a</\u{FF53}cript>b", // fullwidth 's'
 'html_entity_no_decode' => 'a&lt;/script&gt;b', // should remain literal, browsers won't decode inside RAWTEXT
 'nested_attr_break'     => '"><script>alert(4)</script>',
 'json_like'             => '{"a":"</script><script>alert(5)</script>"}',
];

foreach ($payloads as $name => $p) {
    $tag = wp_get_inline_script_tag($p);
    $failed = ($tag === '');
    echo "== $name ==\n";
    echo "in : " . json_encode($p) . "\n";
    echo "out: " . json_encode($tag) . "\n";
    echo $failed ? "  (rejected -> empty string)\n" : "\n";
}
