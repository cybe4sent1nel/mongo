<?php
error_reporting(E_ERROR|E_PARSE);
function out($k,$v){ echo $k.': '.$v."\n"; }
$payload = '<<??php file_put_contents("/home/user/wpaudit/CBT_CONTRIB.txt","pwn"); ?>';
foreach (array('author','contributor','editor') as $login) {
  $u = get_user_by('login',$login); if(!$u){ out($login,'(no such user)'); continue; }
  wp_set_current_user($u->ID);
  kses_init();   // cap-aware, the REAL flow (not kses_init_filters)
  out($login.'_unfiltered_html', current_user_can('unfiltered_html')?'YES':'no');
  // Real REST block-creation path
  $req = new WP_REST_Request('POST','/wp/v2/blocks');
  $req->set_param('title','cbt-'.$login);
  $req->set_param('status','publish');
  $req->set_param('content',$payload);
  $res = rest_do_request($req);
  $st = $res->get_status();
  if ($st >= 200 && $st < 300) {
    $d = $res->get_data();
    $stored = get_post($d['id'])->post_content;
    out($login.'_rest_status', $st);
    out($login.'_stored', $stored);
    out($login.'_literal_lt_survived', strpos($stored,'<<??php')!==false ? '*** YES ***' : 'no (kses mangled)');
    wp_delete_post($d['id'], true);
  } else {
    out($login.'_rest_status', $st.' '.json_encode($res->get_data()));
  }
}
