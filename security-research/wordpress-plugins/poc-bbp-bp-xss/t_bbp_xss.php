<?php
error_reporting(E_ERROR|E_PARSE);
$u = get_user_by('login','subscriber'); wp_set_current_user($u->ID);
// Real bbPress SAVE chain for a reply (encode_bad 10, code_trick 20, kses 30, balanceTags 40)
function bbp_save($c){ return wp_unslash( apply_filters("bbp_new_reply_pre_content", wp_slash($c)) ); }
// Real FRONT-END display chain (note: bbp_kses_data is admin-only, so NOT applied here)
function bbp_display($c){ return apply_filters('bbp_get_reply_content', $c); }

$payloads = array(
 // make_clickable: plain-text URL that may break out of the generated href
 'url_quote'      => 'http://example.com/"onmouseover="alert(1)',
 'url_quote2'     => 'http://example.com/?a="><img src=x onerror=alert(1)>',
 'url_apos'       => "http://example.com/'onmouseover='alert(1)",
 'url_entity'     => 'http://example.com/&quot;onmouseover=&quot;alert(1)',
 'url_backtick'   => 'http://example.com/`onmouseover=alert(1)',
 'url_space_attr' => 'http://example.com/ onmouseover=alert(1)',
 'www_quote'      => 'www.example.com/"onmouseover="alert(1)',
 'email_quote'    => 'a@b.com"onmouseover="alert(1)',
 // smilies build <img>
 'smiley'         => ':) :( 8) :?:',
 // code trick / encode bad interaction
 'code_block'     => '[code]<img src=x onerror=alert(1)>[/code]',
 'code_partial'   => '[code]<img src=x[/code] onerror=alert(1)>',
 'encode_bad'     => '<img src=x onerror=alert(1)',
 // texturize / convert_chars
 'texturize'      => 'a--b "quoted" ...',
 'plain_script'   => '<script>alert(1)</script>',
 'plain_onerror'  => '<img src=x onerror=alert(1)>',
);
$out=array();
foreach($payloads as $k=>$p){
  $saved = bbp_save($p);
  $out['reply__'.$k] = bbp_display($saved);
  $out['_saved__'.$k] = $saved;
}
echo json_encode($out);
