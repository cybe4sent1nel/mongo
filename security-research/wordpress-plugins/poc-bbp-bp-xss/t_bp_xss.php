<?php
error_reporting(E_ERROR|E_PARSE);
$sub = get_user_by('login','subscriber'); wp_set_current_user($sub->ID);
$payloads = array(
 'script'        => '<script>alert(1)</script>',
 'img_onerror'   => '<img src=x onerror=alert(1)>',
 'a_js'          => '<a href="javascript:alert(1)">x</a>',
 'a_target_rel'  => '<a href="http://e.tld" target="_blank" rel="noopener" aria-label="x&quot; onmouseover=alert(1) y=&quot;">x</a>',
 'tooltip_break' => '<a href="#" data-bp-tooltip="x&quot; onmouseover=alert(1) z=&quot;">x</a>',
 'livestamp'     => '<span data-livestamp="x&quot; onmouseover=alert(1) z=&quot;">t</span>',
 'img_src_js'    => '<img src="javascript:alert(1)">',
 'svg_onload'    => '<svg onload=alert(1)></svg>',
 'iframe_srcdoc' => '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>',
 'style_expr'    => '<p style="width:expression(alert(1))">x</p>',
 'mxss_math'     => '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
 'mxss_noscript' => '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
 'form_action'   => '<form action="javascript:alert(1)"><button>x</button></form>',
 'a_dblenc'      => '<a href="jav&#x09;ascript:alert(1)">x</a>',
 'img_alt_break' => '<img src=x alt="y&quot; onerror=&quot;alert(1)">',
);
$out = array();
foreach ($payloads as $k=>$p) {
  // ACTIVITY: real save filter then real display filter chain.
  $saved_act = apply_filters('bp_activity_content_before_save', $p);
  $out['activity__'.$k] = apply_filters('bp_get_activity_content_body', $saved_act);
  // GROUP DESCRIPTION: real save + display chain.
  $saved_grp = apply_filters('group_description_before_save', $p);
  $out['groupdesc__'.$k] = apply_filters('bp_get_group_description', $saved_grp);
  // GROUP NAME
  $saved_gn = apply_filters('group_name_before_save', $p);
  $out['groupname__'.$k] = apply_filters('bp_get_group_name', $saved_gn);
  // MESSAGE CONTENT
  $saved_msg = apply_filters('messages_message_content_before_save', $p);
  $out['message__'.$k] = apply_filters('bp_get_the_thread_message_content', $saved_msg);
}
echo json_encode($out);
