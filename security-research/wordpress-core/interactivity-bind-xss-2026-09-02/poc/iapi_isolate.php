<?php
$cases = array(
 'bind href on child'   => '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"u":"javascript:alert(1)"}\'><a data-wp-bind--href="context.u">x</a></div>',
 'bind href same tag'   => '<a data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"u":"javascript:alert(1)"}\' data-wp-bind--href="context.u">x</a>',
 'bind title same tag'  => '<b data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"u":"a\" onmouseover=\"alert(1)"}\' data-wp-bind--title="context.u">x</b>',
 'bind title on child'  => '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"u":"HIT"}\'><b data-wp-bind--title="context.u">x</b></div>',
 'style same tag'       => '<p data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"c":"red"}\' data-wp-style--color="context.c">x</p>',
 'style on child'       => '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"c":"red"}\'><p data-wp-style--color="context.c">x</p></div>',
 'class on child'       => '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"c":true}\'><p data-wp-class--pwned="context.c">x</p></div>',
 'text on child'        => '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"t":"<img src=x onerror=alert(1)>"}\'><p data-wp-text="context.t">x</p></div>',
 'bind src img child'   => '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'{"u":"javascript:alert(1)"}\'><img data-wp-bind--src="context.u"></div>',
);
foreach ($cases as $label => $html) {
  $out = wp_interactivity_process_directives($html);
  printf("%-22s %s\n", $label, $out === $html ? '(UNCHANGED)' : $out);
}
