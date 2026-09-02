<?php
$cases = array(
 'href benign'     => '{"u":"https://example.com/ok"}',
 'href relative'   => '{"u":"/ok"}',
 'href javascript' => '{"u":"javascript:alert(1)"}',
 'href JaVaScRiPt' => '{"u":"JaVaScRiPt:alert(1)"}',
 'href js tab'     => '{"u":"java\tscript:alert(1)"}',
 'href leading sp' => '{"u":" javascript:alert(1)"}',
 'href newline'    => '{"u":"java\nscript:alert(1)"}',
 'href data html'  => '{"u":"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}',
 'href vbscript'   => '{"u":"vbscript:msgbox(1)"}',
 'href entity'     => '{"u":"&#106;avascript:alert(1)"}',
 'href colon enc'  => '{"u":"javascript&colon;alert(1)"}',
 'href mailto'     => '{"u":"mailto:a@b.c"}',
);
foreach ( $cases as $label => $ctx ) {
	$html = '<div data-wp-interactive=\'{"namespace":"pwn"}\' data-wp-context=\'' . $ctx . '\'><a data-wp-bind--href="context.u">x</a></div>';
	$out  = wp_interactivity_process_directives( $html );
	if ( preg_match( '~<a[^>]*>~', $out, $m ) ) {
		printf( "%-18s %s\n", $label, $m[0] );
	}
}
