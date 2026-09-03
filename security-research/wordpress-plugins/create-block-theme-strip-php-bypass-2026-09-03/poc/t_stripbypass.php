<?php
// Replicate CBT_Theme_Patterns::strip_php_tags exactly.
function strip_php_tags( $content ) {
	if ( ! is_string( $content ) || '' === $content ) return $content;
	$content = preg_replace( '/<\?/', '', $content );
	$content = preg_replace( '#<script\s+language\s*=\s*["\']?php["\']?[^>]*>.*?</script>#is', '', $content );
	return $content;
}
$tests = array(
  'plain <?php'          => '<?php system("id"); ?>',
  'recombine <<??php'    => '<<??php system("id"); ?>',
  'recombine <?<?php'    => '<?<?php system("id"); ?>',
  'recombine <<??php'    => '<<??php system("id"); ?>',
  'short <<??='          => '<<??= `id` ?>',
  'nested <<??<??php'    => '<<??<??php system("id"); ?>',
);
foreach ($tests as $label=>$in) {
  $out = strip_php_tags($in);
  $exec = (strpos($out,'<?php')!==false || strpos($out,'<?=')!==false || preg_match('/<\?[^x]/',$out) || strpos($out,'<?')!==false);
  printf("%-22s in=%-28s out=%-28s %s\n", $label, $in, $out, $exec ? '*** PHP TAG SURVIVES ***':'clean');
}
