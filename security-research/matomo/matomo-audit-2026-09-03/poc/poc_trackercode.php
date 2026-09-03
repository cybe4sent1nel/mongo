<?php
// Minimal demonstration of the ordering defect in
// core/Tracker/TrackerCodeGenerator::generate():
//   $jsCode = htmlentities($jsCode, ...);            // template escaped
//   foreach ($codeImpl as $k => $v)                  // ... THEN placeholders filled
//       $jsCode = str_replace('{$'.$k.'}', $v, $jsCode);
// => everything substituted in (including $options) bypasses the escaping.

$excludedReferrers = ['<img src=x onerror=alert(1)>'];
$options  = '  _paq.push(["setExcludedReferrers", ' . json_encode($excludedReferrers) . ']);' . "\n";

$template = "<!-- Matomo -->\n<script>\n  var _paq = window._paq = window._paq || [];\n{\$options}  _paq.push(['trackPageView']);\n</script>\n";

$jsCode = htmlentities($template, ENT_COMPAT | ENT_HTML401, 'UTF-8');
$jsCode = str_replace('{$options}', $options, $jsCode);   // <-- inserted raw

echo "--- value that reaches  <pre>{{ jsTag|raw }}</pre>  ---\n";
echo $jsCode, "\n";
echo "--- checks ---\n";
printf("template '<' escaped        : %s\n", str_contains($jsCode, '&lt;script&gt;') ? 'yes' : 'no');
printf("injected '<img' still live  : %s\n", str_contains($jsCode, '<img src=x onerror=') ? 'YES  <-- unescaped markup' : 'no');
