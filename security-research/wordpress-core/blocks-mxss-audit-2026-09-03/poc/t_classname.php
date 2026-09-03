<?php
function out($k,$v){ echo $k.': '.$v."\n"; }
// 1. Direct: does get_block_wrapper_attributes escape a malicious class?
$wrap = get_block_wrapper_attributes(array('class'=>'x" onmouseover=alert(1) y="'));
out('wrapper_direct', $wrap);

// 2. Full render path: a core block with a malicious className attribute.
$contrib=get_user_by('login','contributor'); wp_set_current_user($contrib->ID);
kses_remove_filters(); kses_init_filters();
// Build via serialize + parse to mimic real storage of className.
$block = array('blockName'=>'core/group','attrs'=>array('className'=>'x" onmouseover=alert(1) z="'),'innerBlocks'=>array(),'innerHTML'=>'<div class="wp-block-group"><p>hi</p></div>','innerContent'=>array('<div class="wp-block-group"><p>hi</p></div>'));
$serialized = serialize_block($block);
out('serialized', $serialized);
// through kses save filter
$filtered = filter_block_content($serialized,'post');
out('filtered_save', $filtered);
$rendered = do_blocks($filtered);
out('RENDERED', trim($rendered));
out('BREAKOUT', (strpos($rendered,'onmouseover=alert(1)')!==false && strpos($rendered,'&quot; onmouseover')===false)?'*** YES breakout ***':'no (escaped)');
