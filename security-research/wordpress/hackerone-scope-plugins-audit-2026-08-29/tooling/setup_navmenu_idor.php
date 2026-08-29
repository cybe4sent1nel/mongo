<?php
define('WP_USE_THEMES', false);
require_once '/home/user/wp-site/wordpress/wp-load.php';

// Field group with a Text field scoped to Users (so form-user.php's own
// save path is the ONLY intended way to write it, gated by
// acf_verify_nonce('user')).
$existing = acf_get_field_group('group_navmenu_idor_test');
if (!$existing) {
    $result = acf_import_field_group(array(
        'key'      => 'group_navmenu_idor_test',
        'title'    => 'NavMenu IDOR Test - User Field',
        'fields'   => array(
            array(
                'key'   => 'field_navmenu_idor_usertext',
                'label' => 'Secret User Note',
                'name'  => 'secret_user_note',
                'type'  => 'text',
            ),
        ),
        'location' => array(
            array(
                array('param' => 'user_role', 'operator' => '==', 'value' => 'all'),
            ),
        ),
        'active' => true,
    ));
    echo "Imported user field group\n";
} else {
    echo "User field group already exists\n";
}

// Target: the contributor account created earlier (a DIFFERENT user than
// whoever performs the nav-menu save).
$target = get_user_by('login', 'sec_research_contributor');
if (!$target) {
    die("target contributor missing\n");
}
echo "Target user id={$target->ID}\n";

// Baseline value before the attack.
$before = get_field('secret_user_note', 'user_' . $target->ID);
echo "BEFORE=" . var_export($before, true) . "\n";

// Need an existing nav menu to update. Create one if none exists.
$menus = wp_get_nav_menus();
if (empty($menus)) {
    $menu_id = wp_create_nav_menu('IDOR Test Menu');
} else {
    $menu_id = $menus[0]->term_id;
}
echo "MENU_ID=$menu_id\n";
echo "TARGET_USER_ID={$target->ID}\n";
echo "READY\n";
