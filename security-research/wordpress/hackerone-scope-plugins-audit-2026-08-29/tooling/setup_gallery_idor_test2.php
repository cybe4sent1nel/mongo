<?php
define('WP_USE_THEMES', false);
require_once '/home/user/wp-site/wordpress/wp-load.php';

// Clean up any half-created field group from the previous attempt.
$old = get_page_by_path('group_idor_gallery_test', OBJECT, 'acf-field-group');
if ($old) {
    wp_delete_post($old->ID, true);
    echo "Deleted stale field group {$old->ID}\n";
}

$field_group = array(
    'key'      => 'group_idor_gallery_test2',
    'title'    => 'IDOR Gallery Test 2',
    'fields'   => array(
        array(
            'key'   => 'field_idor_test_gallery2',
            'label' => 'Test Gallery',
            'name'  => 'test_gallery',
            'type'  => 'gallery',
        ),
    ),
    'location' => array(
        array(
            array(
                'param'    => 'post_type',
                'operator' => '==',
                'value'    => 'post',
            ),
        ),
    ),
    'active' => true,
);

$result = acf_import_field_group($field_group);
echo "Imported field group: " . json_encode(array_keys((array)$result)) . "\n";
$fg = acf_get_field_group('group_idor_gallery_test2');
echo "Field group active=" . var_export($fg['active'] ?? null, true) . " ID=" . ($fg['ID'] ?? 'n/a') . "\n";
$field = acf_get_field('field_idor_test_gallery2');
echo "Field: " . json_encode($field ? array('key'=>$field['key'],'type'=>$field['type'],'name'=>$field['name']) : null) . "\n";

echo "READY\n";
