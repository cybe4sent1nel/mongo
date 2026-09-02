<?php
/**
 * Runs WordPress's real save-time AND display-time filter chains over payloads.
 *
 * Input : JSON array of strings (file path in $args[0], else stdin).
 * Output: JSON array of
 *   { payload, comment, comment_display, post, post_display, post_excerpt }
 *
 * comment / post          = what gets stored (kses, low-privilege user).
 * *_display               = what is finally emitted to a reader's browser.
 *
 * The display chains matter because everything that runs after kses
 * (wptexturize, make_clickable, force_balance_tags, wpautop, shortcodes,
 * convert_smilies, the block filters) can reintroduce markup kses removed.
 */

$path     = $args[0] ?? 'php://stdin';
$payloads = json_decode( file_get_contents( $path ), true );
if ( ! is_array( $payloads ) ) {
	fwrite( STDERR, "bad input\n" );
	exit( 1 );
}

// Low-privilege filter set: no unfiltered_html.
wp_set_current_user( 0 );
kses_remove_filters();
kses_init_filters();

$out = array();
foreach ( $payloads as $p ) {
	$row = array( 'payload' => $p );

	$stored_comment    = wp_unslash( apply_filters( 'pre_comment_content', wp_slash( $p ) ) );
	$row['comment']    = $stored_comment;
	$row['comment_display'] = apply_filters( 'comment_text', apply_filters( 'get_comment_text', $stored_comment ) );

	$stored_post    = wp_unslash( apply_filters( 'content_save_pre', wp_slash( $p ) ) );
	$row['post']    = $stored_post;
	$row['post_display'] = apply_filters( 'the_content', $stored_post );

	$row['post_excerpt'] = apply_filters(
		'the_excerpt',
		apply_filters( 'get_the_excerpt', wp_trim_excerpt( '', (object) array( 'post_content' => $stored_post, 'post_excerpt' => '', 'ID' => 0 ) ) )
	);

	$out[] = $row;
}

echo json_encode( $out );
