<?php
function apply_filters($tag, $value, ...$args) { return $value; }
function did_action($tag) { return true; }
function wp_allowed_protocols() {
    return array( 'http', 'https', 'ftp', 'ftps', 'mailto', 'news', 'irc', 'irc6', 'ircs', 'gopher', 'nntp', 'feed', 'telnet', 'mms', 'rtsp', 'sms', 'svn', 'tel', 'fax', 'xmpp', 'webcal', 'urn' );
}
function wp_parse_args( $args, $defaults = array() ) {
    if ( is_object( $args ) ) { $parsed_args = get_object_vars( $args ); }
    elseif ( is_array( $args ) ) { $parsed_args =& $args; }
    else { parse_str( (string) $args, $parsed_args ); }
    if ( is_array( $defaults ) && $defaults ) { return array_merge( $defaults, $parsed_args ); }
    return $parsed_args;
}
function sanitize_key( $key ) {
    $key = strtolower( (string) $key );
    return preg_replace( '/[^a-z0-9_\-]/', '', $key );
}
function wp_strip_all_tags( $text, $remove_breaks = false ) {
    if ( is_null( $text ) ) { return ''; }
    if ( ! is_scalar( $text ) ) { return ''; }
    $text = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $text );
    $text = strip_tags( $text );
    if ( $remove_breaks ) {
        $text = preg_replace( '/[\r\n\t ]+/', ' ', $text );
    }
    return trim( $text );
}
