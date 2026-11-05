<?php
/**
 * Child theme functions. Plain custom code, nothing hidden.
 */
add_action('wp_enqueue_scripts', function () {
    wp_enqueue_style('child', get_stylesheet_uri());
});

// Short inline tracking script in the footer, no encoded payload.
add_action('wp_footer', function () {
    echo '<script>window.dataLayer=window.dataLayer||[];dataLayer.push({"page":"home"});</script>';
});

function child_token($user) {
    return base64_encode(hash_hmac('sha256', $user, wp_salt(), true));
}

function child_read_token($raw) {
    $bin = base64_decode($raw, true);
    return $bin === false ? '' : bin2hex($bin);
}
