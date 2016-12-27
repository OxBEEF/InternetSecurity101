<?php                                                                                                                                                                                          
/**
 * Fake plugin containing intentional security vulnerabilities designed for
 * plugin author education.
 *
 * Do NOT run this plugin on an internet accessible site. Do NOT re-use code
 * from this plugin.
 *
 * This plugin attempts to track potential attackers visiting a site and display
 * audit information to the administrator.
 */

/**
 * Log failed authentication attempts.
 *
 * @param WP_User $user
 * @param string $pass
 * @return WP_User
 */
function dvp_check_login( $user, $pass ) {
        if ( ! wp_check_password( $pass, $user->user_pass, $user->ID ) ) {
                dvp_log_failed_login( $user, $pass );
        }

        return $user;
}
add_filter( 'wp_authenticate_user', 'dvp_check_login', 10, 2 );

/**
 * Add a log record for a failed login attempt.
 *
 * @param WP_User $user
 * @param string $pass
 */
function dvp_log_failed_login( $user, $pass ) {
        global $wpdb;

        $login = $user->user_login;
        $ip = dvp_get_ip();
        $time = current_time( 'mysql' );

        $wpdb->query( $wpdb->prepare( "INSERT INTO login_audit (login, pass, ip, time) VALUES ('$login', '$pass', '$ip', '$time')" ) );
}

function dvp_menu() {
        add_submenu_page( 'tools.php', 'Failed Logins', 'Failed Logins', 'manage_options', 'failed-logins', 'dvp_admin' );
}
add_action( 'admin_menu', 'dvp_menu' );

// Display the failed login(s)
function dvp_admin() {                                                                                                                                                                         
        echo '<div class="wrap">';
        if ( ! empty( $_GET['id'] ) ) {
                dvp_view_log( $_GET['id'] );
        } else {
                dvp_view_all_logs();
        }
        echo '</div>';
}

// Display all failed login attempts + options form
function dvp_view_all_logs() {
        global $wpdb;
        $logs = $wpdb->get_results( "SELECT * FROM login_audit", ARRAY_A );

        echo '<h2>Failed logins</h2>';

        if (empty($logs)) {
                echo '<p>None... yet</p>';
        } else {
                echo '<table><thead><tr><td>Username</td><td>Password</td><td>IP address</td><td>Time</td></tr></thead><tbody>';

                foreach ($logs as $log) {
                        echo '<tr>';
                        echo '<td>' . $log['login'] . '</td>';
                        echo '<td>' . $log['pass'] . '</td>';
                        echo '<td>' . $log['ip'] . '</td>';
                        $url = add_query_arg( 'id', $log['ID'], menu_page_url( 'failed-logins', false ) );
                        echo '<td><a href="' . $url . '">' . $log['time'] . '</a></td>';
                        echo '</tr>';
                }

                echo '</tbody></table>';
        }

        echo '<hr />';

        echo '<h3>Settings</h3>';
        echo '<form action="admin-post.php?action=dvp_settings" method="post">';
        wp_nonce_field( 'dvp_settings', 'nonce' );
        echo '<label>';
        echo '<input type="checkbox" name="option[dvp_unknown_logins]" value="1" ' . checked(1, get_option('dvp_unknown_logins'), false) . ' />';
        echo 'Should login attempts for unknown usernames be logged?</label>';
        submit_button( 'Update', 'secondary' );
        echo '</form>';
}

// Display a single failed attempt with a form to delete the entry
function dvp_view_log( $id ) {
        global $wpdb;
                                                                                                                                                                                               
        $log = $wpdb->get_row( "SELECT * FROM login_audit WHERE ID = " . esc_sql( $id ), ARRAY_A );

        echo '<h2>Failed login #' . $id . '</h2>';

        echo '<div>';
        echo '<strong>Username:</strong> ' . $log['login'];
        echo '<br /><strong>Attempted password:</strong> ' . $log['pass'];
        echo '<br /><strong>IP address:</strong> ' . $log['ip'];
        echo '<br /><strong>Time of event:</strong> ' . $log['time'];
        echo '</div>';

        echo '<form action="admin-post.php?action=dvp_delete_log" method="post">';
        wp_nonce_field();
        echo '<input type="hidden" name="id" value="' . $id . '" />';
        echo '<input type="hidden" name="redirect" value="' . $_SERVER['PHP_SELF'] . '?page=failed-logins" />';
        submit_button( 'Delete entry', 'delete' );
        echo '</form>';
}

// Delete entry handler
function dvp_delete_log() {
        check_admin_referer();

        if ( isset( $_POST['id'] ) ) {
                global $wpdb;
                $wpdb->query( "DELETE FROM login_audit WHERE ID = " . esc_sql( $_POST['id'] ) );
        }

        wp_redirect( $_REQUEST['redirect'] );
}
add_action( 'admin_post_dvp_delete_log', 'dvp_delete_log' );

// Update plugin options handler
function dvp_change_settings() {
        // CSRF defence + caps check
        if (isset($_REQUEST['nonce']) && ! wp_verify_nonce($_REQUEST['nonce'], 'dvp_settings')
                || ! current_user_can( 'manage_options' )
        ) {
                wp_safe_redirect( admin_url( 'tools.php?page=failed-logins' ) );
        }

        if ( ! isset( $_POST['option']['dvp_unknown_logins'] ) )
                $_POST['option']['dvp_unknown_logins'] = 0;

        // Update options and redirect
        foreach ( $_POST['option'] as $name => $value )
                update_option( $name, $value );
        wp_safe_redirect( admin_url( 'tools.php?page=failed-logins' ) );
}
add_action( 'admin_post_dvp_settings', 'dvp_change_settings' );


/**
 * Retrieve the IP address of the current user
 *
 * @return string IP address of current user
 */
function dvp_get_ip() {
        // True IP in case of proxies
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else if (isset($_SERVER['REMOTE_ADDR'])) {
                return $_SERVER['REMOTE_ADDR'];
        }

        return '0.0.0.0';
}