<?php   
/* Plugin Name: Damn Vulnerable WordPress Plugin
 * Description: Intentionally vulnerable plugin for plugin author education
 * Version: 0.1
 * Plugin URI: http://make.wordpress.org/plugins/2013/04/09/intentionally-vulnerable-plugin/
 * Author: Jon Cave
 * Author URI: http://joncave.co.uk
 * License: GPLv2+
 *              
 * DO NOT RUN THIS PLUGIN ON AN INTERNET ACCESSIBLE SITE
 */     

function dvp_admin_safety_notice() { 
        echo '<div class="error"><p><strong>WARNING:</strong> Damn Vulnerable WordPress Plugin contains
                intentional security issues and should only be run on local development machines.</p></div>';
}
add_action( 'all_admin_notices', 'dvp_admin_safety_notice' );                                                                                                                                  

// Safety precautions are out of the way so load the actual stuff
if (defined('LOAD_INTENTIONAL_VULNS') && LOAD_INTENTIONAL_VULNS) {
	include( dirname(__FILE__) . '/vulnerable.php' );
}
                
function dvp_install() {
        $sql = "CREATE TABLE login_audit (
                ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                login varchar(200) NOT NULL default '',
                pass varchar(200) NOT NULL default '',
                ip varchar(20) NOT NULL default '',
                time datetime NOT NULL default '0000-00-00 00:00:00',
                PRIMARY KEY (ID)
        );";
                
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );

        update_option( 'dvp_unknown_logins', 1 );
}
register_activation_hook( __FILE__, 'dvp_install' );