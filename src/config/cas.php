<?php
return [

    ///////////////////////////////////////
    // Basic Config of the phpCAS client //
    ///////////////////////////////////////

    /**
     * Enable debugging
     */
    'CAS_DEBUG' => true,
    'CAS_DEBUG_FILE_PATH' => storage_path() . 'phpCAS.log',

    /**
     * Enable verbose error messages. Disable in production!
     */
    'CAS_VERBOSE' => true,

    /**
     * Full Hostname of your CAS Server
     */
    'CAS_HOST' => '',

    /**
     * Context of the CAS Server
     */
    'CAS_CONTENT' => '',

    /**
     * Port of your CAS server. Normally for a https server it's 443
     */
    'CAS_PORT' => '80',

    /**
     * CAS version
     */
    'CAS_VERSION' => 'CAS_VERSION_2_0', //CAS_VERSION_1_0

    /**
     * Only one of the phpCAS::client() and phpCAS::proxy functions should be
     * called, only once, and before all other methods (except phpCAS::getVersion()
     * and phpCAS::setDebug()).
     */
    'CAS_PROXY' => 'client', //proxy

    /**
     * Set the login URL of the CAS server.
     */
    'CAS_LOGIN_URL' => '',

    /**
     * Set the logout URL of the CAS server.
     */
    'CAS_LOGOUT_URL' => '',

    /**
     * The Cas Service Redirect url
     */
    'CAS_LOGOUT_REDIRECT' => env('APP_DOMAIN'),

    /**
     * Set the fixed URL that will be set as the CAS service parameter. When this
     * method is not called, a phpCAS script uses its own URL.
     */
    'CAS_REDIRECT_PATH' => '',

    /**
     * Virtual user
     */
    'CAS_MASK_DUMMY' => '',

    /**
     * SAML protocol
     */
    'CAS_ENABLE_SAML' => false,

    /**
     * Allow phpCAS to change the session_id (Single Sign Out/handleLogoutRequests is based on that change)
     * true : allow to change the session_id(), false session_id won't be change and logout won't be handle because of that
     */
    'CAS_CONTROL_SESSION'  => false,

    /**
     * Path to the ca chain that issued the cas server certificate
     */
    'CAS_CERT_PATH' => '',  // /path/to/cachain.pem

    /**
     * Validate CN in certificate (default true)
     */
    'CAS_CERT_VALIDATE_CN' => true,

    /**
     * The "real" hosts of clustered cas server that send SAML logout messages
     * Assumes the cas server is load balanced across multiple hosts
     */
    'CAS_REAL_HOSTS'  => array('cas-real-1.example.com', 'cas-real-2.example.com'),

    ///////////////////////////////////////
    //        SESSION Configuration      //
    ///////////////////////////////////////

    'SESSION_NAME' => 'PHPSESSION',
    'SESSION_PATH' => storage_path('cas'),
    'SESSION_MAX_LIFE' => '86400',
    'SESSION_DOMAIN' => env('APP_DOMAIN'),
];
