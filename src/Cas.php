<?php

namespace Medlive\LaravelCas;

use Couchbase\Exception;
use phpCAS;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

class Cas
{

    protected $error = 'no initialize';

    /**
     * Cas" configuration settings array
     */
    protected $config;

    /**
     * Fake user for use when the "CAS" server cannot be called
     */
    protected $_maskdummy = false;

    /**
     * Attributes used for overriding or masquerading.
     */
    protected $_attributes = [];

    protected $auth;

    protected $userid;

    /**
     * @param array $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;

        if (!$this->validateSpider()) {
            $this->setAuth(false);
            $this->setUser(0);
        }

        if ($dummy = $this->config['CAS_MASK_DUMMY']) {
            $this->setAuth(true);
            $this->setUser($dummy);
        }

        $this->initializeCas();
    }

    /**
     * Initial configuration Cas Client
     */
    public function initializeCas()
    {
        if (!phpCAS::isInitialized()) {
            // Initialize phpCAS
            $this->configureCasClient();
        }

        $this->error = 'initialize cas';

        // validateLogout
        $this->validateLogout();
    }

    /**
     * Configure CAS Client|Proxy
     * @param $method
     */
    protected function configureCasClient($method = 'client')
    {
        $this->setDebug();

        phpCAS::$method(
            $this->serverVersion(),
            $this->config['CAS_HOST'],
            (int)$this->config['CAS_PORT'],
            $this->config['CAS_CONTENT'],
            $this->config['CAS_CONTROL_SESSION']
        );

        // $this->setSessionInfo();

        if ($this->config['CAS_ENABLE_SAML']) {
            // Handle SAML logout requests that emanate from the CAS host exclusively.
            // Failure to restrict SAML logout requests to authorized hosts could
            // allow denial of service attacks where at the least the server is
            // tied up parsing bogus XML messages.
            phpCAS::handleLogoutRequests(true, explode(',', $this->config['CAS_REAL_HOSTS']));
        }

        // For production use set the CA certificate that is the issuer of the cert on the CAS server and uncomment the line below
        $this->configureCasCert();

        // Set some urls
        $this->setServiceUrl();
    }

    /**
     * Get phpCAS initializer server type
     * @return mixed|string
     */
    protected function serverVersion()
    {
        if ($this->config['CAS_ENABLE_SAML']) {
            $server_type = SAML_VERSION_1_1;
        } else {
            // This allows the user to use 1.0, 2.0, etc as a string in the config
            $cas_version_str = $this->config['CAS_VERSION'];

            // We pull the phpCAS constant values as this is their definition
            // PHP will generate a E_WARNING if the version string is invalid which is helpful for troubleshooting
            $server_type = constant($cas_version_str);

            if (is_null($server_type)) {
                // This will never be null, but can be invalid values for which we need to detect and substitute.
                phpCAS::log('Invalid CAS version set; Reverting to defaults');
                $server_type = CAS_VERSION_2_0;
            }
        }

        return $server_type;
    }

    /**
     * If a fake user is set in the configuration
     * @return bool
     */
    protected function isDummy()
    {
        if (!empty($this->config['CAS_MASK_DUMMY'])) {
            $this->_maskdummy = true;
            phpCAS::log('Masquerading as user: ' . $this->config['CAS_MASK_DUMMY']);
            return true;
        }
        return false;
    }

    /**
     * set debug and verbose
     */
    protected function setDebug()
    {
        if ($this->config['CAS_DEBUG']) {
            try {
                phpCAS::setDebug($this->config['CAS_DEBUG_FILE_PATH']);
            } catch (\Exception $e) {
                if (!class_exists("\\Monolog\\Logger") || !class_exists("\\Monolog\\Handler\\StreamHandler")) {
                    $logger = null;
                } else {
                    // Fix for depreciation of setDebug
                    // Does the file exist
                    if (!file_exists($this->config['CAS_DEBUG_FILE_PATH'])) {
                        fopen($this->config['CAS_DEBUG_FILE_PATH'], "w");
                    }
                    // Instantiate the log class (the log header information here can be customized, so that you can quickly find out the log you need)
                    $logger = new \Monolog\Logger('LaravelCas');
                    // Write
                    $logger->pushHandler(new \Monolog\Handler\StreamHandler($this->config['CAS_DEBUG_FILE_PATH'], \Monolog\Logger::INFO));
                }

                phpCAS::setLogger($logger);
            }
            phpCAS::log('Loaded configuration:' . PHP_EOL . serialize($this->config));
            phpCAS::setVerbose($this->config['CAS_VERBOSE']);
        }
    }

    /**
     * Configure SSL Validation
     * Having some kind of server cert validation in production is highly recommended.
     */
    protected function configureCasCert()
    {
        if (!empty($this->config['CAS_CERT_PATH'])) {
            // You can also disable the validation of the certficate CN. This means the
            // certificate must be valid but the CN of the certificate must not match the
            // IP or hostname you are using to access the server
            phpCAS::setCasServerCACert($this->config['CAS_CERT_PATH'], $this->config['CAS_CERT_VALIDATE_CN']);
        } else {
            // For quick testing you can disable SSL validation of the CAS server.
            // THIS SETTING IS NOT RECOMMENDED FOR PRODUCTION.
            // VALIDATING THE CAS SERVER IS CRUCIAL TO THE SECURITY OF THE CAS PROTOCOL!
            phpCAS::setNoCasServerValidation();
        }
    }

    /**
     * Verify that HTTP_USER_AGENT is a spider
     * @return bool
     */
    protected static function validateSpider()
    {
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            return false;
        }
        $agent = $_SERVER['HTTP_USER_AGENT'];
        $spiders = array(
            'Googlebot', 'msnbot', 'Baiduspider', 'bingbot', 'Sogou web spider', 'Sogou inst spider', 'Sogou Pic Spider',
            'JikeSpider', 'Sosospider', 'Slurp', '360Spider', 'YodaoBot', 'OutfoxBot', 'fast-webcrawler',
            'lycos_spider', 'scooter', 'ia_archiver', 'MJ12bot', 'AhrefsBot', 'Yisouspider', 'Bytespider',
        );
        foreach ($spiders as $spider) {
            if (stristr($agent, $spider)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Set session and cookie
     */
    protected function setSessionInfo()
    {
        // Calling the session_name() function generates an error after the content of the cookie is sent in the HTTP response
        // In php7.2, you need to use session_start() before
        // More information：php.net/manual/zh/function.session-name.php
        if (!headers_sent() && session_id() == "") {
//            try {
//                if(!file_exists($this->config['SESSION_PATH'].'/.gitignore')) {
//                    mkdir($this->config['SESSION_PATH'], 0777, true);
//                    file_put_contents($this->config['SESSION_PATH'].'/.gitignore',"*\n!.gitignore");
//                }
//            } catch (\Exception $e) {
//                throw new \Exception('Cannot create file： ' . $this->config['SESSION_PATH'].'/.gitignore');
//            }

            session_name($this->config['SESSION_NAME']);

            // Harden session cookie to prevent some attacks on the cookie (e.g. XSS)
            $currentCookieParams = session_get_cookie_params();
            session_set_cookie_params(
                $this->config['SESSION_MAX_LIFE'],
                $this->config['SESSION_PATH'],
                $this->config['SESSION_DOMAIN'],
                $currentCookieParams["secure"],
                $currentCookieParams["httponly"]
            );
        }
    }

    /**
     * Set up login and logout url
     */
    protected function setServiceUrl()
    {
        // Set the login URL of the CAS server.
        if ($this->config['CAS_LOGIN_URL']) {
            phpCAS::setServerLoginURL($this->config['CAS_LOGIN_URL']);
        }
        // If specified, this will override the URL the user will be returning to.
        if ($this->config['CAS_REDIRECT_PATH']) {
            // Set the fixed URL that will be set as the CAS service parameter.
            // When this method is not called, a phpCAS script uses its own URL.
            phpCAS::setFixedServiceURL($this->config['CAS_REDIRECT_PATH']);
        }

        // 设置 登出 url
        phpCAS::setServerLogoutURL($this->config['CAS_LOGOUT_URL']);

        // 设置 validate url
        phpCAS::setServerServiceValidateURL($this->config['CAS_VALIDATE_URL']);
    }

    /**
     * Returns the current config.
     *
     * @return array
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * Get login url
     * @return string
     */
    public function login_url()
    {
        return \phpCAS::getServerLoginURL();
    }

    /**
     * Get logout url
     * @return string
     */
    public function logout_url()
    {
        return \phpCAS::getServerLogoutURL();
    }

    /**
     * Handle logout requests.
     * Verify in any request
     */
    public function validateLogout()
    {
        if (empty($_POST['logoutRequest'])) {
            return;
        }
        // 仅取 CAS_REAL_HOSTS 中的 HOST 部分
        \phpCAS::handleLogoutRequests(true, array_map(function ($url) {
            return parse_url($url, PHP_URL_HOST);
        }, $this->config['CAS_REAL_HOSTS']));

        die();
    }

    /**
     * Logout of the CAS session and redirect users.
     *
     * @param string $service
     */
    public function logout($service = '')
    {
        if (phpCAS::isSessionAuthenticated()) {
            if (isset($_SESSION['phpCAS'])) {
                $serialized = serialize($_SESSION['phpCAS']);
                phpCAS::log('Logout requested, but no session data found for user:' . PHP_EOL . $serialized);
            }
        }
        $params = [];

        // set logout url
        $params['url'] = \phpCAS::getServerLogoutURL();

        // set logout redirect url
        if ($service) {
            $params['service'] = $service;
        } else if ($this->config['CAS_LOGOUT_REDIRECT']) {
            $params['service'] = $this->config['CAS_LOGOUT_REDIRECT'];
        } else {
            if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
                $params['service'] = 'https://';
            } else {
                $params['service'] = 'http://';
            }
            $params['service'] .= $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
        }

        \phpCAS::logout($params);
        $_SESSION['phpCAS']['user'] = 0;
        exit;
    }

    /**
     * Retrieve authenticated credentials.
     * Returns either the masqueraded account or the phpCAS user.
     * 获取用户id
     * @return int
     */
    public function user()
    {
        if (isset($this->userid)) {
            return $this->userid;
        }
        // 重新去cas服务器验证后，自动获取到user
        $this->auth = $this->checkAuthentication();
        if (!$this->auth) {
            return 0;
        }
        $this->userid = (int)phpCAS::getUser();
        return $this->userid;
    }

    /**
     * Checks to see is user is authenticated locally
     * 不自动跳转登陆
     *
     * @return bool
     */
    public function isAuthenticated()
    {
        if (isset($this->auth)) {
            return $this->auth;
        }
        return $this->isDummy() || phpCAS::isAuthenticated();
    }

    /**
     * Checks to see is user is globally in CAS
     * 不自动跳转登陆
     * @return bool
     * @throws \Exception
     */
    public function checkAuthentication()
    {
        if (isset($this->auth)) {
            return $this->auth;
        }
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            // 1.可能出现页面显示到提交这段时间内，其他站点登录，本站无效问题
            // 2.直接跨域POST请求，可能发生身份取得不正确的问题
            $this->auth = $this->isAuthenticated();
        } else {
            try {
                $this->auth = phpCAS::checkAuthentication();
            } catch(\Exception $e) {
                $this->auth = false;
                $str = '[Error]' . $this->error . ' [HTTP_REFERER]' . ($_SERVER['HTTP_REFERER'] ?? '') . ' [USER_AGENT]' . ($_SERVER['HTTP_USER_AGENT'] ?? '');
                $ne = new \Exception($str, 40000, $e);
                report($ne);
            }
        }
        if (empty($this->auth)) {
            $this->userid = 0;
        } else {
            $this->userid = (int)phpCAS::getUser();
        }
        return $this->auth;
    }

    /**
     * Authenticates the user based on the current request.
     * 强制登陆
     * @return bool
     */
    public function forceAuthentication()
    {
        if ($this->isDummy()) {
            return true;
        }
        return phpCAS::forceAuthentication();
    }

    /**
     * Retrieve a specific attribute by key name.  The
     * attribute returned can be either a string or
     * an array based on matches.
     *
     * @param $key
     *
     * @return mixed
     */
    public function getAttribute($key)
    {
        if (!$this->isDummy()) {
            return phpCAS::getAttribute($key);
        }
        if ($this->hasAttribute($key)) {
            return $this->_attributes[$key];
        }

        return;
    }

    /**
     * Get the attributes for for the currently connected user. This method
     * can only be called after forceAuthentication() or an error wil be thrown.
     *
     * @return mixed
     */
    public function getAttributes()
    {
        // We don't error check because phpCAS has its own error handling.
        return $this->isDummy() ? $this->_attributes : phpCAS::getAttributes();
    }

    /**
     * Check for the existence of a key in attributes.
     *
     * @param $key
     *
     * @return boolean
     */
    public function hasAttribute($key)
    {
        if ($this->isDummy()) {
            return array_key_exists($key, $this->_attributes);
        }

        return phpCAS::hasAttribute($key);
    }

    /**
     * Set the attributes for a user when masquerading. This
     * method has no effect when not masquerading.
     *
     * @param array $attr : the attributes of the user.
     */
    public function setAttributes(array $attr)
    {
        $this->_attributes = $attr;
        phpCAS::log('Forced setting of user masquerading attributes: ' . serialize($attr));
    }

    public function setAuth($auth)
    {
        $this->auth = (bool)$auth;
        return $this;
    }

    public function setUser($id)
    {
        $this->userid = (int)$id;
        return $this;
    }

    /**
     * Pass through undefined methods to phpCAS
     * @param $method
     * @param $params
     * @return mixed
     */
    public function __call($method, $params)
    {
        if (method_exists('phpCAS', $method) && is_callable(['phpCAS', $method])) {
            return call_user_func_array(['phpCAS', $method], $params);
        }
        throw new \BadMethodCallException('Method not callable in phpCAS ' . $method . '::' . print_r($params, true));
    }
}
