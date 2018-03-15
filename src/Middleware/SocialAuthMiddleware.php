<?php

namespace CakeDC\Users\Middleware;

use Cake\Core\InstanceConfigTrait;
use Cake\Network\Exception\NotFoundException;
use CakeDC\Users\Auth\Exception\InvalidProviderException;
use CakeDC\Users\Auth\Exception\InvalidSettingsException;
use CakeDC\Users\Auth\Exception\MissingProviderConfigurationException;
use CakeDC\Users\Auth\Social\Util\SocialUtils;
use CakeDC\Users\Controller\Traits\ReCaptchaTrait;
use CakeDC\Users\Exception\AccountNotActiveException;
use CakeDC\Users\Exception\MissingEmailException;
use CakeDC\Users\Exception\MissingProviderException;
use CakeDC\Users\Exception\UserNotActiveException;
use CakeDC\Users\Listener\AuthListener;
use CakeDC\Users\Model\Table\SocialAccountsTable;
use Cake\Core\Configure;
use Cake\Event\EventDispatcherTrait;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\Log\LogTrait;
use Cake\ORM\TableRegistry;
use Cake\Utility\Hash;
use League\OAuth2\Client\Provider\AbstractProvider;
use Psr\Http\Message\ResponseInterface;

class SocialAuthMiddleware
{
    use EventDispatcherTrait;
    use InstanceConfigTrait;
    use LogTrait;
    use ReCaptchaTrait;

    const AUTH_ERROR_MISSING_EMAIL = 10;
    const AUTH_ERROR_ACCOUNT_NOT_ACTIVE = 20;
    const AUTH_ERROR_USER_NOT_ACTIVE = 30;
    const AUTH_ERROR_INVALID_RECAPTCHA = 40;
    const AUTH_SUCCESS = 100;

    protected $_defaultConfig = [];
    protected $authStatus = 0;
    protected $rawData = [];
    protected $providerConfig = [];
    protected $providerName;
    /**
     * @var \CakeDC\Users\Social\Service\ServiceInterface
     */
    protected $service;

    /**
     * Serve assets if the path matches one.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \Psr\Http\Message\ResponseInterface $response The response.
     * @param callable $next Callback to invoke the next middleware.
     * @return \Psr\Http\Message\ResponseInterface A response
     */
    public function __invoke(ServerRequest $request, ResponseInterface $response, $next)
    {
        $action = $request->getParam('action');
        if (!in_array($action, ['socialLogin', 'socialEmail'])) {
            return $next($request, $response);
        }

        $this->setConfig($this->initialConfig([]));
        if ($action == 'socialEmail') {
            return $this->handleSocialEmailStep($request, $response, $next);
        }

        $service = $this->service($request);
        if (!$service->isGetUserStep($request)) {
            return $response->withLocation($service->getAuthorizationUrl($request));
        }

        return $this->finishWithResult($this->authenticate($request), $request, $response, $next);
    }

    /**
     * finish middleware process.
     *
     * @param int $result authentication result
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \Psr\Http\Message\ResponseInterface $response The response.
     * @param callable $next Callback to invoke the next middleware.
     * @return \Psr\Http\Message\ResponseInterface A response
     */
    private function finishWithResult($result, ServerRequest $request, ResponseInterface $response, $next)
    {
        if ($result) {
            $this->authStatus = self::AUTH_SUCCESS;
            $request->getSession()->write(
                $this->getConfig('sessionAuthKey'),
                $result
            );
        }

        $request = $request->withAttribute('socialAuthStatus', $this->authStatus);
        $request = $request->withAttribute('socialRawData', $this->rawData);

        return $next($request, $response);
    }

    /**
     * Handle social email step post.
     *
     * @param int $result authentication result
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \Psr\Http\Message\ResponseInterface $response The response.
     * @param callable $next Callback to invoke the next middleware.
     * @return \Psr\Http\Message\ResponseInterface A response
     */
    private function handleSocialEmailStep(ServerRequest $request, ResponseInterface $response, $next)
    {
        if (!$request->getSession()->check(Configure::read('Users.Key.Session.social'))) {
            throw new NotFoundException();
        }
        $request->getSession()->delete('Flash.auth');
        $result = false;

        if (!$request->is('post')) {
            return $this->finishWithResult($result, $request, $response, $next);
        }

        if (!$this->_validateRegisterPost($request)) {
            $this->authStatus = self::AUTH_ERROR_INVALID_RECAPTCHA;
        } else {
            $result = $this->authenticate($request);
        }

        return $this->finishWithResult($result, $request, $response, $next);
    }

    /**
     * Check the POST and validate it for registration, for now we check the reCaptcha
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return bool
     */
    protected function _validateRegisterPost($request)
    {
        if (!Configure::read('Users.reCaptcha.registration')) {
            return true;
        }

        return $this->validateReCaptcha(
            $request->getData('g-recaptcha-response'),
            $request->clientIp()
        );
    }

    /**
     * Get a user based on information in the request.
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     * @param \Cake\Http\Response $response Response object
     * @return bool
     * @throws \RuntimeException If the `CakeDC/Users/OAuth2.newUser` event is missing or returns empty.
     */
    public function authenticate(ServerRequest $request)
    {
        $data = $request->getSession()->read(Configure::read('Users.Key.Session.social'));
        $requestDataEmail = $request->getData('email');
        if (!empty($data) && empty($data['uid']) && (!empty($data['email']) || !empty($requestDataEmail))) {
            if (!empty($requestDataEmail)) {
                $data['email'] = $requestDataEmail;
            }
            $user = $data;
            $request->getSession()->delete(Configure::read('Users.Key.Session.social'));
        } else {

            if (empty($data) && !$rawData = $this->_authenticate($request)) {
                return false;
            }

            if (empty($rawData)) {
                $rawData = $data;
            }

            try {
                $user = $this->_mapUser($rawData);
            } catch (MissingProviderException $ex) {
                $request->getSession()->delete(Configure::read('Users.Key.Session.social'));
                throw $ex;
            }
        }
        if (!$user || !$this->getConfig('userModel')) {
            return false;
        }

        $this->rawData = $user;
        if (!$result = $this->_touch($user)) {
            return false;
        }

        if ($request->getSession()->check(Configure::read('Users.Key.Session.social'))) {
            $request->getSession()->delete(Configure::read('Users.Key.Session.social'));
        }
        $request->getSession()->write('Users.successSocialLogin', true);

        return $result;
    }


    /**
     * Instance of OAuth2 provider.
     *
     * @var \League\OAuth2\Client\Provider\AbstractProvider
     */
    protected $_provider;

    /**
     * Get initial config
     *
     * @param array $config Array of config to use.
     * @throws \Exception
     *
     * @return array
     */
    public function initialConfig(array $config = [])
    {
        $oauthConfig = Configure::read('OAuth');
        $enabledNoOAuth2Provider = $this->_isProviderEnabled($oauthConfig['providers']['twitter']);

        $providers = [];
        foreach ($oauthConfig['providers'] as $provider => $options) {
            if ($this->_isProviderEnabled($options)) {
                $providers[$provider] = $options;
            }
        }
        $oauthConfig['providers'] = $providers;
        Configure::write('OAuth2', $oauthConfig);
        $config['userModel'] = Configure::read('Users.table');
        $base = (array)Configure::read('SocialAuthMiddleware');
        $config = $this->normalizeConfig(Hash::merge($base, $config, $oauthConfig), $enabledNoOAuth2Provider);
        return $config;
    }

    /**
     * Normalizes providers' configuration.
     *
     * @param array $config Array of config to normalize.
     * @param bool $enabledNoOAuth2Provider True when any noOAuth2 provider is enabled
     * @return array
     * @throws \Exception
     */
    public function normalizeConfig(array $config, $enabledNoOAuth2Provider = false)
    {
        $config = Hash::merge((array)Configure::read('OAuth2'), $config);
        if (empty($config['providers']) && !$enabledNoOAuth2Provider) {
            throw new MissingProviderConfigurationException();
        }

        if (!empty($config['providers'])) {
            array_walk($config['providers'], [$this, '_normalizeConfig'], $config);
        }

        return $config;
    }

    /**
     * Callback to loop through config values.
     *
     * @param array $config Configuration.
     * @param string $alias Provider's alias (key) in configuration.
     * @param array $parent Parent configuration.
     * @return void
     */
    protected function _normalizeConfig(&$config, $alias, $parent)
    {
        unset($parent['providers']);

        $defaults = [
                'className' => null,
                'service' => null,
                'mapper' => null,
                'options' => [],
                'collaborators' => [],
                'mapFields' => [],
            ] + $parent + $this->_defaultConfig;

        $config = array_intersect_key($config, $defaults);
        $config += $defaults;

        array_walk($config, [$this, '_validateConfig']);

        foreach (['options', 'collaborators'] as $key) {
            if (empty($parent[$key]) || empty($config[$key])) {
                continue;
            }

            $config[$key] = array_merge($parent[$key], $config[$key]);
        }
    }

    /**
     * Validates the configuration.
     *
     * @param mixed $value Value.
     * @param string $key Key.
     * @return void
     * @throws \CakeDC\Users\Auth\Exception\InvalidProviderException
     * @throws \CakeDC\Users\Auth\Exception\InvalidSettingsException
     */
    protected function _validateConfig(&$value, $key)
    {
        if (in_array($key, ['className', 'service', 'mapper'], true) && !class_exists($value)) {
            throw new InvalidProviderException([$value]);
        } elseif (!is_array($value) && in_array($key, ['options', 'collaborators'])) {
            throw new InvalidSettingsException([$key]);
        }
    }

    /**
     * Returns when a provider has been enabled.
     *
     * @param array $options array of options by provider
     * @return bool
     */
    protected function _isProviderEnabled($options)
    {
        return !empty($options['options']['redirectUri']) && !empty($options['options']['clientId']) &&
            !empty($options['options']['clientSecret']);
    }

    /**
     * Authenticates with OAuth provider by getting an access token and
     * retrieving the authorized user's profile data.
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     * @return array|bool
     */
    protected function _authenticate(ServerRequest $request)
    {
        try {
            return $this->service($request)->getUser($request);
        } catch (\Exception $e) {
            $message = sprintf(
                "Error getting an access token / retrieving the authorized user's profile data. Error message: %s %s",
                $e->getMessage(),
                $e
            );
            $this->log($message);

            return false;
        }
    }

    /**
     * Maps raw provider's user profile data to local user's data schema.
     *
     * @param array $data Raw user data.
     * @return array
     */
    protected function _map($data)
    {
        if (!$map = $this->getConfig('mapFields')) {
            return $data;
        }

        foreach ($map as $dst => $src) {
            $data[$dst] = $data[$src];
            unset($data[$src]);
        }

        return $data;
    }

    /**
     * Returns the `$requested service.
     *
     * @param \Cake\Http\ServerRequest $request Current HTTP request.
     * @return \CakeDC\Users\Social\Service\ServiceInterface|false
     */
    public function service(ServerRequest $request)
    {
        $alias = $request->getAttribute('params')['provider'] ?? null;

        $config = $this->getConfig('providers.' . $alias);
        if (!$alias || !$config) {
            throw new NotFoundException('Not found provider');
        }
        $this->providerName = $alias;
        $this->providerConfig = $config;
        if ($this->service === null) {
            $this->service = new $config['service']($config);
        }

        return $this->service;
    }

    /**
     * Find or create local user
     *
     * @param array $data data
     * @return array|bool|mixed
     * @throws MissingEmailException
     */
    protected function _touch(array $data)
    {
        try {
            $user = $this->_socialLogin($data);
        } catch (UserNotActiveException $ex) {
            $this->authStatus = self::AUTH_ERROR_USER_NOT_ACTIVE;
            $exception = $ex;
        } catch (AccountNotActiveException $ex) {
            $this->authStatus = self::AUTH_ERROR_ACCOUNT_NOT_ACTIVE;
            $exception = $ex;
        } catch (MissingEmailException $ex) {
            $this->authStatus = self::AUTH_ERROR_MISSING_EMAIL;
            $exception = $ex;
        }

        if (!empty($exception)) {
            $args = ['exception' => $exception, 'rawData' => $data];
            $this->dispatchEvent( AuthListener::EVENT_FAILED_SOCIAL_LOGIN, $args);
            return false;
        }

        // If new SocialAccount was created $user is returned containing it
        if ($user->get('social_accounts')) {
            $this->dispatchEvent(AuthListener::EVENT_AFTER_SOCIAL_REGISTER, compact('user'));
        }

        if (!empty($user->username)) {

            $user = $this->findUser($user)->first();
        }

        return $user;
    }

    /**
     * Get query object for fetching user from database.
     *
     * @param User $user The user.
     *
     * @return \Cake\Orm\Query
     */
    protected function findUser($user)
    {
        $config = $this->_config;
        $table = TableRegistry::get($config['userModel']);
        $field = $this->getConfig('usernameField');
        $finder = $this->getConfig('finder');

        return $table->find($finder)->where([
            $field => $user->get($field)
        ]);
    }

    /**
     * Map userdata with mapper defined at $providerConfig
     *
     * @param array $data User data
     * @return mixed Either false or an array of user information
     */
    protected function _mapUser($data)
    {
        $providerMapperClass = $this->providerConfig['mapper'];
        $providerMapper = new $providerMapperClass($data);
        $user = $providerMapper();
        $user['provider'] = $this->providerName;

        return $user;
    }

    /**
     * @param mixed $data data
     * @return mixed
     */
    protected function _socialLogin($data)
    {
        $options = [
            'use_email' => Configure::read('Users.Email.required'),
            'validate_email' => Configure::read('Users.Email.validate'),
            'token_expiration' => Configure::read('Users.Token.expiration')
        ];

        $userModel = Configure::read('Users.table');
        $User = TableRegistry::get($userModel);
        $user = $User->socialLogin($data, $options);

        return $user;
    }

}