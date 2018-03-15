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
use CakeDC\Users\Social\Locator\DatabaseLocator;
use CakeDC\Users\Social\ProviderConfig;
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
    const AUTH_ERROR_FIND_USER = 50;
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

        $this->setConfig(Configure::read('SocialAuthMiddleware'));
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
    private function _validateRegisterPost($request)
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
    private function authenticate(ServerRequest $request)
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
        if (!$user) {
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
     * Returns the `$requested service.
     *
     * @param \Cake\Http\ServerRequest $request Current HTTP request.
     * @return \CakeDC\Users\Social\Service\ServiceInterface|false
     */
    protected function service(ServerRequest $request)
    {
        if ($this->service !== null) {
            return $this->service;
        }

        $alias = $request->getAttribute('params')['provider'] ?? null;
        $config = (new ProviderConfig())->getConfig($alias);
        if (!$alias || !$config) {
            throw new NotFoundException('Not found provider');
        }
        $this->providerName = $alias;
        $this->providerConfig = $config;
        $this->service = new $config['service']($config);

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
        $locator = new DatabaseLocator($this->getConfig('locator'));
        try {
            return $locator->getOrCreate($data);
        } catch (UserNotActiveException $ex) {
            $this->authStatus = self::AUTH_ERROR_USER_NOT_ACTIVE;
            $exception = $ex;
        } catch (AccountNotActiveException $ex) {
            $this->authStatus = self::AUTH_ERROR_ACCOUNT_NOT_ACTIVE;
            $exception = $ex;
        } catch (MissingEmailException $ex) {
            $this->authStatus = self::AUTH_ERROR_MISSING_EMAIL;
            $exception = $ex;
        } catch(RecordNotFoundException $ex) {
            $this->authStatus = self::AUTH_ERROR_FIND_USER;
            $exception = $ex;
        }

        $args = ['exception' => $exception, 'rawData' => $data];
        $this->dispatchEvent( AuthListener::EVENT_FAILED_SOCIAL_LOGIN, $args);

        return false;
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

}