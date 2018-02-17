<?php

namespace CakeDC\Users\Authenticator;

use Authentication\Authenticator\AbstractAuthenticator;
use Authentication\Authenticator\Result;
use Authentication\Identifier\IdentifierInterface;
use Authentication\UrlChecker\UrlCheckerTrait;
use Cake\Core\Configure;
use Cake\Log\Log;
use Cake\Log\LogTrait;
use Cake\ORM\TableRegistry;
use Cake\Utility\Hash;
use CakeDC\Users\Auth\Exception\InvalidProviderException;
use CakeDC\Users\Auth\Exception\InvalidSettingsException;
use CakeDC\Users\Auth\Exception\MissingProviderConfigurationException;
use CakeDC\Users\Auth\Social\Util\SocialUtils;
use CakeDC\Users\Controller\Component\UsersAuthComponent;
use CakeDC\Users\Exception\AccountNotActiveException;
use CakeDC\Users\Exception\MissingEmailException;
use CakeDC\Users\Exception\MissingProviderException;
use CakeDC\Users\Exception\UserNotActiveException;
use CakeDC\Users\Model\Table\SocialAccountsTable;
use League\OAuth2\Client\Provider\AbstractProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Social Authenticator
 *
 * Authenticates an identity based on the social oauth
 */
class SocialAuthenticator extends AbstractAuthenticator
{
    use LogTrait;

    /**
     * Identifier collection.
     *
     * @var \Authentication\Identifier\IdentifierCollection
     */
    protected $_identifiers;

    private $_provider;

    /**
     * Constructor
     *
     * @param \Authentication\Identifier\IdentifierInterface $identifier Identifier or identifiers collection.
     * @param array $config Configuration settings.
     */
    public function __construct(IdentifierInterface $identifier, array $config = [])
    {
        $config = $this->initialConfig($config);

        parent::__construct($identifier, $config);
    }


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
        //We unset twitter from providers to exclude from OAuth2 config
        unset($oauthConfig['providers']['twitter']);

        $providers = [];
        foreach ($oauthConfig['providers'] as $provider => $options) {
            if ($this->_isProviderEnabled($options)) {
                $providers[$provider] = $options;
            }
        }
        $oauthConfig['providers'] = $providers;

        Configure::write('OAuth2', $oauthConfig);
        $config = $this->normalizeConfig(Hash::merge($config, $oauthConfig), $enabledNoOAuth2Provider);

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
        if ($key === 'className' && !class_exists($value)) {
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
     * Prepares the error object for a login URL error
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request that contains login information.
     * @return \Authentication\Authenticator\ResultInterface
     */
    protected function _buildLoginUrlErrorResult($request)
    {
        $errors = [
            sprintf(
                'Oauth state invalid.',
                (string)$request->getUri(),
                implode('` or `', (array)$this->getConfig('loginUrl'))
            )
        ];

        return new Result(null, Result::FAILURE_OTHER, $errors);
    }

    /**
     * Authenticate user.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \Psr\Http\Message\ResponseInterface $response The response.
     * @return \Authentication\Authenticator\ResultInterface
     */
    public function authenticate(ServerRequestInterface $request, ResponseInterface $response)
    {
        if (!$this->_validate($request)) {
            return new Result(null, Result::FAILURE_OTHER, ['Oauth state is not valid']);
        }

        $user = $this->getUser($request);
        if (empty($user)) {
            return new Result(null, Result::FAILURE_IDENTITY_NOT_FOUND, $this->_identifier->getErrors());
        }

        return new Result($user, Result::SUCCESS);
    }

    /**
     * Validates OAuth2 request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return bool
     */
    protected function _validate(ServerRequestInterface $request)
    {
        if (!array_key_exists('code', $request->getQueryParams()) || !$this->provider($request)) {
            return false;
        }

        $session = $request->getSession();
        $sessionKey = 'oauth2state';
        $state = $request->getQuery('state');

        if ($this->getConfig('options.state') &&
            (!$state || $state !== $session->read($sessionKey))) {
            $session->delete($sessionKey);

            return false;
        }

        return true;
    }

    /**
     * Get a user based on information in the request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return mixed Either false or an array of user information
     * @throws \RuntimeException If the `CakeDC/Users/OAuth2.newUser` event is missing or returns empty.
     */
    public function getUser(ServerRequestInterface $request)
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

            $provider = $this->_getProviderName($request);
            try {
                $user = $this->_mapUser($provider, $rawData);
            } catch (MissingProviderException $ex) {
                $request->getSession()->delete(Configure::read('Users.Key.Session.social'));
                throw $ex;
            }
            if ($user['provider'] === SocialAccountsTable::PROVIDER_TWITTER) {
                $request->getSession()->write(Configure::read('Users.Key.Session.social'), $user);
            }
        }

        if (!$user || !$this->getConfig('userModel')) {
            return false;
        }

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
     * Find or create local user
     *
     * @param array $data data
     * @return array|bool|mixed
     * @throws MissingEmailException
     */
    protected function _touch(array $data)
    {
        try {
            if (empty($data['provider']) && !empty($this->_provider)) {
                $data['provider'] = SocialUtils::getProvider($this->_provider);
            }
            $user = $this->_socialLogin($data);
        } catch (UserNotActiveException $ex) {
            $exception = $ex;
        } catch (AccountNotActiveException $ex) {
            $exception = $ex;
        } catch (MissingEmailException $ex) {
            $exception = $ex;
        }
        if (!empty($exception)) {
            $args = ['exception' => $exception, 'rawData' => $data];
            $this->dispatchEvent(UsersAuthComponent::EVENT_FAILED_SOCIAL_LOGIN, $args);
            return false;
        }

        // If new SocialAccount was created $user is returned containing it
        if ($user->get('social_accounts')) {
            $this->dispatchEvent(UsersAuthComponent::EVENT_AFTER_REGISTER, compact('user'));
        }

        if (!empty($user->username)) {
            $user = $this->_findUser($user->username);
        }

        return $user;
    }

    /**
     * Find a user record using the username and password provided.
     *
     * Input passwords will be hashed even when a user doesn't exist. This
     * helps mitigate timing attacks that are attempting to find valid usernames.
     *
     * @param string $username The username/identifier.
     * @param string|null $password The password, if not provided password checking is skipped
     *   and result of find is returned.
     * @return bool|array Either false on failure, or an array of user data.
     */
    protected function _findUser($username, $password = null)
    {
        $result = $this->_query($username)->first();

        if (empty($result)) {
            $hasher = $this->passwordHasher();
            $hasher->hash((string)$password);

            return false;
        }

        $passwordField = $this->_config['fields']['password'];

        $key = array_search($passwordField, $hidden);
        unset($hidden[$key]);
        $result->setHidden($hidden);

        return $result->toArray();
    }
    /**
     * Get the provider name based on the request or on the provider set.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return mixed Either false or an array of user information
     */
    protected function _getProviderName($request = null)
    {
        $provider = false;
        if (!empty($request->getParam('provider'))) {
            $provider = ucfirst($request->getParam('provider'));
        } elseif (!is_null($this->_provider)) {
            $provider = SocialUtils::getProvider($this->_provider);
        }

        return $provider;
    }

    /**
     * Get the provider name based on the request or on the provider set.
     *
     * @param string $provider Provider name.
     * @param array $data User data
     * @throws MissingProviderException
     * @return mixed Either false or an array of user information
     */
    protected function _mapUser($provider, $data)
    {
        if (empty($provider)) {
            throw new MissingProviderException(__d('CakeDC/Users', "Provider cannot be empty"));
        }
        $providerMapperClass = $this->getConfig('providers.' . strtolower($provider) . '.options.mapper') ?: "\\CakeDC\\Users\\Auth\\Social\\Mapper\\$provider";
        $providerMapper = new $providerMapperClass($data);
        $user = $providerMapper();
        $user['provider'] = $provider;

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

    /**
     * Authenticates with OAuth2 provider by getting an access token and
     * retrieving the authorized user's profile data.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return array|bool
     */
    protected function _authenticate(ServerRequestInterface $request)
    {
        if (!$this->_validate($request)) {
            return false;
        }

        $provider = $this->provider($request);
        $code = $request->getQuery('code');

        try {
            $token = $provider->getAccessToken('authorization_code', compact('code'));

            return compact('token') + $provider->getResourceOwner($token)->toArray();
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
     * Returns the `$request`-ed provider.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return \League\Oauth2\Client\Provider\GenericProvider|false
     */
    public function provider(ServerRequestInterface $request)
    {
        if (!$alias = $request->getParam('provider')) {
            return false;
        }

        if (empty($this->_provider)) {
            $this->_provider = $this->_getProvider($alias);
        }

        return $this->_provider;
    }

    /**
     * Instantiates provider object.
     *
     * @param string $alias of the provider.
     * @return bool|\League\Oauth2\Client\Provider\GenericProvider
     */
    protected function _getProvider($alias)
    {
        if (!$config = $this->getConfig('providers.' . $alias)) {
            return false;
        }

        $this->setConfig($config);

        if (is_object($config) && $config instanceof AbstractProvider) {
            return $config;
        }

        $class = $config['className'];

        return new $class($config['options'], $config['collaborators']);
    }



}
