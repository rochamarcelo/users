<?php
/**
 * Copyright 2010 - 2017, Cake Development Corporation (https://www.cakedc.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2010 - 2017, Cake Development Corporation (https://www.cakedc.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

namespace CakeDC\Users\Controller\Traits;

use Cake\Core\Configure;
use Cake\Network\Exception\NotFoundException;
use League\OAuth2\Client\Provider\AbstractProvider;

/**
 * Ações para "linkar" contas sociais
 *
 */
trait LinkSocialTrait
{
    /**
     * Ação para inicial processo de link e autenticação social (facebook, google)
     *
     * @param string $alias of the provider.
     *
     * @throws \Cake\Network\Exception\NotFoundException Quando o provider informado não existe
     * @return  \Cake\Network\Response Redirects on successful
     */
    public function linkSocial($alias = null)
    {
        $provider = $this->_getSocialProvider($alias);

        $authUrl = $provider->getAuthorizationUrl();
        $this->request->session()->write('SocialLink.oauth2state', $provider->getState());

        return $this->redirect($authUrl);
    }

    /**
     * Ação para receber o retorno do provedor (facebook, google) referente ao
     *  processo de link e autenticação social
     *
     * @param string $alias of the provider.
     *
     * @throws \Cake\Network\Exception\NotFoundException Quando o provider informado não existe
     * @return  \Cake\Network\Response Redirects to profile if okay or error
     */
    public function callbackLinkSocial($alias = null)
    {
        $provider = $this->_getSocialProvider($alias);
        if (!$this->_validateCallbackSocialLink()) {
            $this->Flash->error('Não foi possivel associar conta, por favor tente novamente');

            return $this->redirect(['action' => 'profile']);
        }

        $code = $this->request->getQuery('code');

        try {
            $token = $provider->getAccessToken('authorization_code', compact('code'));

            $data = compact('token') + $provider->getResourceOwner($token)->toArray();
            $data = $this->_mapSocialUser($alias, $data);
            $user = $this->getUsersTable()->get($this->Auth->user('id'));

            $this->getUsersTable()->linkSocialAccount($user, $data);

            if ($user->errors()) {
                $error = $user->errors('social_accounts');
                $error = $error ? reset($error) : 'Não foi possivel associar conta, por favor tente novamente';
                $this->Flash->error(is_array($error) ? implode('. ', $error) : $error);
            } else {
                $this->Flash->success('Conta social associada ao cadastro.');
            }
        } catch (\Exception $e) {
            $message = sprintf(
                "Error getting an access token / retrieving the authorized user's profile data. Error message: %s %s",
                $e->getMessage(),
                $e
            );
            $this->log($message);

            $this->Flash->error('Não foi possivel associar conta, por favor tente novamente');
        }

        return $this->redirect(['action' => 'profile']);
    }

    /**
     * Get the provider name based on the request or on the provider set.
     *
     * @param string $alias of the provider.
     * @param array $data User data
     *
     * @throws MissingProviderException
     * @return array
     */
    protected function _mapSocialUser($alias, $data)
    {
        $alias = ucfirst($alias);
        $providerMapperClass = "\\CakeDC\\Users\\Auth\\Social\\Mapper\\$alias";
        $providerMapper = new $providerMapperClass($data);
        $user = $providerMapper();
        $user['provider'] = $alias;

        return $user;
    }

    /**
     * Instantiates provider object.
     *
     * @param string $alias of the provider.
     *
     * @throws \Cake\Network\Exception\NotFoundException Quando o provider informado não existe
     * @return \League\OAuth2\Client\Provider\AbstractProvider
     */
    protected function _getSocialProvider($alias) : AbstractProvider
    {
        $config = Configure::read('OAuth.providers.' . $alias);
        if (!$config) {
            throw new NotFoundException("Página não encontrada");
        }

        $optionsLink = Configure::read('SocialLink.providers.' . $alias . '.options.redirectUri');
        if (!$optionsLink) {
            throw new NotFoundException("Página não encontrada");
        }

        if (is_object($config) && $config instanceof AbstractProvider) {
            return $config;
        }

        $class = $config['className'];
        $config['options']['redirectUri'] = $optionsLink;

        return new $class($config['options'], []);
    }

    /**
     * Validates OAuth2 request.
     *
     * @return bool
     */
    protected function _validateCallbackSocialLink(): bool
    {
        $error = $this->request->getQuery('error');
        if (!empty($error)) {
            $this->log('Got error in _validateCallbackSocialLink: ' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8'));

            return false;
        }

        $queryParams = $this->request->getQueryParams();
        if (!array_key_exists('code', $queryParams)) {
            return false;
        }

        $sessionKey = 'SocialLink.oauth2state';
        $oauth2state = $this->request->session()->read($sessionKey);
        $this->request->session()->delete($sessionKey);
        $state = $this->request->getQuery('state');

        return $oauth2state === $state;
    }
}