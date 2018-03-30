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

use CakeDC\Users\Controller\Component\UsersAuthComponent;
use CakeDC\Users\Exception\AccountNotActiveException;
use CakeDC\Users\Exception\MissingEmailException;
use CakeDC\Users\Exception\UserNotActiveException;
use CakeDC\Users\Middleware\SocialAuthMiddleware;
use CakeDC\Users\Model\Table\SocialAccountsTable;
use Cake\Core\Configure;
use Cake\Core\Exception\Exception;
use Cake\Event\Event;
use Cake\Network\Exception\NotFoundException;
use Cake\Utility\Hash;
use League\OAuth1\Client\Server\Twitter;

/**
 * Covers the login, logout and social login
 *
 * @property \Cake\Controller\Component\AuthComponent $Auth
 * @property \Cake\Http\ServerRequest $request
 */
trait LoginTrait
{
    use CustomUsersTableTrait;

    /**
     * @param int $error auth error
     * @param mixed $data data
     * @param bool|false $flash flash
     * @return mixed
     */
    public function failedSocialLogin($error, $data, $flash = false)
    {
        $msg = __d('CakeDC/Users', 'Issues trying to log in with your social account');

        switch ($error) {
            case SocialAuthMiddleware::AUTH_ERROR_MISSING_EMAIL:
                if ($flash) {
                    $this->Flash->success(__d('CakeDC/Users', 'Please enter your email'), ['clear' => true]);
                }
                $this->request->getSession()->write(Configure::read('Users.Key.Session.social'), $data);

                return $this->redirect([
                    'plugin' => 'CakeDC/Users',
                    'controller' => 'Users',
                    'action' => 'socialEmail'
                ]);
            case SocialAuthMiddleware::AUTH_ERROR_USER_NOT_ACTIVE:
                $msg = __d(
                    'CakeDC/Users',
                    'Your user has not been validated yet. Please check your inbox for instructions'
                );
                break;
            case SocialAuthMiddleware::AUTH_ERROR_ACCOUNT_NOT_ACTIVE:
                $msg = __d(
                    'CakeDC/Users',
                    'Your social account has not been validated yet. Please check your inbox for instructions'
                );
                break;

        }

        if ($flash) {
            $this->request->getSession()->delete(Configure::read('Users.Key.Session.social'));
            $this->Flash->success($msg, ['clear' => true]);
        }

        return $this->redirect(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login']);
    }

    /**
     * Social login
     *
     * @throws NotFoundException
     * @return mixed
     */
    public function socialLogin()
    {
        $status = $this->request->getAttribute('socialAuthStatus');
        if ($status === SocialAuthMiddleware::AUTH_SUCCESS) {
            $user = $this->request->getAttribute('identity')->getOriginalData();

            return $this->_afterIdentifyUser($user, true);
        }
        $socialProvider = $this->request->getParam('provider');

        if (empty($socialProvider)) {
            throw new NotFoundException();
        }

        $data = $this->request->getAttribute('socialRawData');

        return $this->failedSocialLogin($status, $data);
    }

    /**
     * Login user
     *
     * @return mixed
     */
    public function login()
    {
        $result = $this->request->getAttribute('authentication')->getResult();

        if ($result->isValid()) {
            return $this->redirect($this->Authentication->getConfig('loginRedirect'));
        }

        if ($this->request->is('post')) {
            $message = __d('CakeDC/Users', 'Username or password is incorrect');
            $this->Flash->error($message, 'default', [], 'auth');
        }
    }

    /**
     * Verify for Google Authenticator
     * If Google Authenticator's enabled we need to verify
     * authenticated user. To avoid accidental access to
     * other URL's we store auth'ed used into temporary session
     * to perform code verification.
     *
     * @return mixed
     */
    public function verify()
    {
        if (!Configure::read('Users.GoogleAuthenticator.login')) {
            $message = __d('CakeDC/Users', 'Please enable Google Authenticator first.');
            $this->Flash->error($message, 'default', [], 'auth');

            return $this->redirect(Configure::read('Auth.loginAction'));
        }

        // storing user's session in the temporary one
        // until the GA verification is checked
        $temporarySession = $this->Auth->user();
        $this->request->getSession()->delete('Auth.User');

        if (!empty($temporarySession)) {
            $this->request->getSession()->write('temporarySession', $temporarySession);
        }

        if (array_key_exists('secret', $temporarySession)) {
            $secret = $temporarySession['secret'];
        }

        $secretVerified = Hash::get((array)$temporarySession, 'secret_verified');

        // showing QR-code until shared secret is verified
        if (!$secretVerified) {
            if (empty($secret)) {
                $secret = $this->GoogleAuthenticator->createSecret();

                // catching sql exception in case of any sql inconsistencies
                try {
                    $query = $this->getUsersTable()->query();
                    $query->update()
                        ->set(['secret' => $secret])
                        ->where(['id' => $temporarySession['id']]);
                    $query->execute();
                } catch (\Exception $e) {
                    $this->request->getSession()->destroy();
                    $message = $e->getMessage();
                    $this->Flash->error($message, 'default', [], 'auth');

                    return $this->redirect(Configure::read('Auth.loginAction'));
                }
            }
            $secretDataUri = $this->GoogleAuthenticator->getQRCodeImageAsDataUri(
                Hash::get((array)$temporarySession, 'email'),
                $secret
            );
            $this->set(compact('secretDataUri'));
        }

        if ($this->request->is('post')) {
            $codeVerified = false;
            $verificationCode = $this->request->getData('code');
            $user = $this->request->getSession()->read('temporarySession');
            $entity = $this->getUsersTable()->get($user['id']);

            if (!empty($entity['secret'])) {
                $codeVerified = $this->GoogleAuthenticator->verifyCode($entity['secret'], $verificationCode);
            }

            if ($codeVerified) {
                unset($user['secret']);

                if (!$user['secret_verified']) {
                    $this->getUsersTable()->query()->update()
                        ->set(['secret_verified' => true])
                        ->where(['id' => $user['id']])
                        ->execute();
                }

                $this->request->getSession()->delete('temporarySession');
                $this->request->getSession()->write('Auth.User', $user);
                $url = $this->Auth->redirectUrl();

                return $this->redirect($url);
            } else {
                $this->request->getSession()->destroy();
                $message = __d('CakeDC/Users', 'Verification code is invalid. Try again');
                $this->Flash->error($message, 'default', [], 'auth');

                return $this->redirect(Configure::read('Auth.loginAction'));
            }
        }
    }

    /**
     * Check reCaptcha if enabled for login
     *
     * @return bool
     */
    protected function _checkReCaptcha()
    {
        if (!Configure::read('Users.reCaptcha.login')) {
            return true;
        }

        return $this->validateReCaptcha(
            $this->request->getData('g-recaptcha-response'),
            $this->request->clientIp()
        );
    }

    /**
     * Update remember me and determine redirect url after user identified
     * @param array $user user data after identified
     * @param bool $socialLogin is social login
     * @param bool $googleAuthenticatorLogin googleAuthenticatorLogin
     * @return array
     */
    protected function _afterIdentifyUser($user, $socialLogin = false, $googleAuthenticatorLogin = false)
    {
        if (!empty($user)) {

            if ($googleAuthenticatorLogin) {
                $url = Configure::read('GoogleAuthenticator.verifyAction');

                return $this->redirect($url);
            }

            $event = $this->dispatchEvent(UsersAuthComponent::EVENT_AFTER_LOGIN, ['user' => $user]);
            if (is_array($event->result)) {
                return $this->redirect($event->result);
            }

            $url = $this->Auth->redirectUrl();

            return $this->redirect($url);
        } else {
            if (!$socialLogin) {
                $message = __d('CakeDC/Users', 'Username or password is incorrect');
                $this->Flash->error($message, 'default', [], 'auth');
            }

            return $this->redirect(Configure::read('Auth.loginAction'));
        }
    }

    /**
     * Logout
     *
     * @return mixed
     */
    public function logout()
    {
        $user = $this->request->getAttribute('identity') ?? [];

        $eventBefore = $this->dispatchEvent(UsersAuthComponent::EVENT_BEFORE_LOGOUT, ['user' => $user]);
        if (is_array($eventBefore->result)) {
            return $this->redirect($eventBefore->result);
        }

        $this->request->getSession()->destroy();
        $this->Flash->success(__d('CakeDC/Users', 'You\'ve successfully logged out'));

        $eventAfter = $this->dispatchEvent(UsersAuthComponent::EVENT_AFTER_LOGOUT, ['user' => $user]);
        if (is_array($eventAfter->result)) {
            return $this->redirect($eventAfter->result);
        }

        return $this->redirect($this->Authentication->logout());
    }

    /**
     * Check if we are doing a social login
     *
     * @return bool true if social login is enabled and we are processing the social login
     * data in the request
     */
    protected function _isSocialLogin()
    {
        return Configure::read('Users.Social.login') &&
            $this->request->getSession()->check(Configure::read('Users.Key.Session.social'));
    }

    /**
     * Check if we doing Google Authenticator Two Factor auth
     * @return bool true if Google Authenticator is enabled
     */
    protected function _isGoogleAuthenticator()
    {
        return Configure::read('Users.GoogleAuthenticator.login');
    }
}
