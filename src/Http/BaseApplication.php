<?php
namespace CakeDC\Users\Http;

use Authentication\AuthenticationServiceInterface;
use Authentication\Middleware\AuthenticationMiddleware;
use Cake\Core\Configure;
use Cake\Error\Middleware\ErrorHandlerMiddleware;
use Cake\Http\BaseApplication as CakeBaseApplication;
use Cake\Log\Log;
use Cake\Routing\Middleware\AssetMiddleware;
use Cake\Routing\Middleware\RoutingMiddleware;
use CakeDC\Users\Middleware\SocialAuthMiddleware;
use CakeDC\Users\Middleware\SocialEmailMiddleware;

/**
 * Application setup class.
 *
 * This defines the bootstrapping logic and middleware layers.
 */
class BaseApplication extends CakeBaseApplication
{
    /**
     * load authenticators and identifiers
     *
     * @param AuthenticationServiceInterface $service Base authentication service
     * @return AuthenticationServiceInterface
     */
    public function authentication(AuthenticationServiceInterface $service)
    {
        $authenticators = Configure::read('Auth.Authenticators');
        $identifiers = Configure::read('Auth.Identifiers');

        foreach($identifiers as $identifier => $options) {
            if (is_numeric($identifier)) {
                $identifier = $options;
                $options = [];
            }

            $service->loadIdentifier($identifier, $options);
        }

        foreach($authenticators as $authenticator => $options) {
            if (is_numeric($authenticator)) {
                $authenticator = $options;
                $options = [];
            }

            $service->loadAuthenticator($authenticator, $options);
        }

        return $service;
    }

    /**
     * Setup the middleware queue your application will use.
     *
     * @param \Cake\Http\MiddlewareQueue $middlewareQueue The middleware queue to setup.
     * @return \Cake\Http\MiddlewareQueue The updated middleware queue.
     */
    public function middleware($middlewareQueue)
    {
        $middlewareQueue
            // Catch any exceptions in the lower layers,
            // and make an error page/response
            ->add(ErrorHandlerMiddleware::class)

            // Handle plugin/theme assets like CakePHP normally does.
            ->add(AssetMiddleware::class)

            // Add routing middleware.
            ->add(new RoutingMiddleware($this));

        $authentication = new AuthenticationMiddleware($this);
        $middlewareQueue->add($authentication);

        return $middlewareQueue;
    }
}