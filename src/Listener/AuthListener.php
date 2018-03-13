<?php
namespace CakeDC\Users\Listener;

use Cake\Event\Event;
use Cake\Event\EventListenerInterface;

class AuthListener implements EventListenerInterface
{
    const EVENT_FAILED_SOCIAL_LOGIN = 'Users.SocialAuth.failedSocialLogin';

    const EVENT_AFTER_SOCIAL_REGISTER = 'Users.SocialAuth.afterRegister';

    /**
     * All implemented events are declared
     *
     * @return array
     */
    public function implementedEvents()
    {
        return [
            'Authentication.afterIdentify' => 'afterIdentify',
            'Authentication.logout' => 'afterLogout'
        ];
    }

    /**
     * execute when Authentication.afterIdentify is dispatched
     *
     * @param Event $event
     */
    public function afterIdentity(Event $event)
    {

    }

    /**
     * execute when Authentication.logout is dispatched
     *
     * @param Event $event
     */
    public function afterLogout(Event $event)
    {

    }


}