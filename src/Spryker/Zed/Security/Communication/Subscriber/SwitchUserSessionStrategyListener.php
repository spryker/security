<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Security\Communication\Subscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class SwitchUserSessionStrategyListener implements EventSubscriberInterface
{
    protected const int SWITCH_USER_EVENT_PRIORITY = 128;

    public function __construct(protected SessionAuthenticationStrategyInterface $sessionAuthenticationStrategy)
    {
    }

    public function onSwitchUser(SwitchUserEvent $switchUserEvent): void
    {
        $request = $switchUserEvent->getRequest();
        $token = $switchUserEvent->getToken();

        if ($token === null || !$request->hasPreviousSession()) {
            return;
        }

        $this->sessionAuthenticationStrategy->onAuthentication($request, $token);
    }

    /**
     * @return array<string, array<int, int|string>>
     */
    public static function getSubscribedEvents(): array
    {
        return [SecurityEvents::SWITCH_USER => ['onSwitchUser', static::SWITCH_USER_EVENT_PRIORITY]];
    }
}
