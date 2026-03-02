<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Security\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\HttpUtils;

class RedirectLogoutListener implements EventSubscriberInterface
{
    /**
     * @var \Symfony\Component\Security\Http\HttpUtils
     */
    protected $httpUtils;

    /**
     * @var \Symfony\Component\HttpFoundation\RequestMatcherInterface
     */
    protected $requestMatcher;

    /**
     * @var string
     */
    protected $targetUrl;

    /**
     * @var int
     */
    public static $priority;

    public function __construct(
        HttpUtils $httpUtils,
        RequestMatcherInterface $requestMatcher,
        string $targetUrl,
        int $priority = 64
    ) {
        $this->httpUtils = $httpUtils;
        $this->requestMatcher = $requestMatcher;
        $this->targetUrl = $targetUrl;

        static::$priority = $priority;
    }

    public function onLogout(LogoutEvent $event): void
    {
        $request = $event->getRequest();

        if (!$this->requestMatcher->matches($request)) {
            return;
        }

        if ($event->getResponse() !== null) {
            return;
        }

        $event->setResponse($this->httpUtils->createRedirectResponse($request, $this->targetUrl));
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => ['onLogout', static::$priority],
        ];
    }
}
