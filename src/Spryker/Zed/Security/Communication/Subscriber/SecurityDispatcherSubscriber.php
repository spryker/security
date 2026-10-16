<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Security\Communication\Subscriber;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Zed\Security\Communication\Configurator\SecurityConfiguratorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Csrf\TokenStorage\ClearableTokenStorageInterface;
use Symfony\Component\Security\Csrf\TokenStorage\SessionTokenStorage;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\EventListener\SessionStrategyListener;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategy;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class SecurityDispatcherSubscriber implements SecurityDispatcherSubscriberInterface
{
    /**
     * @var string
     */
    protected const SERVICE_SECURITY_FIREWALL = 'security.firewall';

    /**
     * @uses \Spryker\Zed\EventDispatcher\Communication\Plugin\Application\EventDispatcherApplicationPlugin::SERVICE_DISPATCHER
     *
     * @var string
     */
    protected const SERVICE_DISPATCHER = 'dispatcher';

    /**
     * @uses \Spryker\Zed\Form\Communication\Plugin\Application\FormApplicationPlugin::SERVICE_SESSION
     */
    protected const string SERVICE_SESSION = 'session';

    protected const int LOGIN_SUCCESS_EVENT_PRIORITY = 128;

    /**
     * @var \Spryker\Zed\Security\Communication\Configurator\SecurityConfiguratorInterface
     */
    protected SecurityConfiguratorInterface $securityConfigurator;

    public function __construct(SecurityConfiguratorInterface $securityConfigurator)
    {
        $this->securityConfigurator = $securityConfigurator;
    }

    public function addSubscriber(ContainerInterface $container): void
    {
        /** @var \Symfony\Component\EventDispatcher\EventDispatcherInterface $dispatcher */
        $dispatcher = $container->get(static::SERVICE_DISPATCHER);
        $dispatcher->addSubscriber($container->get(static::SERVICE_SECURITY_FIREWALL));

        $sessionAuthenticationStrategy = $this->createSessionAuthenticationStrategy($container);
        $dispatcher->addListener(
            LoginSuccessEvent::class,
            [new SessionStrategyListener($sessionAuthenticationStrategy), 'onSuccessfulLogin'],
            static::LOGIN_SUCCESS_EVENT_PRIORITY,
        );
        $dispatcher->addSubscriber(new SwitchUserSessionStrategyListener($sessionAuthenticationStrategy));

        $eventSubscribers = $this->securityConfigurator->getSecurityConfiguration($container)->getEventSubscribers();

        foreach ($eventSubscribers as $eventSubscriber) {
            $dispatcher->addSubscriber(call_user_func($eventSubscriber, $container));
        }
    }

    protected function createSessionAuthenticationStrategy(ContainerInterface $container): SessionAuthenticationStrategyInterface
    {
        return new SessionAuthenticationStrategy(
            SessionAuthenticationStrategy::MIGRATE,
            $this->findCsrfTokenStorage($container),
        );
    }

    protected function findCsrfTokenStorage(ContainerInterface $container): ?ClearableTokenStorageInterface
    {
        if (!$container->has(static::SERVICE_SESSION)) {
            return null;
        }

        return new SessionTokenStorage($this->createRequestStack($container->get(static::SERVICE_SESSION)));
    }

    protected function createRequestStack(SessionInterface $session): RequestStack
    {
        $request = new Request();
        $request->setSession($session);

        $requestStack = new RequestStack();
        $requestStack->push($request);

        return $requestStack;
    }
}
