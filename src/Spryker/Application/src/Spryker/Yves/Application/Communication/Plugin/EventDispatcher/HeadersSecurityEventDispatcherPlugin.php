<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Application\Communication\Plugin\EventDispatcher;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\EventDispatcher\EventDispatcherInterface;
use Spryker\Shared\EventDispatcherExtension\Dependency\Plugin\EventDispatcherPluginInterface;
use Spryker\Yves\Kernel\AbstractPlugin;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * @method \Spryker\Zed\Application\ApplicationConfig getConfig()
 */
class HeadersSecurityEventDispatcherPlugin extends AbstractPlugin implements EventDispatcherPluginInterface
{
    /**
     * {@inheritdoc}
     * - Provides security headers.
     *
     * @api
     *
     * @param \Spryker\Shared\EventDispatcher\EventDispatcherInterface $eventDispatcher
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Shared\EventDispatcher\EventDispatcherInterface
     */
    public function extend(EventDispatcherInterface $eventDispatcher, ContainerInterface $container): EventDispatcherInterface
    {
        $securityHeaders = $this->getConfig()->getSecurityHeaders();

        $eventDispatcher->addListener(
            KernelEvents::RESPONSE,
            function (FilterResponseEvent $event) use ($securityHeaders) {
                foreach ($securityHeaders as $securityHeaderName => $securityHeaderValue) {
                    if ($securityHeaderValue) {
                        $event->getResponse()->headers->set($securityHeaderName, $securityHeaderValue);
                    }
                }
            }
        );

        return $eventDispatcher;
    }
}
