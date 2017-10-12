<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Event;

use Spryker\Zed\Event\Dependency\Client\EventToQueueBridge;
use Spryker\Zed\Event\Dependency\EventCollection;
use Spryker\Zed\Event\Dependency\EventSubscriberCollection;
use Spryker\Zed\Event\Dependency\Service\EventToUtilEncoding;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class EventDependencyProvider extends AbstractBundleDependencyProvider
{
    const EVENT_LISTENERS = 'event_listeners';
    const EVENT_SUBSCRIBERS = 'event subscribers';

    const CLIENT_QUEUE = 'client queue';

    const SERVICE_UTIL_ENCODING = 'service util encoding';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container[static::EVENT_LISTENERS] = function (Container $container) {
            return $this->getEventListenerCollection();
        };

        $container[static::EVENT_SUBSCRIBERS] = function (Container $container) {
            return $this->getEventSubscriberCollection();
        };

        $container[static::CLIENT_QUEUE] = function (Container $container) {
            return new EventToQueueBridge($container->getLocator()->queue()->client());
        };

        $container[static::SERVICE_UTIL_ENCODING] = function (Container $container) {
            return new EventToUtilEncoding($container->getLocator()->utilEncoding()->service());
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\Event\Dependency\EventCollectionInterface
     */
    public function getEventListenerCollection()
    {
        return new EventCollection();
    }

    /**
     * @return \Spryker\Zed\Event\Dependency\EventSubscriberCollectionInterface
     */
    public function getEventSubscriberCollection()
    {
        return new EventSubscriberCollection();
    }
}
