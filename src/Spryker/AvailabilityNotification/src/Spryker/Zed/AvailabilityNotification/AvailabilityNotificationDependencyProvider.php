<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\AvailabilityNotification;

use Spryker\Zed\AvailabilityNotification\Dependency\Facade\AvailabilityNotificationToGlossaryFacadeBridge;
use Spryker\Zed\AvailabilityNotification\Dependency\Facade\AvailabilityNotificationToLocaleFacadeBridge;
use Spryker\Zed\AvailabilityNotification\Dependency\Facade\AvailabilityNotificationToMailFacadeBridge;
use Spryker\Zed\AvailabilityNotification\Dependency\Facade\AvailabilityNotificationToStoreFacadeBridge;
use Spryker\Zed\AvailabilityNotification\Dependency\Service\AvailabilityNotificationToUtilValidateServiceBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class AvailabilityNotificationDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_MAIL = 'FACADE_MAIL';
    public const FACADE_GLOSSARY = 'FACADE_GLOSSARY';
    public const FACADE_LOCALE = 'FACADE_LOCALE';
    public const FACADE_STORE = 'FACADE_STORE';

    public const SERVICE_UTIL_VALIDATE = 'SERVICE_UTIL_VALIDATE';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container): Container
    {
        $container = $this->addMailFacade($container);
        $container = $this->addUtilValidateService($container);
        $container = $this->addStoreClient($container);
        $container = $this->addLocaleFacade($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container): Container
    {
        $container = $this->addMailFacade($container);
        $container = $this->addGlossaryFacade($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addUtilValidateService(Container $container): Container
    {
        $container[static::SERVICE_UTIL_VALIDATE] = function (Container $container) {
            return new AvailabilityNotificationToUtilValidateServiceBridge($container->getLocator()->utilValidate()->service());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addStoreClient(Container $container): Container
    {
        $container[static::FACADE_STORE] = function (Container $container) {
            return new AvailabilityNotificationToStoreFacadeBridge($container->getLocator()->store()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addLocaleFacade(Container $container): Container
    {
        $container[static::FACADE_LOCALE] = function (Container $container) {
            return new AvailabilityNotificationToLocaleFacadeBridge($container->getLocator()->locale()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMailFacade(Container $container): Container
    {
        $container[self::FACADE_MAIL] = function (Container $container) {
            return new AvailabilityNotificationToMailFacadeBridge($container->getLocator()->mail()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addGlossaryFacade(Container $container): Container
    {
        $container[self::FACADE_GLOSSARY] = function (Container $container) {
            return new AvailabilityNotificationToGlossaryFacadeBridge($container->getLocator()->glossary()->facade());
        };

        return $container;
    }
}
