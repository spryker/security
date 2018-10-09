<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\RestRequestValidator\Business\Builder;

use Spryker\Zed\RestRequestValidator\Business\Collector\RestRequestValidatorCacheCollectorInterface;
use Spryker\Zed\RestRequestValidator\Business\Merger\RestRequestValidatorSchemaMergerInterface;
use Spryker\Zed\RestRequestValidator\Business\Saver\RestRequestValidatorCacheSaverInterface;
use Spryker\Zed\RestRequestValidator\Dependency\Facade\RestRequestValidatorToStoreFacadeInterface;

class RestRequestValidatorCacheBuilder implements RestRequestValidatorCacheBuilderInterface
{
    /**
     * @var \Spryker\Zed\RestRequestValidator\Business\Collector\RestRequestValidatorCacheCollectorInterface
     */
    protected $restRequestValidatorCacheCollector;

    /**
     * @var \Spryker\Zed\RestRequestValidator\Business\Merger\RestRequestValidatorSchemaMergerInterface
     */
    protected $restRequestValidatorSchemaMerger;

    /**
     * @var \Spryker\Zed\RestRequestValidator\Business\Saver\RestRequestValidatorCacheSaverInterface
     */
    protected $restRequestValidatorCacheSaver;

    /**
     * @var \Spryker\Zed\RestRequestValidator\Dependency\Facade\RestRequestValidatorToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @param \Spryker\Zed\RestRequestValidator\Business\Collector\RestRequestValidatorCacheCollectorInterface $restRequestValidatorCacheCollector
     * @param \Spryker\Zed\RestRequestValidator\Business\Merger\RestRequestValidatorSchemaMergerInterface $restRequestValidatorSchemaMerger
     * @param \Spryker\Zed\RestRequestValidator\Business\Saver\RestRequestValidatorCacheSaverInterface $restRequestValidatorCacheSaver
     * @param \Spryker\Zed\RestRequestValidator\Dependency\Facade\RestRequestValidatorToStoreFacadeInterface $storeFacade
     */
    public function __construct(
        RestRequestValidatorCacheCollectorInterface $restRequestValidatorCacheCollector,
        RestRequestValidatorSchemaMergerInterface $restRequestValidatorSchemaMerger,
        RestRequestValidatorCacheSaverInterface $restRequestValidatorCacheSaver,
        RestRequestValidatorToStoreFacadeInterface $storeFacade
    ) {
        $this->restRequestValidatorCacheCollector = $restRequestValidatorCacheCollector;
        $this->restRequestValidatorSchemaMerger = $restRequestValidatorSchemaMerger;
        $this->restRequestValidatorCacheSaver = $restRequestValidatorCacheSaver;
        $this->storeFacade = $storeFacade;
    }

    /**
     * @return void
     */
    public function build(): void
    {
        foreach ($this->storeFacade->getAllStores() as $store) {
            $config = $this->restRequestValidatorCacheCollector->collect($store);
            $config = $this->restRequestValidatorSchemaMerger->merge($config);
            $this->restRequestValidatorCacheSaver->save($config, $store);
        }
    }
}
