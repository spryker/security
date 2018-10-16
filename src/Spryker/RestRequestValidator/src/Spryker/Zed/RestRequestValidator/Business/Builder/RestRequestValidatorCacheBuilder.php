<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\RestRequestValidator\Business\Builder;

use Spryker\Shared\Kernel\Store;
use Spryker\Zed\RestRequestValidator\Business\Collector\RestRequestValidatorCacheCollectorInterface;
use Spryker\Zed\RestRequestValidator\Business\Merger\RestRequestValidatorSchemaMergerInterface;
use Spryker\Zed\RestRequestValidator\Business\Saver\RestRequestValidatorCacheSaverInterface;

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
     * @var \Spryker\Shared\Kernel\Store
     */
    protected $store;

    /**
     * @param \Spryker\Zed\RestRequestValidator\Business\Collector\RestRequestValidatorCacheCollectorInterface $restRequestValidatorCacheCollector
     * @param \Spryker\Zed\RestRequestValidator\Business\Merger\RestRequestValidatorSchemaMergerInterface $restRequestValidatorSchemaMerger
     * @param \Spryker\Zed\RestRequestValidator\Business\Saver\RestRequestValidatorCacheSaverInterface $restRequestValidatorCacheSaver
     * @param \Spryker\Shared\Kernel\Store $store
     */
    public function __construct(
        RestRequestValidatorCacheCollectorInterface $restRequestValidatorCacheCollector,
        RestRequestValidatorSchemaMergerInterface $restRequestValidatorSchemaMerger,
        RestRequestValidatorCacheSaverInterface $restRequestValidatorCacheSaver,
        Store $store
    ) {
        $this->restRequestValidatorCacheCollector = $restRequestValidatorCacheCollector;
        $this->restRequestValidatorSchemaMerger = $restRequestValidatorSchemaMerger;
        $this->restRequestValidatorCacheSaver = $restRequestValidatorCacheSaver;
        $this->store = $store;
    }

    /**
     * @return void
     */
    public function build(): void
    {
        foreach ($this->store->getAllowedStores() as $storeName) {
            $config = $this->restRequestValidatorCacheCollector->collect($storeName);
            $config = $this->restRequestValidatorSchemaMerger->merge($config);
            $this->restRequestValidatorCacheSaver->save($config, $storeName);
        }
    }
}
