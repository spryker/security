<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Store\Reader;

use Generated\Shared\Transfer\StoreTransfer;
use Spryker\Shared\Store\Dependency\Adapter\StoreToKernelStoreInterface;

class KernelStoreReader implements KernelStoreReaderInterface
{
    /**
     * @var \Spryker\Shared\Store\Dependency\Adapter\StoreToKernelStoreInterface
     */
    protected $store;

    /**
     * @param \Spryker\Shared\Store\Dependency\Adapter\StoreToKernelStoreInterface $store
     */
    public function __construct(StoreToKernelStoreInterface $store)
    {
        $this->store = $store;
    }

    /**
     * @param string $storeName
     *
     * @return \Generated\Shared\Transfer\StoreTransfer
     */
    public function getStoreByName($storeName)
    {
        $storeTransfer = (new StoreTransfer())
            ->setName($storeName)
            ->setSelectedCurrencyIsoCode($this->store->getCurrentStoreSelectedCurrencyIsoCode())
            ->setDefaultCurrencyIsoCode($this->store->getDefaultCurrencyFor($storeName))
            ->setAvailableCurrencyIsoCodes($this->store->getAvailableCurrenciesFor($storeName))
            ->setAvailableLocaleIsoCodes($this->store->getAvailableLocaleIsoCodesFor($storeName));

        return $storeTransfer;
    }

    /**
     * @return \Generated\Shared\Transfer\StoreTransfer
     */
    public function getCurrentStore()
    {
        return $this->getStoreByName($this->store->getCurrentStoreName());
    }
}
