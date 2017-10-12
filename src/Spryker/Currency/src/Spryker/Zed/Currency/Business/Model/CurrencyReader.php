<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Currency\Business\Model;

use ArrayObject;
use Generated\Shared\Transfer\StoreTransfer;
use Generated\Shared\Transfer\StoreWithCurrencyTransfer;
use Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException;
use Spryker\Zed\Currency\Dependency\Facade\CurrencyToStoreInterface;
use Spryker\Zed\Currency\Persistence\CurrencyQueryContainerInterface;

class CurrencyReader implements CurrencyReaderInterface
{
    /**
     * @var \Spryker\Zed\Currency\Persistence\CurrencyQueryContainerInterface
     */
    protected $currencyQueryContainer;

    /**
     * @var \Spryker\Zed\Currency\Business\Model\CurrencyMapperInterface
     */
    protected $currencyMapper;

    /**
     * @var \Spryker\Zed\Currency\Dependency\Facade\CurrencyToStoreInterface
     */
    protected $storeFacade;

    /**
     * @var \Generated\Shared\Transfer\CurrencyTransfer[]
     */
    protected static $currencyCache = [];

    /**
     * @param \Spryker\Zed\Currency\Persistence\CurrencyQueryContainerInterface $currencyQueryContainer
     * @param \Spryker\Zed\Currency\Business\Model\CurrencyMapperInterface $currencyMapper
     * @param \Spryker\Zed\Currency\Dependency\Facade\CurrencyToStoreInterface $storeFacade
     */
    public function __construct(
        CurrencyQueryContainerInterface $currencyQueryContainer,
        CurrencyMapperInterface $currencyMapper,
        CurrencyToStoreInterface $storeFacade
    ) {

        $this->currencyQueryContainer = $currencyQueryContainer;
        $this->currencyMapper = $currencyMapper;
        $this->storeFacade = $storeFacade;
    }

    /**
     * @param int $idCurrency
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getByIdCurrency($idCurrency)
    {
        $currencyEntity = $this->currencyQueryContainer
            ->queryCurrencyByIdCurrency($idCurrency)
            ->findOne();

        if (!$currencyEntity) {
            throw new CurrencyNotFoundException(
                sprintf('Currency with id "%d" not found.', $idCurrency)
            );
        }

        return $this->currencyMapper->mapEntityToTransfer($currencyEntity);
    }

    /**
     * @return \Generated\Shared\Transfer\StoreWithCurrencyTransfer
     */
    public function getCurrentStoreWithCurrencies()
    {
        $storeTransfer = $this->storeFacade->getCurrentStore();

        return $this->mapStoreCurrency($storeTransfer);
    }

    /**
     * @return \Generated\Shared\Transfer\StoreWithCurrencyTransfer[]
     */
    public function getAllStoresWithCurrencies()
    {
        $currenciesPerStore = [];
        foreach ($this->storeFacade->getAllStores() as $storeTransfer) {
            $currenciesPerStore[] = $this->mapStoreCurrency($storeTransfer);
        }

        return $currenciesPerStore;
    }

    /**
     * @param string $isoCode
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getByIsoCode($isoCode)
    {
        if (isset(static::$currencyCache[$isoCode])) {
            return static::$currencyCache[$isoCode];
        }

        $currencyEntity = $this->currencyQueryContainer
            ->queryCurrencyByIsoCode($isoCode)
            ->findOne();

        if (!$currencyEntity) {
            throw new CurrencyNotFoundException(
                sprintf('Currency with iso code "%s" not found.', $isoCode)
            );
        }

        $currencyTransfer = $this->currencyMapper->mapEntityToTransfer($currencyEntity);

        static::$currencyCache[$isoCode] = $currencyTransfer;

        return $currencyTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return array
     */
    protected function getCurrenciesByIsoCodes(StoreTransfer $storeTransfer)
    {
        $currencyCollection = $this->currencyQueryContainer
            ->queryCurrenciesByIsoCodes($storeTransfer->getAvailableCurrencyIsoCodes())
            ->find();

        if (count($currencyCollection) === 0) {
            throw new CurrencyNotFoundException(
                sprintf(
                    "There is no currency configured for current store, 
                    make sure you have currency iso codes provided in 'currencyIsoCodes' array in current stores.php config."
                )
            );
        }

        $currencies = [];
        foreach ($currencyCollection as $currencyEntity) {
            $currencies[] = $this->currencyMapper->mapEntityToTransfer($currencyEntity);
        }
        return $currencies;
    }

    /**
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return \Generated\Shared\Transfer\StoreWithCurrencyTransfer
     */
    protected function mapStoreCurrency(StoreTransfer $storeTransfer)
    {
        $storeWithCurrencyTransfer = new StoreWithCurrencyTransfer();
        $storeWithCurrencyTransfer->setStore($storeTransfer);
        $storeWithCurrencyTransfer->setCurrencies(
            new ArrayObject($this->getCurrenciesByIsoCodes($storeTransfer))
        );
        return $storeWithCurrencyTransfer;
    }
}
