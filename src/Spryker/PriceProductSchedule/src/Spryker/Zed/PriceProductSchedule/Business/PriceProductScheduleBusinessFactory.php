<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductSchedule\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\PriceProductSchedule\Business\Currency\CurrencyFinder;
use Spryker\Zed\PriceProductSchedule\Business\Currency\CurrencyFinderInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProduct\PriceProductFallbackFinder;
use Spryker\Zed\PriceProductSchedule\Business\PriceProduct\PriceProductFallbackFinderInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProduct\PriceProductUpdater;
use Spryker\Zed\PriceProductSchedule\Business\PriceProduct\PriceProductUpdaterInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferMoneyValueDataExpander;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferPriceDimensionDataExpander;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferPriceTypeDataExpander;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferProductDataExpander;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleApplier;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleApplierInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleCleaner;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleCleanerInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleDisabler;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleDisablerInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleImportMapper;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleImportMapperInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleMapper;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleMapperInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleValidator;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleValidatorInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleWriter;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleWriterInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListCreator;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListCreatorInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListFinder;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListFinderInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListImporter;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListImporterInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListUpdater;
use Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListUpdaterInterface;
use Spryker\Zed\PriceProductSchedule\Business\PriceType\PriceTypeFinder;
use Spryker\Zed\PriceProductSchedule\Business\PriceType\PriceTypeFinderInterface;
use Spryker\Zed\PriceProductSchedule\Business\Product\ProductFinder;
use Spryker\Zed\PriceProductSchedule\Business\Product\ProductFinderInterface;
use Spryker\Zed\PriceProductSchedule\Business\Store\StoreFinder;
use Spryker\Zed\PriceProductSchedule\Business\Store\StoreFinderInterface;
use Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToCurrencyFacadeInterface;
use Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToPriceProductFacadeInterface;
use Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToProductFacadeInterface;
use Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToStoreFacadeInterface;
use Spryker\Zed\PriceProductSchedule\PriceProductScheduleDependencyProvider;

/**
 * @method \Spryker\Zed\PriceProductSchedule\PriceProductScheduleConfig getConfig()
 * @method \Spryker\Zed\PriceProductSchedule\Persistence\PriceProductScheduleEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\PriceProductSchedule\Persistence\PriceProductScheduleRepositoryInterface getRepository()
 */
class PriceProductScheduleBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleCleanerInterface
     */
    public function createPriceProductScheduleCleaner(): PriceProductScheduleCleanerInterface
    {
        return new PriceProductScheduleCleaner(
            $this->getEntityManager()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleApplierInterface
     */
    public function createPriceProductScheduleApplier(): PriceProductScheduleApplierInterface
    {
        return new PriceProductScheduleApplier(
            $this->createPriceProductScheduleWriter(),
            $this->createPriceProductScheduleDisabler(),
            $this->getRepository(),
            $this->getPriceProductFacade(),
            $this->getStoreFacade()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleWriterInterface
     */
    public function createPriceProductScheduleWriter(): PriceProductScheduleWriterInterface
    {
        return new PriceProductScheduleWriter(
            $this->getEntityManager()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleDisablerInterface
     */
    public function createPriceProductScheduleDisabler(): PriceProductScheduleDisablerInterface
    {
        return new PriceProductScheduleDisabler(
            $this->createPriceProductScheduleWriter(),
            $this->getRepository(),
            $this->createPriceProductFallbackFinder(),
            $this->createProductPriceUpdater(),
            $this->getPriceProductFacade()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProduct\PriceProductFallbackFinderInterface
     */
    public function createPriceProductFallbackFinder(): PriceProductFallbackFinderInterface
    {
        return new PriceProductFallbackFinder(
            $this->getConfig(),
            $this->getPriceProductFacade()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProduct\PriceProductUpdaterInterface
     */
    public function createProductPriceUpdater(): PriceProductUpdaterInterface
    {
        return new PriceProductUpdater(
            $this->getEntityManager(),
            $this->getPriceProductFacade()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListCreatorInterface
     */
    public function createPriceProductScheduleListCreator(): PriceProductScheduleListCreatorInterface
    {
        return new PriceProductScheduleListCreator(
            $this->getEntityManager()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListUpdaterInterface
     */
    public function createPriceProductScheduleListUpdater(): PriceProductScheduleListUpdaterInterface
    {
        return new PriceProductScheduleListUpdater(
            $this->getEntityManager()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListImporterInterface
     */
    public function createPriceProductScheduleListImporter(): PriceProductScheduleListImporterInterface
    {
        return new PriceProductScheduleListImporter(
            $this->getEntityManager(),
            $this->createPriceProductScheduleValidator(),
            $this->createPriceProductScheduleMapper(),
            $this->getPriceProductTransferDataExpanderList()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleValidatorInterface
     */
    public function createPriceProductScheduleValidator(): PriceProductScheduleValidatorInterface
    {
        return new PriceProductScheduleValidator(
            $this->getRepository(),
            $this->createPriceProductScheduleImportMapper(),
            $this->createStoreFinder(),
            $this->createCurrencyFinder(),
            $this->createPriceTypeFinder(),
            $this->createProductFinder()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleMapperInterface
     */
    public function createPriceProductScheduleMapper(): PriceProductScheduleMapperInterface
    {
        return new PriceProductScheduleMapper();
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\PriceProductScheduleImportMapperInterface
     */
    public function createPriceProductScheduleImportMapper(): PriceProductScheduleImportMapperInterface
    {
        return new PriceProductScheduleImportMapper();
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferDataExpanderInterface[]
     */
    public function getPriceProductTransferDataExpanderList(): array
    {
        return [
            $this->createPriceProductTransferPriceDimensionDataExpander(),
            $this->createPriceProductTransferMoneyValueDataExpander(),
            $this->createPriceProductTransferPriceTypeDataExpander(),
            $this->createPriceProductTransferProductDataExpander(),
        ];
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferPriceDimensionDataExpander
     */
    public function createPriceProductTransferPriceDimensionDataExpander(): PriceProductTransferPriceDimensionDataExpander
    {
        return new PriceProductTransferPriceDimensionDataExpander($this->getConfig());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferMoneyValueDataExpander
     */
    public function createPriceProductTransferMoneyValueDataExpander(): PriceProductTransferMoneyValueDataExpander
    {
        return new PriceProductTransferMoneyValueDataExpander(
            $this->createStoreFinder(),
            $this->createCurrencyFinder()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\Currency\CurrencyFinderInterface
     */
    public function createCurrencyFinder(): CurrencyFinderInterface
    {
        return new CurrencyFinder($this->getCurrencyFacade());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\Store\StoreFinderInterface
     */
    public function createStoreFinder(): StoreFinderInterface
    {
        return new StoreFinder($this->getStoreFacade());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceType\PriceTypeFinderInterface
     */
    public function createPriceTypeFinder(): PriceTypeFinderInterface
    {
        return new PriceTypeFinder($this->getPriceProductFacade());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\Product\ProductFinderInterface
     */
    public function createProductFinder(): ProductFinderInterface
    {
        return new ProductFinder($this->getProductFacade());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferPriceTypeDataExpander
     */
    public function createPriceProductTransferPriceTypeDataExpander(): PriceProductTransferPriceTypeDataExpander
    {
        return new PriceProductTransferPriceTypeDataExpander($this->createPriceTypeFinder());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\DataExpander\PriceProductTransferProductDataExpander
     */
    public function createPriceProductTransferProductDataExpander(): PriceProductTransferProductDataExpander
    {
        return new PriceProductTransferProductDataExpander($this->createProductFinder());
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleList\PriceProductScheduleListFinderInterface
     */
    public function createPriceProductScheduleListFinder(): PriceProductScheduleListFinderInterface
    {
        return new PriceProductScheduleListFinder(
            $this->getRepository()
        );
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToPriceProductFacadeInterface
     */
    public function getPriceProductFacade(): PriceProductScheduleToPriceProductFacadeInterface
    {
        return $this->getProvidedDependency(PriceProductScheduleDependencyProvider::FACADE_PRICE_PRODUCT);
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToStoreFacadeInterface
     */
    public function getStoreFacade(): PriceProductScheduleToStoreFacadeInterface
    {
        return $this->getProvidedDependency(PriceProductScheduleDependencyProvider::FACADE_STORE);
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToProductFacadeInterface
     */
    public function getProductFacade(): PriceProductScheduleToProductFacadeInterface
    {
        return $this->getProvidedDependency(PriceProductScheduleDependencyProvider::FACADE_PRODUCT);
    }

    /**
     * @return \Spryker\Zed\PriceProductSchedule\Dependency\Facade\PriceProductScheduleToCurrencyFacadeInterface
     */
    public function getCurrencyFacade(): PriceProductScheduleToCurrencyFacadeInterface
    {
        return $this->getProvidedDependency(PriceProductScheduleDependencyProvider::FACADE_CURRENCY);
    }
}
