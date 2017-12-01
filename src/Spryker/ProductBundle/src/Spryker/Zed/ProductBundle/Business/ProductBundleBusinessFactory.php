<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\PreCheck\ProductBundleCartAvailabilityCheck;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\PreCheck\ProductBundleCheckoutAvailabilityCheck;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\ProductBundleAvailabilityHandler;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Calculation\ProductBundlePriceCalculation;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartExpander;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartItemGroupKeyExpander;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartPostSaveUpdate;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleImageCartExpander;
use Spryker\Zed\ProductBundle\Business\ProductBundle\ProductBundleReader;
use Spryker\Zed\ProductBundle\Business\ProductBundle\ProductBundleWriter;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Sales\ProductBundleIdHydrator;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Sales\ProductBundleSalesOrderSaver;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Sales\ProductBundlesSalesOrderHydrate;
use Spryker\Zed\ProductBundle\Business\ProductBundle\Stock\ProductBundleStockWriter;
use Spryker\Zed\ProductBundle\ProductBundleDependencyProvider;

/**
 * @method \Spryker\Zed\ProductBundle\ProductBundleConfig getConfig()
 * @method \Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface getQueryContainer()
 */
class ProductBundleBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\ProductBundleWriterInterface
     */
    public function createProductBundleWriter()
    {
        return new ProductBundleWriter(
            $this->getProductFacade(),
            $this->getQueryContainer(),
            $this->createProductBundleStockWriter()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\ProductBundleReaderInterface
     */
    public function createProductBundleReader()
    {
        return new ProductBundleReader(
            $this->getQueryContainer(),
            $this->getAvailabilityQueryContainer()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartExpanderInterface
     */
    public function createProductBundleCartExpander()
    {
        return new ProductBundleCartExpander(
            $this->getQueryContainer(),
            $this->getPriceFacade(),
            $this->getProductFacade(),
            $this->getLocaleFacade()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartExpanderInterface
     */
    public function createProductBundleImageCartExpander()
    {
        return new ProductBundleImageCartExpander($this->getProductImageFacade(), $this->getLocaleFacade());
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartItemGroupKeyExpander
     */
    public function createProductBundleCartItemGroupKeyExpander()
    {
        return new ProductBundleCartItemGroupKeyExpander();
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Sales\ProductBundleSalesOrderSaverInterface
     */
    public function createProductBundleSalesOrderSaver()
    {
        return new ProductBundleSalesOrderSaver($this->getSalesQueryContainer(), $this->getQueryContainer());
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Calculation\ProductBundlePriceCalculationInterface
     */
    public function createProductBundlePriceCalculator()
    {
        return new ProductBundlePriceCalculation();
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Cart\ProductBundleCartPostSaveUpdateInterface
     */
    public function createProductBundlePostSaveUpdate()
    {
        return new ProductBundleCartPostSaveUpdate();
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\PreCheck\ProductBundleCartAvailabilityCheckInterface
     */
    public function createProductBundleCartPreCheck()
    {
        return new ProductBundleCartAvailabilityCheck(
            $this->getAvailabilityFacade(),
            $this->getQueryContainer(),
            $this->getAvailabilityQueryContainer()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\PreCheck\ProductBundleCheckoutAvailabilityCheckInterface
     */
    public function createProductBundleCheckoutPreCheck()
    {
        return new ProductBundleCheckoutAvailabilityCheck(
            $this->getAvailabilityFacade(),
            $this->getQueryContainer()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\ProductBundleAvailabilityHandlerInterface
     */
    public function createProductBundleAvailabilityHandler()
    {
        return new ProductBundleAvailabilityHandler(
            $this->getAvailabilityQueryContainer(),
            $this->getAvailabilityFacade(),
            $this->getQueryContainer()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Stock\ProductBundleStockWriterInterface
     */
    public function createProductBundleStockWriter()
    {
        return new ProductBundleStockWriter(
            $this->getQueryContainer(),
            $this->getStockQueryContainer(),
            $this->createProductBundleAvailabilityHandler()
        );
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Sales\ProductBundlesSalesOrderHydrateInterface
     */
    public function createProductBundlesSalesOrderHydrate()
    {
        return new ProductBundlesSalesOrderHydrate($this->getSalesQueryContainer(), $this->createProductBundlePriceCalculator());
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductInterface
     */
    protected function getProductFacade()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::FACADE_PRODUCT);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductImageInterface
     */
    protected function getProductImageFacade()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::FACADE_PRODUCT_IMAGE);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceInterface
     */
    protected function getPriceFacade()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::FACADE_PRICE);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToLocaleInterface
     */
    protected function getLocaleFacade()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::FACADE_LOCALE);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityInterface
     */
    protected function getAvailabilityFacade()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::FACADE_AVAILABILITY);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface
     */
    protected function getAvailabilityQueryContainer()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::QUERY_CONTAINER_AVAILABILITY);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToSalesQueryContainerInterface
     */
    protected function getSalesQueryContainer()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::QUERY_CONTAINER_SALES);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToStockQueryContainerInterface
     */
    protected function getStockQueryContainer()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::QUERY_CONTAINER_STOCK);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToProductQueryContainerInterface
     */
    protected function getProductQueryContainer()
    {
        return $this->getProvidedDependency(ProductBundleDependencyProvider::QUERY_CONTAINER_PRODUCT);
    }

    /**
     * @return \Spryker\Zed\ProductBundle\Business\ProductBundle\Sales\ProductBundleIdHydratorInterface
     */
    public function createProductBundlesIdHydrator()
    {
        return new ProductBundleIdHydrator(
            $this->getProductQueryContainer()
        );
    }
}
