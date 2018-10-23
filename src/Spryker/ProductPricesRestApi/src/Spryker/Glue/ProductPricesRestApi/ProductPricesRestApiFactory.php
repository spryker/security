<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductPricesRestApi;

use Spryker\Glue\Kernel\AbstractFactory;
use Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToCurrencyClientInterface;
use Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToPriceClientInterface;
use Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToPriceProductClientInterface;
use Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToPriceProductStorageClientInterface;
use Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToProductStorageClientInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\AbstractProductPrices\AbstractProductPricesReader;
use Spryker\Glue\ProductPricesRestApi\Processor\AbstractProductPrices\AbstractProductPricesReaderInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\ConcreteProductPrices\ConcreteProductPricesReader;
use Spryker\Glue\ProductPricesRestApi\Processor\ConcreteProductPrices\ConcreteProductPricesReaderInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\Currency\CurrencySetter;
use Spryker\Glue\ProductPricesRestApi\Processor\Currency\CurrencySetterInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\Currency\CurrencyValidator;
use Spryker\Glue\ProductPricesRestApi\Processor\Currency\CurrencyValidatorInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\Mapper\ProductPricesMapper;
use Spryker\Glue\ProductPricesRestApi\Processor\Mapper\ProductPricesMapperInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\PriceMode\PriceModeSetter;
use Spryker\Glue\ProductPricesRestApi\Processor\PriceMode\PriceModeSetterInterface;
use Spryker\Glue\ProductPricesRestApi\Processor\PriceMode\PriceModeValidator;
use Spryker\Glue\ProductPricesRestApi\Processor\PriceMode\PriceModeValidatorInterface;

class ProductPricesRestApiFactory extends AbstractFactory
{
    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\Mapper\ProductPricesMapperInterface
     */
    public function createProductPricesMapper(): ProductPricesMapperInterface
    {
        return new ProductPricesMapper(
            $this->getPriceClient(),
            $this->getCurrencyClient()
        );
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\AbstractProductPrices\AbstractProductPricesReaderInterface
     */
    public function createAbstractProductPricesReader(): AbstractProductPricesReaderInterface
    {
        return new AbstractProductPricesReader(
            $this->getProductStorageClient(),
            $this->getPriceProductStorageClient(),
            $this->getPriceProductClient(),
            $this->getResourceBuilder(),
            $this->createProductPricesMapper()
        );
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\ConcreteProductPrices\ConcreteProductPricesReaderInterface
     */
    public function createConcreteProductPricesReader(): ConcreteProductPricesReaderInterface
    {
        return new ConcreteProductPricesReader(
            $this->getProductStorageClient(),
            $this->getPriceProductStorageClient(),
            $this->getPriceProductClient(),
            $this->getResourceBuilder(),
            $this->createProductPricesMapper()
        );
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\Currency\CurrencyValidatorInterface
     */
    public function createCurrencyValidator(): CurrencyValidatorInterface
    {
        return new CurrencyValidator($this->getCurrencyClient());
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\PriceMode\PriceModeValidatorInterface
     */
    public function createPriceModeValidator(): PriceModeValidatorInterface
    {
        return new PriceModeValidator($this->getPriceClient());
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\Currency\CurrencySetterInterface
     */
    public function createCurrencySetter(): CurrencySetterInterface
    {
        return new CurrencySetter($this->getCurrencyClient());
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Processor\PriceMode\PriceModeSetterInterface
     */
    public function createPriceModeSetter(): PriceModeSetterInterface
    {
        return new PriceModeSetter($this->getPriceClient());
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToPriceProductStorageClientInterface
     */
    public function getPriceProductStorageClient(): ProductPricesRestApiToPriceProductStorageClientInterface
    {
        return $this->getProvidedDependency(ProductPricesRestApiDependencyProvider::CLIENT_PRICE_PRODUCT_STORAGE);
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToProductStorageClientInterface
     */
    public function getProductStorageClient(): ProductPricesRestApiToProductStorageClientInterface
    {
        return $this->getProvidedDependency(ProductPricesRestApiDependencyProvider::CLIENT_PRODUCT_STORAGE);
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToPriceProductClientInterface
     */
    public function getPriceProductClient(): ProductPricesRestApiToPriceProductClientInterface
    {
        return $this->getProvidedDependency(ProductPricesRestApiDependencyProvider::CLIENT_PRICE_PRODUCT);
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToPriceClientInterface
     */
    public function getPriceClient(): ProductPricesRestApiToPriceClientInterface
    {
        return $this->getProvidedDependency(ProductPricesRestApiDependencyProvider::CLIENT_PRICE);
    }

    /**
     * @return \Spryker\Glue\ProductPricesRestApi\Dependency\Client\ProductPricesRestApiToCurrencyClientInterface
     */
    public function getCurrencyClient(): ProductPricesRestApiToCurrencyClientInterface
    {
        return $this->getProvidedDependency(ProductPricesRestApiDependencyProvider::CLIENT_CURRENCY);
    }
}
