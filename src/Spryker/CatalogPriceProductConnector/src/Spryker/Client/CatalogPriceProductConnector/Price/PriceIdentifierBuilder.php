<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\CatalogPriceProductConnector\Price;

use Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToCurrencyClientInterface;
use Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToPriceClientInterface;
use Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToPriceProductClientInterface;

class PriceIdentifierBuilder implements PriceIdentifierBuilderInterface
{
    /**
     * @var \Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToCurrencyClientInterface
     */
    protected $currencyClient;

    /**
     * @var \Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToPriceClientInterface
     */
    protected $priceClient;

    /**
     * @var \Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToPriceProductClientInterface
     */
    protected $priceProductClient;

    /**
     * @param \Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToCurrencyClientInterface $currencyClient
     * @param \Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToPriceClientInterface $priceClient
     * @param \Spryker\Client\CatalogPriceProductConnector\Dependency\CatalogPriceProductConnectorToPriceProductClientInterface $priceProductClient
     */
    public function __construct(
        CatalogPriceProductConnectorToCurrencyClientInterface $currencyClient,
        CatalogPriceProductConnectorToPriceClientInterface $priceClient,
        CatalogPriceProductConnectorToPriceProductClientInterface $priceProductClient
    ) {
        $this->currencyClient = $currencyClient;
        $this->priceClient = $priceClient;
        $this->priceProductClient = $priceProductClient;
    }

    /**
     * @return string
     */
    public function buildIdentifierForCurrentCurrency()
    {
        $priceType = $this->priceProductClient->getPriceTypeDefaultName();
        $currencyIsoCode = $this->currencyClient->getCurrent()->getCode();
        $priceMode = $this->priceClient->getCurrentPriceMode();

        return $this->buildIdentifierFor($priceType, $currencyIsoCode, $priceMode);
    }

    /**
     * @param string $priceType
     * @param string $currencyIsoCode
     * @param string $priceMode
     *
     * @return string
     */
    public function buildIdentifierFor($priceType, $currencyIsoCode, $priceMode)
    {
        return sprintf('price-%s-%s-%s', $priceType, $currencyIsoCode, $priceMode);
    }
}
