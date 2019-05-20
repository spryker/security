<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CartsRestApi\Processor\Cart;

use Generated\Shared\Transfer\RestCartsAttributesTransfer;
use Spryker\Client\CartsRestApi\CartsRestApiClientInterface;
use Spryker\Glue\CartsRestApi\Processor\Mapper\CartsResourceMapperInterface;
use Spryker\Glue\CartsRestApi\Processor\RestResponseBuilder\CartRestResponseBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;

class CartUpdater implements CartUpdaterInterface
{
    /**
     * @var \Spryker\Client\CartsRestApi\CartsRestApiClientInterface
     */
    protected $cartsRestApiClient;

    /**
     * @var \Spryker\Glue\CartsRestApi\Processor\Mapper\CartsResourceMapperInterface
     */
    protected $cartsResourceMapper;

    /**
     * @var \Spryker\Glue\CartsRestApi\Processor\RestResponseBuilder\CartRestResponseBuilderInterface
     */
    protected $cartRestResponseBuilder;

    /**
     * @var \Spryker\Glue\CartsRestApiExtension\Dependency\Plugin\CustomerExpanderPluginInterface[]
     */
    protected $quoteCustomerExpanderPlugins;

    /**
     * @param \Spryker\Client\CartsRestApi\CartsRestApiClientInterface $cartsRestApiClient
     * @param \Spryker\Glue\CartsRestApi\Processor\Mapper\CartsResourceMapperInterface $cartsResourceMapper
     * @param \Spryker\Glue\CartsRestApi\Processor\RestResponseBuilder\CartRestResponseBuilderInterface $cartRestResponseBuilder
     * @param \Spryker\Glue\CartsRestApiExtension\Dependency\Plugin\CustomerExpanderPluginInterface[] $quoteCustomerExpanderPlugins
     */
    public function __construct(
        CartsRestApiClientInterface $cartsRestApiClient,
        CartsResourceMapperInterface $cartsResourceMapper,
        CartRestResponseBuilderInterface $cartRestResponseBuilder,
        array $quoteCustomerExpanderPlugins
    ) {
        $this->cartsRestApiClient = $cartsRestApiClient;
        $this->cartsResourceMapper = $cartsResourceMapper;
        $this->cartRestResponseBuilder = $cartRestResponseBuilder;
        $this->quoteCustomerExpanderPlugins = $quoteCustomerExpanderPlugins;
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     * @param \Generated\Shared\Transfer\RestCartsAttributesTransfer $restCartsAttributesTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function update(
        RestRequestInterface $restRequest,
        RestCartsAttributesTransfer $restCartsAttributesTransfer
    ): RestResponseInterface {
        $quoteTransfer = $this->cartsResourceMapper->mapRestCartsAttributesTransferToQuoteTransfer($restCartsAttributesTransfer, $restRequest);
        $quoteTransfer->setUuid($restRequest->getResource()->getId());

        foreach ($this->quoteCustomerExpanderPlugins as $quoteCustomerExpanderPlugin) {
            $quoteTransfer->setCustomer(
                $quoteCustomerExpanderPlugin->expand($quoteTransfer->getCustomer(), $restRequest)
            );
        }

        $quoteResponseTransfer = $this->cartsRestApiClient->updateQuote($quoteTransfer);

        if (count($quoteResponseTransfer->getErrorCodes()) > 0) {
            return $this->cartRestResponseBuilder->buildErrorRestResponseBasedOnErrorCodes($quoteResponseTransfer->getErrorCodes());
        }

        $restResource = $this->cartsResourceMapper->mapCartsResource(
            $quoteResponseTransfer->getQuoteTransfer(),
            $restRequest
        );

        return $this->cartRestResponseBuilder->createCartRestResponse($restResource);
    }
}
