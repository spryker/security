<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductAvailabilitiesRestApi\Processor\ConcreteProductAvailability;

use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToAvailabilityStorageClientInterface;
use Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToProductStorageClientInterface;
use Spryker\Glue\ProductAvailabilitiesRestApi\Processor\Mapper\ConcreteProductAvailabilitiesResourceMapperInterface;
use Spryker\Glue\ProductAvailabilitiesRestApi\ProductAvailabilitiesRestApiConfig;
use Spryker\Glue\ProductsRestApi\ProductsRestApiConfig;
use Symfony\Component\HttpFoundation\Response;

class ConcreteProductAvailabilitiesReader implements ConcreteProductAvailabilitiesReaderInterface
{
    protected const PRODUCT_CONCRETE_MAPPING = 'sku';
    protected const KEY_ID_PRODUCT_ABSTRACT = 'id_product_abstract';

    /**
     * @var \Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToAvailabilityStorageClientInterface
     */
    protected $availabilityStorageClient;

    /**
     * @var \Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToProductStorageClientInterface
     */
    protected $productStorageClient;

    /**
     * @var \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface
     */
    protected $restResourceBuilder;

    /**
     * @var \Spryker\Glue\ProductAvailabilitiesRestApi\Processor\Mapper\ConcreteProductAvailabilitiesResourceMapperInterface
     */
    protected $concreteProductsAvailabilityResourceMapper;

    /**
     * @param \Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToAvailabilityStorageClientInterface $availabilityStorageClient
     * @param \Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToProductStorageClientInterface $productStorageClient
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface $restResourceBuilder
     * @param \Spryker\Glue\ProductAvailabilitiesRestApi\Processor\Mapper\ConcreteProductAvailabilitiesResourceMapperInterface $concreteProductsAvailabilityResourceMapper
     */
    public function __construct(
        ProductAvailabilitiesRestApiToAvailabilityStorageClientInterface $availabilityStorageClient,
        ProductAvailabilitiesRestApiToProductStorageClientInterface $productStorageClient,
        RestResourceBuilderInterface $restResourceBuilder,
        ConcreteProductAvailabilitiesResourceMapperInterface $concreteProductsAvailabilityResourceMapper
    ) {
        $this->availabilityStorageClient = $availabilityStorageClient;
        $this->productStorageClient = $productStorageClient;
        $this->restResourceBuilder = $restResourceBuilder;
        $this->concreteProductsAvailabilityResourceMapper = $concreteProductsAvailabilityResourceMapper;
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getConcreteProductAvailability(RestRequestInterface $restRequest): RestResponseInterface
    {
        $restResponse = $this->restResourceBuilder->createRestResponse();

        $concreteProductResource = $restRequest->findParentResourceByType(ProductsRestApiConfig::RESOURCE_CONCRETE_PRODUCTS);
        if (!$concreteProductResource) {
            $restErrorTransfer = (new RestErrorMessageTransfer())
                ->setCode(ProductsRestApiConfig::RESPONSE_CODE_CONCRETE_PRODUCT_SKU_IS_NOT_SPECIFIED)
                ->setStatus(Response::HTTP_BAD_REQUEST)
                ->setDetail(ProductsRestApiConfig::RESPONSE_DETAIL_CONCRETE_PRODUCT_SKU_IS_NOT_SPECIFIED);

            return $restResponse->addError($restErrorTransfer);
        }

        $productConcreteSku = $concreteProductResource->getId();
        $availabilityResource = $this->findConcreteProductAvailabilityByConcreteProductSku($productConcreteSku, $restRequest);
        if (!$availabilityResource) {
            return $this->createErrorResponse($restResponse);
        }

        return $restResponse->addResource($availabilityResource);
    }

    /**
     * @param string $concreteProductSku
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface|null
     */
    public function findConcreteProductAvailabilityByConcreteProductSku(string $concreteProductSku, RestRequestInterface $restRequest): ?RestResourceInterface
    {
        $localeName = $restRequest->getMetadata()->getLocale();
            $productConcreteStorageData = $this->productStorageClient
            ->findProductConcreteStorageDataByMap(static::PRODUCT_CONCRETE_MAPPING, $concreteProductSku, $localeName);
        if (!$productConcreteStorageData) {
            return null;
        }
        $idProductAbstract = $productConcreteStorageData[static::KEY_ID_PRODUCT_ABSTRACT];

        $availabilityAbstractEntityTransfer = $this->availabilityStorageClient->getAvailabilityAbstract((int)$idProductAbstract);
        foreach ($availabilityAbstractEntityTransfer->getSpyAvailabilities() as $availabilityEntityTransfer) {
            if ($availabilityEntityTransfer->getSku() === $concreteProductSku) {
                $restResource = $this->concreteProductsAvailabilityResourceMapper
                    ->mapConcreteProductsAvailabilityTransferToRestResource($availabilityEntityTransfer);

                $restResourceSelfLink = sprintf(
                    '%s/%s/%s',
                    ProductsRestApiConfig::RESOURCE_CONCRETE_PRODUCTS,
                    $concreteProductSku,
                    ProductAvailabilitiesRestApiConfig::RESOURCE_CONCRETE_PRODUCT_AVAILABILITIES
                );
                $restResource->addLink('self', $restResourceSelfLink);

                return $restResource;
            }
        }
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface $restResponse
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createErrorResponse(RestResponseInterface $restResponse): RestResponseInterface
    {
        $restErrorTransfer = (new RestErrorMessageTransfer())
            ->setCode(ProductAvailabilitiesRestApiConfig::RESPONSE_CODE_CONCRETE_PRODUCT_AVAILABILITY_NOT_FOUND)
            ->setStatus(Response::HTTP_NOT_FOUND)
            ->setDetail(ProductAvailabilitiesRestApiConfig::RESPONSE_DETAILS_CONCRETE_PRODUCT_AVAILABILITY_NOT_FOUND);

        return $restResponse->addError($restErrorTransfer);
    }
}
