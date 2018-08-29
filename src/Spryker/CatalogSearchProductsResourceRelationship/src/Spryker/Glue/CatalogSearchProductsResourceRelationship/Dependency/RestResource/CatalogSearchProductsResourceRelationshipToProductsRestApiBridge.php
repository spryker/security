<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CatalogSearchProductsResourceRelationship\Dependency\RestResource;

use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;

class CatalogSearchProductsResourceRelationshipToProductsRestApiBridge implements CatalogSearchProductsResourceRelationshipToProductsRestApiInterface
{
    /**
     * @var \Spryker\Glue\ProductsRestApi\ProductsRestApiResourceInterface
     */
    protected $productsResource;

    /**
     * @param \Spryker\Glue\ProductsRestApi\ProductsRestApiResourceInterface $productsResource
     */
    public function __construct($productsResource)
    {
        $this->productsResource = $productsResource;
    }

    /**
     * @param string $abstractProductSku
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface|null
     */
    public function findOneByProductAbstractSku(string $abstractProductSku, RestRequestInterface $restRequest): ?RestResourceInterface
    {
        return $this->productsResource->findOneByProductAbstractSku($abstractProductSku, $restRequest);
    }
}
