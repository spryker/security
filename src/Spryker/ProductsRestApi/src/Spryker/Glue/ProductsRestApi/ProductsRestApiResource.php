<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductsRestApi;

use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\Kernel\AbstractRestResource;

/**
 * @method \Spryker\Glue\ProductsRestApi\ProductsRestApiFactory getFactory()
 */
class ProductsRestApiResource extends AbstractRestResource implements ProductsRestApiResourceInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $sku
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface|null
     */
    public function findProductAbstractBySku(string $sku, RestRequestInterface $restRequest): ?RestResourceInterface
    {
        return $this->getFactory()
            ->createAbstractProductsReader()
            ->findProductAbstractBySku($sku, $restRequest);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $sku
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface|null
     */
    public function findProductConcreteBySku(string $sku, RestRequestInterface $restRequest): ?RestResourceInterface
    {
        return $this
            ->getFactory()
            ->createConcreteProductsReader()
            ->findProductConcreteBySku($sku, $restRequest);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductAbstract
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface|null
     */
    public function findAbstractProductById(int $idProductAbstract, RestRequestInterface $restRequest): ?RestResourceInterface
    {
        return $this->getFactory()
            ->createAbstractProductsReader()
            ->findAbstractProductById($idProductAbstract, $restRequest);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductConcrete
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface|null
     */
    public function findConcreteProductById(int $idProductConcrete, RestRequestInterface $restRequest): ?RestResourceInterface
    {
        return $this->getFactory()
            ->createConcreteProductsReader()
            ->findConcreteProductById($idProductConcrete, $restRequest);
    }
}
