<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductsRestApi\Controller;

use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\Kernel\Controller\AbstractController;

/**
 * @method \Spryker\Glue\ProductsRestApi\ProductsRestApiFactory getFactory()
 */
class ConcreteProductsResourceController extends AbstractController
{
    /**
     * @Glue({
     *     "getResource": {
     *          "summary": [
     *              "Retrieve product concrete data."
     *          ],
     *          "headers": [
     *              "Accept-Language"
     *          ],
     *          "responses": {
     *              "400": "Concrete product sku is not specified.",
     *              "404": "Concrete product is not found."
     *          }
     *     }
     * })
     *
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getAction(RestRequestInterface $restRequest): RestResponseInterface
    {
        return $this->getFactory()
            ->createConcreteProductsReader()
            ->getProductConcreteStorageData($restRequest);
    }
}
