<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\OrdersRestApi\Controller;

use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\Kernel\Controller\AbstractController;

/**
 * @method \Spryker\Glue\OrdersRestApi\OrdersRestApiFactory getFactory()
 */
class OrdersResourceController extends AbstractController
{
    /**
     * @Glue({
     *     "getResource": {
     *          "summary": [
     *              "Get order by reference."
     *          ],
     *          "headers": [
     *              "Accept-Language"
     *          ],
     *          "responses": {
     *              "404": "Can not find order by the given order reference."
     *          }
     *     },
     *     "getCollection": {
     *          "summary": [
     *              "Get collection of orders."
     *          ],
     *          "headers": [
     *              "Accept-Language"
     *          ]
     *     }
     * })
     *
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getAction(RestRequestInterface $restRequest): RestResponseInterface
    {
        return $this->getFactory()->createOrderReader()->getOrderAttributes($restRequest);
    }
}
