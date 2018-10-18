<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductAvailabilitiesRestApi\Controller;

use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\Kernel\Controller\AbstractController;

/**
 * @method \Spryker\Glue\ProductAvailabilitiesRestApi\ProductAvailabilitiesRestApiFactory getFactory()
 */
class AbstractProductAvailabilitiesResourceController extends AbstractController
{
    /**
     * @Glue({
     *     "getResource": {
     *          "summary": [
     *              "Retrieve Abstract product availabilities data for given sku."
     *          ],
     *          "headers": [
     *              "Accept-Language"
     *          ],
     *          "responses": {
     *              "400": "Abstract product sku is not specified.",
     *              "404": "Abstract product availability is not found."
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
            ->createAbstractProductAvailabilitiesReader()
            ->getAbstractProductAvailability($restRequest);
    }
}
