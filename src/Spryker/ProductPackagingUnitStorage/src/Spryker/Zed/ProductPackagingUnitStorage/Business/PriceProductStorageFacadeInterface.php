<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Business;

interface PriceProductStorageFacadeInterface
{
    /**
     * Specification:
     * - Queries all priceProduct with the given productConcreteIds
     * - Stores data as json encoded to storage table
     * - Sends a copy of data to queue based on module config
     *
     * @api
     *
     * @param array $productConcreteIds
     *
     * @return void
     */
    public function publishPriceProductConcrete(array $productConcreteIds);

    /**
     * Specification:
     * - Finds and deletes priceProduct storage entities with the given productConcreteIds
     * - Sends delete message to queue based on module config
     *
     * @api
     *
     * @param array $productConcreteIds
     *
     * @return void
     */
    public function unpublishPriceProductConcrete(array $productConcreteIds);

    /**
     * - Queries all priceProduct with the given productAbstractIds
     * - Stores data as json encoded to storage table
     * - Sends a copy of data to queue based on module config
     *
     * @api
     *
     * @param array $productAbstractIds
     *
     * @return void
     */
    public function publishPriceProductAbstract(array $productAbstractIds);

    /**
     * Specification:
     * - Finds and deletes priceProduct storage entities with the given productAbstractIds
     * - Sends delete message to queue based on module config
     *
     * @api
     *
     * @param array $productAbstractIds
     *
     * @return void
     */
    public function unpublishPriceProductAbstract(array $productAbstractIds);
}
