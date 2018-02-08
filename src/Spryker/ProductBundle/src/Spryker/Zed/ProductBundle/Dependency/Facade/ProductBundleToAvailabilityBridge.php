<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Dependency\Facade;

use Generated\Shared\Transfer\StoreTransfer;

class ProductBundleToAvailabilityBridge implements ProductBundleToAvailabilityInterface
{
    /**
     * @var \Spryker\Zed\Availability\Business\AvailabilityFacadeInterface
     */
    protected $availabilityFacade;

    /**
     * @param \Spryker\Zed\Availability\Business\AvailabilityFacadeInterface $availabilityFacade
     */
    public function __construct($availabilityFacade)
    {
        $this->availabilityFacade = $availabilityFacade;
    }

    /**
     * @param string $sku
     * @param int $quantity
     *
     * @return bool
     */
    public function isProductSellable($sku, $quantity)
    {
        return $this->availabilityFacade->isProductSellable($sku, $quantity);
    }

    /**
     * @param string $sku
     *
     * @return int
     */
    public function calculateStockForProduct($sku)
    {
        return $this->availabilityFacade->calculateStockForProduct($sku);
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return int
     */
    public function calculateStockForProductWithStore($sku, StoreTransfer $storeTransfer)
    {
        if (method_exists($this->availabilityFacade, 'calculateStockForProductWithStore')) {
            return $this->availabilityFacade->calculateStockForProductWithStore($sku, $storeTransfer);
        }

        return $this->availabilityFacade->calculateStockForProduct($sku);
    }

    /**
     * @param string $sku
     * @param int $quantity
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return bool
     */
    public function isProductSellableForStore($sku, $quantity, StoreTransfer $storeTransfer)
    {
        if (method_exists($this->availabilityFacade, 'isProductSellableForStore')) {
            return $this->availabilityFacade->isProductSellableForStore($sku, $quantity, $storeTransfer);
        }

        return $this->availabilityFacade->calculateStockForProduct($sku);
    }

    /**
     * @param int $idAvailabilityAbstract
     *
     * @return void
     */
    public function touchAvailabilityAbstract($idAvailabilityAbstract)
    {
        $this->availabilityFacade->touchAvailabilityAbstract($idAvailabilityAbstract);
    }

    /**
     * @param string $sku
     * @param int $quantity
     *
     * @return int
     */
    public function saveProductAvailability($sku, $quantity)
    {
        return $this->availabilityFacade->saveProductAvailability($sku, $quantity);
    }

    /**
     * @param string $sku
     * @param int $quantity
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return int
     */
    public function saveProductAvailabilityForStore($sku, $quantity, StoreTransfer $storeTransfer)
    {
        if (method_exists($this->availabilityFacade, 'saveProductAvailabilityForStore')) {
            return $this->availabilityFacade->saveProductAvailabilityForStore($sku, $quantity, $storeTransfer);
        }

        return $this->availabilityFacade->saveProductAvailability($sku, $quantity);
    }
}
