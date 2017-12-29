<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Availability\Business\Model;

use Generated\Shared\Transfer\ProductAbstractAvailabilityTransfer;
use Generated\Shared\Transfer\ProductConcreteAvailabilityRequestTransfer;
use Generated\Shared\Transfer\ProductConcreteAvailabilityTransfer;
use Orm\Zed\Availability\Persistence\SpyAvailability;
use Orm\Zed\Product\Persistence\SpyProductAbstract;
use Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface;

class ProductReservationReader implements ProductReservationReaderInterface
{
    /**
     * @var \Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface
     */
    protected $availabilityQueryContainer;

    /**
     * @param \Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface $availabilityQueryContainer
     */
    public function __construct(AvailabilityQueryContainerInterface $availabilityQueryContainer)
    {
        $this->availabilityQueryContainer = $availabilityQueryContainer;
    }

    /**
     * @param int $idProductAbstract
     * @param int $idLocale
     *
     * @return \Generated\Shared\Transfer\ProductAbstractAvailabilityTransfer
     */
    public function getProductAbstractAvailability($idProductAbstract, $idLocale)
    {
        $productAbstractEntity = $this->availabilityQueryContainer
            ->queryAvailabilityAbstractWithStockByIdProductAbstractAndIdLocale(
                $idProductAbstract,
                $idLocale
            )
            ->findOne();

        return $this->mapAbstractProductAvailabilityEntityToTransfer($productAbstractEntity);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteAvailabilityRequestTransfer $productConcreteAvailabilityRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteAvailabilityTransfer|null
     */
    public function findProductConcreteAvailability(ProductConcreteAvailabilityRequestTransfer $productConcreteAvailabilityRequestTransfer)
    {
        $productConcreteAvailabilityRequestTransfer->requireSku();

        $availabilityEntity = $this->availabilityQueryContainer
            ->querySpyAvailabilityBySku($productConcreteAvailabilityRequestTransfer->getSku())
            ->findOne();

        if (!$availabilityEntity) {
            return null;
        }

        return $this->mapProductConcreteAvailabilityEntityToTransfer($availabilityEntity);
    }

    /**
     * @param string $reservationQuantity
     *
     * @return int
     */
    protected function calculateReservation($reservationQuantity)
    {
        $reservationItems = explode(',', $reservationQuantity);
        $reservationItems = array_unique($reservationItems);

        return $this->getReservationUniqueValue($reservationItems);
    }

    /**
     * @param array $reservationItems
     *
     * @return int
     */
    protected function getReservationUniqueValue($reservationItems)
    {
        $reservation = 0;
        foreach ($reservationItems as $item) {
            $value = explode(':', $item);

            if (count($value) > 1) {
                $reservation += (int)$value[1];
            }
        }

        return $reservation;
    }

    /**
     * @param \Orm\Zed\Availability\Persistence\SpyAvailability $availabilityEntity
     *
     * @return \Generated\Shared\Transfer\ProductConcreteAvailabilityTransfer
     */
    protected function mapProductConcreteAvailabilityEntityToTransfer(SpyAvailability $availabilityEntity)
    {
        return (new ProductConcreteAvailabilityTransfer())
            ->setAvailability($availabilityEntity->getQuantity())
            ->setIsNeverOutOfStock($availabilityEntity->getIsNeverOutOfStock());
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductAbstract $productAbstractEntity
     *
     * @return \Generated\Shared\Transfer\ProductAbstractAvailabilityTransfer
     */
    protected function mapAbstractProductAvailabilityEntityToTransfer(SpyProductAbstract $productAbstractEntity)
    {
        $productAbstractAvailabilityTransfer = new ProductAbstractAvailabilityTransfer();
        $productAbstractAvailabilityTransfer->fromArray($productAbstractEntity->toArray(), true);
        $productAbstractAvailabilityTransfer->setAvailability($productAbstractEntity->getAvailabilityQuantity());
        $productAbstractAvailabilityTransfer->setReservationQuantity(
            $this->calculateReservation($productAbstractEntity->getReservationQuantity())
        );

        $this->setAbstractNeverOutOfStock($productAbstractEntity, $productAbstractAvailabilityTransfer);

        return $productAbstractAvailabilityTransfer;
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductAbstract $productAbstractEntity
     * @param \Generated\Shared\Transfer\ProductAbstractAvailabilityTransfer $productAbstractAvailabilityTransfer
     *
     * @return void
     */
    protected function setAbstractNeverOutOfStock(
        SpyProductAbstract $productAbstractEntity,
        ProductAbstractAvailabilityTransfer $productAbstractAvailabilityTransfer
    ) {

        $neverOutOfStockSet = explode(',', $productAbstractEntity->getConcreteNeverOutOfStockSet());

        $productAbstractAvailabilityTransfer->setIsNeverOutOfStock(false);
        foreach ($neverOutOfStockSet as $status) {
            if (filter_var($status, FILTER_VALIDATE_BOOLEAN)) {
                $productAbstractAvailabilityTransfer->setIsNeverOutOfStock(true);
                break;
            }
        }
    }
}
