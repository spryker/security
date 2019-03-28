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
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStockInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStoreFacadeInterface;
use Spryker\Zed\Availability\Dependency\Service\AvailabilityToUtilQuantityServiceInterface;
use Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface;

class ProductReservationReader implements ProductReservationReaderInterface
{
    /**
     * @var \Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface
     */
    protected $availabilityQueryContainer;

    /**
     * @var \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStockInterface
     */
    protected $stockFacade;

    /**
     * @var \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\Availability\Dependency\Service\AvailabilityToUtilQuantityServiceInterface
     */
    protected $utilQuantityService;

    /**
     * @param \Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface $availabilityQueryContainer
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStockInterface $stockFacade
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\Availability\Dependency\Service\AvailabilityToUtilQuantityServiceInterface $utilQuantityService
     */
    public function __construct(
        AvailabilityQueryContainerInterface $availabilityQueryContainer,
        AvailabilityToStockInterface $stockFacade,
        AvailabilityToStoreFacadeInterface $storeFacade,
        AvailabilityToUtilQuantityServiceInterface $utilQuantityService
    ) {
        $this->availabilityQueryContainer = $availabilityQueryContainer;
        $this->stockFacade = $stockFacade;
        $this->storeFacade = $storeFacade;
        $this->utilQuantityService = $utilQuantityService;
    }

    /**
     * @param int $idProductAbstract
     * @param int $idLocale
     *
     * @return \Generated\Shared\Transfer\ProductAbstractAvailabilityTransfer
     */
    public function getProductAbstractAvailability($idProductAbstract, $idLocale)
    {
        $storeTransfer = $this->getStoreTransfer();

        $stockNames = $this->stockFacade->getStoreToWarehouseMapping()[$storeTransfer->getName()];

        $productAbstractEntity = $this->availabilityQueryContainer
            ->queryAvailabilityAbstractWithStockByIdProductAbstractAndIdLocale(
                $idProductAbstract,
                $idLocale,
                $storeTransfer->getIdStore(),
                $stockNames
            )
            ->findOne();

        return $this->mapAbstractProductAvailabilityEntityToTransfer($productAbstractEntity);
    }

    /**
     * @param int $idProductAbstract
     * @param int $idLocale
     * @param int $idStore
     *
     * @return \Generated\Shared\Transfer\ProductAbstractAvailabilityTransfer|null
     */
    public function findProductAbstractAvailability($idProductAbstract, $idLocale, $idStore)
    {
        $storeTransfer = $this->getStoreTransfer($idStore);

        $stockTypes = $this->stockFacade->getStoreToWarehouseMapping()[$storeTransfer->getName()];

        $productAbstractEntity = $this->availabilityQueryContainer
            ->queryAvailabilityAbstractWithStockByIdProductAbstractAndIdLocale(
                $idProductAbstract,
                $idLocale,
                $storeTransfer->getIdStore(),
                $stockTypes
            )
            ->findOne();

        if (!$productAbstractEntity) {
            return null;
        }

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

        $storeTransfer = $this->storeFacade->getCurrentStore();

        $availabilityEntity = $this->availabilityQueryContainer
            ->queryAvailabilityBySkuAndIdStore($productConcreteAvailabilityRequestTransfer->getSku(), $storeTransfer->getIdStore())
            ->findOne();

        if (!$availabilityEntity) {
            return null;
        }

        return $this->mapProductConcreteAvailabilityEntityToTransfer($availabilityEntity);
    }

    /**
     * @param string $reservationQuantity
     *
     * @return float
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
     * @return float
     */
    protected function getReservationUniqueValue($reservationItems)
    {
        $reservation = 0.0;
        foreach ($reservationItems as $item) {
            $value = explode(':', $item);

            if (count($value) > 1) {
                $reservation = $this->sumQuantities($reservation, (float)$value[1]);
            }
        }

        return $reservation;
    }

    /**
     * @param float $firstQuantity
     * @param float $secondQuantity
     *
     * @return float
     */
    protected function sumQuantities(float $firstQuantity, float $secondQuantity): float
    {
        return $this->utilQuantityService->sumQuantities($firstQuantity, $secondQuantity);
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

    /**
     * @param int|null $idStore
     *
     * @return \Generated\Shared\Transfer\StoreTransfer
     */
    protected function getStoreTransfer($idStore = null)
    {
        if ($idStore !== null) {
            return $this->storeFacade->getStoreById($idStore);
        }

        return $this->storeFacade->getCurrentStore();
    }
}
