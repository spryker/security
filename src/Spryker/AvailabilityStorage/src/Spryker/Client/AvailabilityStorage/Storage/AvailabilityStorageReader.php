<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\AvailabilityStorage\Storage;

use Generated\Shared\Transfer\SpyAvailabilityAbstractEntityTransfer;
use Generated\Shared\Transfer\StorageAvailabilityTransfer;
use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Spryker\Client\AvailabilityStorage\Dependency\Client\AvailabilityStorageToStorageClientInterface;
use Spryker\Client\AvailabilityStorage\Dependency\Service\AvailabilityStorageToSynchronizationServiceInterface;
use Spryker\Shared\AvailabilityStorage\AvailabilityStorageConstants;
use Spryker\Shared\Kernel\Store;

class AvailabilityStorageReader implements AvailabilityStorageReaderInterface
{
    /**
     * @var \Spryker\Client\AvailabilityStorage\Dependency\Client\AvailabilityStorageToStorageClientInterface
     */
    protected $storageClient;

    /**
     * @var \Spryker\Client\AvailabilityStorage\Dependency\Service\AvailabilityStorageToSynchronizationServiceInterface
     */
    protected $synchronizationService;

    /**
     * @param \Spryker\Client\AvailabilityStorage\Dependency\Client\AvailabilityStorageToStorageClientInterface $storageClient
     * @param \Spryker\Client\AvailabilityStorage\Dependency\Service\AvailabilityStorageToSynchronizationServiceInterface $synchronizationService
     */
    public function __construct(AvailabilityStorageToStorageClientInterface $storageClient, AvailabilityStorageToSynchronizationServiceInterface $synchronizationService)
    {
        $this->storageClient = $storageClient;
        $this->synchronizationService = $synchronizationService;
    }

    /**
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\StorageAvailabilityTransfer
     */
    public function getAvailabilityAbstractAsStorageTransfer($idProductAbstract)
    {
        $spyAvailabilityAbstractTransfer = $this->getAvailabilityAbstract($idProductAbstract);
        $storageAvailabilityTransfer = new StorageAvailabilityTransfer();

        $isAbstractProductAvailable = $spyAvailabilityAbstractTransfer->getQuantity() > 0;
        $storageAvailabilityTransfer->setIsAbstractProductAvailable($isAbstractProductAvailable);

        $concreteAvailabilities = [];
        foreach ($spyAvailabilityAbstractTransfer->getSpyAvailabilities() as $spyAvailability) {
            $concreteAvailabilities[$spyAvailability->getSku()] = $spyAvailability->getQuantity() > 0 || $spyAvailability->getIsNeverOutOfStock();
        }

        $storageAvailabilityTransfer->setConcreteProductAvailableItems($concreteAvailabilities);

        return $storageAvailabilityTransfer;
    }

    /**
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\SpyAvailabilityAbstractEntityTransfer
     */
    public function getAvailabilityAbstract($idProductAbstract)
    {
        $key = $this->generateKey($idProductAbstract);
        $availability = $this->storageClient->get($key);

        $spyAvailabilityAbstractEntityTransfer = new SpyAvailabilityAbstractEntityTransfer();
        if ($availability === null) {
            return $spyAvailabilityAbstractEntityTransfer;
        }

        return $spyAvailabilityAbstractEntityTransfer->fromArray($availability, true);
    }

    /**
     * @param int $idProductAbstract
     *
     * @return string
     */
    protected function generateKey($idProductAbstract)
    {
        $store = Store::getInstance()->getStoreName();

        $synchronizationDataTransfer = new SynchronizationDataTransfer();
        $synchronizationDataTransfer->setStore($store);
        $synchronizationDataTransfer->setReference($idProductAbstract);

        return $this->synchronizationService->getStorageKeyBuilder(AvailabilityStorageConstants::AVAILABILITY_RESOURCE_NAME)->generateKey($synchronizationDataTransfer);
    }
}
