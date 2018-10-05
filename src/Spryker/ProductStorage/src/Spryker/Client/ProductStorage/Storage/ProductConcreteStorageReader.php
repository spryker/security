<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductStorage\Storage;

use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Spryker\Client\ProductStorage\Dependency\Client\ProductStorageToStorageClientInterface;
use Spryker\Client\ProductStorage\Dependency\Service\ProductStorageToSynchronizationServiceInterface;
use Spryker\Shared\ProductStorage\ProductStorageConstants;

class ProductConcreteStorageReader implements ProductConcreteStorageReaderInterface
{
    /**
     * @var \Spryker\Client\ProductStorage\Dependency\Service\ProductStorageToSynchronizationServiceInterface
     */
    protected $synchronizationService;

    /**
     * @var \Spryker\Client\ProductStorage\Dependency\Client\ProductStorageToStorageClientInterface
     */
    protected $storageClient;

    /**
     * @var \Spryker\Client\ProductStorageExtension\Dependency\Plugin\ProductConcreteRestrictionPluginInterface[]
     */
    protected $productConcreteRestrictionPlugins;

    /**
     * @param \Spryker\Client\ProductStorage\Dependency\Client\ProductStorageToStorageClientInterface $storageClient
     * @param \Spryker\Client\ProductStorage\Dependency\Service\ProductStorageToSynchronizationServiceInterface $synchronizationService
     * @param \Spryker\Client\ProductStorageExtension\Dependency\Plugin\ProductConcreteRestrictionPluginInterface[] $productConcreteRestrictionPlugins
     */
    public function __construct(
        ProductStorageToStorageClientInterface $storageClient,
        ProductStorageToSynchronizationServiceInterface $synchronizationService,
        array $productConcreteRestrictionPlugins = []
    ) {
        $this->storageClient = $storageClient;
        $this->synchronizationService = $synchronizationService;
        $this->productConcreteRestrictionPlugins = $productConcreteRestrictionPlugins;
    }

    /**
     * @deprecated Use findProductConcreteStorageData($idProductConcrete, $localeName): ?array
     *
     * @param int $idProductConcrete
     * @param string $localeName
     *
     * @return array
     */
    public function getProductConcreteStorageData($idProductConcrete, $localeName)
    {
        return $this->findProductConcreteStorageData($idProductConcrete, $localeName);
    }

    /**
     * @param int $idProductConcrete
     * @param string $localeName
     *
     * @return array|null
     */
    public function findProductConcreteStorageData($idProductConcrete, $localeName): ?array
    {
        if (!$idProductConcrete || $this->isProductConcreteRestricted($idProductConcrete)) {
            return null;
        }

        $key = $this->getStorageKey($idProductConcrete, $localeName);

        return $this->storageClient->get($key);
    }

    /**
     * @param int $idProductConcrete
     *
     * @return bool
     */
    public function isProductConcreteRestricted(int $idProductConcrete): bool
    {
        foreach ($this->productConcreteRestrictionPlugins as $productConcreteRestrictionPlugin) {
            if ($productConcreteRestrictionPlugin->isRestricted($idProductConcrete)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $mappingType
     * @param string $identifier
     * @param string $localeName
     *
     * @return array|null
     */
    public function findProductConcreteStorageDataByMapping(string $mappingType, string $identifier, string $localeName): ?array
    {
        $reference = $mappingType . ':' . $identifier;
        $mappingKey = $this->getStorageKey($reference, $localeName);
        $mappingData = $this->storageClient->get($mappingKey);

        if (!$mappingData) {
            return null;
        }

        return $this->findProductConcreteStorageData($mappingData['id'], $localeName);
    }

    /**
     * @param string $reference
     * @param string $localeName
     *
     * @return string
     */
    protected function getStorageKey(string $reference, string $localeName): string
    {
        $synchronizationDataTransfer = new SynchronizationDataTransfer();
        $synchronizationDataTransfer
            ->setReference($reference)
            ->setLocale($localeName);

        return $this->synchronizationService
            ->getStorageKeyBuilder(ProductStorageConstants::PRODUCT_CONCRETE_RESOURCE_NAME)
            ->generateKey($synchronizationDataTransfer);
    }
}
