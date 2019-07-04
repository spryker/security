<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\UrlStorage\Business\Storage;

use Generated\Shared\Transfer\UrlStorageTransfer;
use Orm\Zed\Url\Persistence\SpyUrl;
use Orm\Zed\UrlStorage\Persistence\SpyUrlStorage;
use Spryker\Zed\Url\Persistence\Propel\AbstractSpyUrl;
use Spryker\Zed\UrlStorage\Business\Exception\MissingResourceException;
use Spryker\Zed\UrlStorage\Dependency\Facade\UrlStorageToStoreFacadeInterface;
use Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface;
use Spryker\Zed\UrlStorage\Persistence\UrlStorageRepositoryInterface;

class UrlStorageWriter implements UrlStorageWriterInterface
{
    public const RESOURCE_TYPE = 'type';
    public const RESOURCE_VALUE = 'value';

    /**
     * @var \Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface
     */
    protected $utilSanitize;

    /**
     * @var \Spryker\Zed\UrlStorage\Persistence\UrlStorageRepositoryInterface
     */
    protected $urlStorageRepository;

    /**
     * @var \Spryker\Zed\UrlStorage\Dependency\Facade\UrlStorageToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var bool
     */
    protected $isSendingToQueue = true;

    /**
     * @param \Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface $utilSanitize
     * @param \Spryker\Zed\UrlStorage\Persistence\UrlStorageRepositoryInterface $urlStorageRepository
     * @param \Spryker\Zed\UrlStorage\Dependency\Facade\UrlStorageToStoreFacadeInterface $storeFacade
     * @param bool $isSendingToQueue
     */
    public function __construct(
        UrlStorageToUtilSanitizeServiceInterface $utilSanitize,
        UrlStorageRepositoryInterface $urlStorageRepository,
        UrlStorageToStoreFacadeInterface $storeFacade,
        bool $isSendingToQueue
    ) {
        $this->utilSanitize = $utilSanitize;
        $this->urlStorageRepository = $urlStorageRepository;
        $this->storeFacade = $storeFacade;
        $this->isSendingToQueue = $isSendingToQueue;
    }

    /**
     * @param int[] $urlIds
     *
     * @return void
     */
    public function publish(array $urlIds)
    {
        $localeNames = $this->getSharedPersistenceLocaleNames();
        $urlEntityTransfers = $this->urlStorageRepository->findLocalizedUrlsByUrlIds($urlIds, $localeNames);
        $urlStorageTransfers = $this->mapUrlsEntitiesToUrlStorageTransfers($urlEntityTransfers);
        $urlStorageEntities = $this->urlStorageRepository->findUrlStorageByUrlIds(array_keys($urlStorageTransfers));

        $this->storeData($urlStorageTransfers, $urlStorageEntities);
    }

    /**
     * @return string[]
     */
    protected function getSharedPersistenceLocaleNames(): array
    {
        $storeTransfer = $this->storeFacade->getCurrentStore();
        $localeNames = $storeTransfer->getAvailableLocaleIsoCodes();
        foreach ($storeTransfer->getStoresWithSharedPersistence() as $storeName) {
            foreach ($this->storeFacade->getStoreByName($storeName)->getAvailableLocaleIsoCodes() as $localeName) {
                $localeNames[] = $localeName;
            }
        }

        return array_unique($localeNames);
    }

    /**
     * @param int[] $urlIds
     *
     * @return void
     */
    public function unpublish(array $urlIds)
    {
        $spyUrlStorageEntities = $this->urlStorageRepository->findUrlStorageByUrlIds($urlIds);
        foreach ($spyUrlStorageEntities as $spyUrlStorageEntity) {
            $spyUrlStorageEntity->delete();
        }
    }

    /**
     * @param \Generated\Shared\Transfer\UrlStorageTransfer[] $urlStorageTransfers
     * @param \Orm\Zed\UrlStorage\Persistence\SpyUrlStorage[] $urlStorageEntities
     *
     * @return void
     */
    protected function storeData(array $urlStorageTransfers, array $urlStorageEntities)
    {
        foreach ($urlStorageTransfers as $urlStorageTransfer) {
            $urlStorageEntity = $urlStorageEntities[$urlStorageTransfer->getIdUrl()] ?? null;

            $this->storeDataSet($urlStorageTransfer, $urlStorageEntity);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\UrlStorageTransfer $urlStorageTransfer
     * @param \Orm\Zed\UrlStorage\Persistence\SpyUrlStorage|null $urlStorageEntity
     *
     * @return void
     */
    protected function storeDataSet(UrlStorageTransfer $urlStorageTransfer, ?SpyUrlStorage $urlStorageEntity = null)
    {
        if ($urlStorageEntity === null) {
            $urlStorageEntity = new SpyUrlStorage();
        }

        $resource = $this->findResourceArguments($urlStorageTransfer->toArray());

        $urlStorageEntity->setByName('fk_' . $resource[static::RESOURCE_TYPE], $resource[static::RESOURCE_VALUE]);
        $urlStorageEntity->setUrl($urlStorageTransfer->getUrl());
        $urlStorageEntity->setFkUrl($urlStorageTransfer->getIdUrl());
        $urlStorageEntity->setData($this->utilSanitize->arrayFilterRecursive($urlStorageTransfer->modifiedToArray()));
        $urlStorageEntity->setIsSendingToQueue($this->isSendingToQueue);
        $urlStorageEntity->save();
    }

    /**
     * @param array $data
     *
     * @throws \Spryker\Zed\UrlStorage\Business\Exception\MissingResourceException
     *
     * @return array
     */
    protected function findResourceArguments(array $data)
    {
        foreach ($data as $columnName => $value) {
            if (!$this->isFkResourceUrl($columnName, $value)) {
                continue;
            }

            $type = str_replace(AbstractSpyUrl::RESOURCE_PREFIX, '', $columnName);

            return [
                static::RESOURCE_TYPE => $type,
                static::RESOURCE_VALUE => $value,
            ];
        }

        throw new MissingResourceException(
            sprintf(
                'Encountered a URL entity that is missing a resource: %s',
                json_encode($data)
            )
        );
    }

    /**
     * @param string $columnName
     * @param string $value
     *
     * @return bool
     */
    protected function isFkResourceUrl($columnName, $value)
    {
        return $value !== null && strpos($columnName, AbstractSpyUrl::RESOURCE_PREFIX) === 0;
    }

    /**
     * @param \Orm\Zed\Url\Persistence\SpyUrl[][] $groupedUrlEntities
     *
     * @return \Generated\Shared\Transfer\UrlStorageTransfer[]
     */
    protected function mapUrlsEntitiesToUrlStorageTransfers(array $groupedUrlEntities)
    {
        $urlStorageTransfers = [];
        foreach ($groupedUrlEntities as $resource => $urlEntities) {
            foreach ($urlEntities as $urlEntity) {
                $urlStorageTransfers[$urlEntity->getIdUrl()] = $this->createUrlStorageTransfer($urlEntity, $urlEntities);
            }
        }

        return $urlStorageTransfers;
    }

    /**
     * @param \Orm\Zed\Url\Persistence\SpyUrl $urlEntity
     * @param \Orm\Zed\Url\Persistence\SpyUrl[] $urlEntities
     *
     * @return \Generated\Shared\Transfer\UrlStorageTransfer
     */
    protected function createUrlStorageTransfer(SpyUrl $urlEntity, array $urlEntities): UrlStorageTransfer
    {
        $urlEntities = array_filter($urlEntities, function (SpyUrl $otherUrlEntity) use ($urlEntity) {
            return $urlEntity->getIdUrl() <> $otherUrlEntity->getIdUrl();
        });

        $urlStorageTransfer = (new UrlStorageTransfer())->fromArray($urlEntity->toArray(), true);

        foreach ($urlEntities as $otherUrlEntity) {
            $urlStorageTransfer->addUrlStorage(
                (new UrlStorageTransfer())->fromArray($otherUrlEntity->toArray(), true)
            );
        }

        return $urlStorageTransfer;
    }
}
