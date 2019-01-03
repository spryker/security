<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\UrlStorage\Business\Storage;

use ArrayObject;
use Generated\Shared\Transfer\UrlStorageTransfer;
use Orm\Zed\UrlStorage\Persistence\SpyUrlStorage;
use Spryker\Shared\Kernel\Store;
use Spryker\Zed\Url\Persistence\Propel\AbstractSpyUrl;
use Spryker\Zed\UrlStorage\Business\Exception\MissingResourceException;
use Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface;
use Spryker\Zed\UrlStorage\Persistence\UrlStorageQueryContainerInterface;

class UrlStorageWriter implements UrlStorageWriterInterface
{
    public const FK_URL = 'fkUrl';

    public const RESOURCE_TYPE = 'type';
    public const RESOURCE_VALUE = 'value';

    /**
     * @var \Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface
     */
    protected $utilSanitize;

    /**
     * @var \Spryker\Zed\UrlStorage\Persistence\UrlStorageQueryContainerInterface
     */
    protected $queryContainer;

    /**
     * @var bool
     */
    protected $isSendingToQueue = true;

    /**
     * @var \Spryker\Shared\Kernel\Store
     */
    protected $store;

    /**
     * @param \Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface $utilSanitize
     * @param \Spryker\Zed\UrlStorage\Persistence\UrlStorageQueryContainerInterface $queryContainer
     * @param bool $isSendingToQueue
     * @param \Spryker\Shared\Kernel\Store $store
     */
    public function __construct(
        UrlStorageToUtilSanitizeServiceInterface $utilSanitize,
        UrlStorageQueryContainerInterface $queryContainer,
        $isSendingToQueue,
        Store $store
    ) {
        $this->utilSanitize = $utilSanitize;
        $this->queryContainer = $queryContainer;
        $this->isSendingToQueue = $isSendingToQueue;
        $this->store = $store;
    }

    /**
     * @param array $urlIds
     *
     * @return void
     */
    public function publish(array $urlIds)
    {
        $urls = $this->findUrls($urlIds);
        $locales = $this->store->getLocales();
        $urlStorageTransfers = $this->mapUrlsToUrlStorageTransfers($urls, $locales);

        $urlStorageEntities = $this->findUrlStorageEntitiesByIds($urlIds);
        $this->storeData($urlStorageTransfers, $urlStorageEntities);
    }

    /**
     * @param array $urlIds
     *
     * @return void
     */
    public function unpublish(array $urlIds)
    {
        $spyUrlStorageEntities = $this->findUrlStorageEntitiesByIds($urlIds);
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
        $urlStorageEntity->setData($urlStorageTransfer->modifiedToArray());
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
     * @param array $localeUrl
     * @param array $urlResourceArguments
     *
     * @return array
     */
    public function findResourceArgumentForLocaleUrls(array $localeUrl, array $urlResourceArguments)
    {
        $urlResourceArgumentType = $urlResourceArguments[static::RESOURCE_TYPE];
        $resourcePrefix = AbstractSpyUrl::RESOURCE_PREFIX . $urlResourceArgumentType;

        return [
            static::RESOURCE_TYPE => $urlResourceArgumentType,
            static::RESOURCE_VALUE => $localeUrl[$resourcePrefix],
        ];
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
     * @param array $urls
     * @param array $locales
     *
     * @return \Generated\Shared\Transfer\UrlStorageTransfer[]
     */
    protected function mapUrlsToUrlStorageTransfers(array $urls, array $locales)
    {
        $localeUrls = $this->findLocaleUrls($urls);
        $localesCount = count($locales);

        $urlStorageTransfers = [];
        foreach ($urls as $url) {
            $urlResource = $this->findResourceArguments($url);
            $urlStorageTransfer = (new UrlStorageTransfer())->fromArray($url, true);
            $urlStorageTransfer->setLocaleUrls(
                $this->getLocaleUrlsForUrl($localeUrls[$urlResource[static::RESOURCE_TYPE]], $urlResource, $localesCount)
            );

            $urlStorageTransfers[] = $urlStorageTransfer;
        }

        return $urlStorageTransfers;
    }

    /**
     * @param array $localeUrls
     * @param array $urlResourceArguments
     * @param int $localesCount
     *
     * @return \ArrayObject|\Generated\Shared\Transfer\UrlStorageTransfer[]
     */
    protected function getLocaleUrlsForUrl(array $localeUrls, array $urlResourceArguments, int $localesCount)
    {
        $siblingUrls = new ArrayObject();
        foreach ($localeUrls as $key => $localeUrl) {
            $resourceArguments = $this->findResourceArgumentForLocaleUrls($localeUrl, $urlResourceArguments);

            if ($urlResourceArguments[static::RESOURCE_VALUE] === $resourceArguments[static::RESOURCE_VALUE]) {
                $siblingUrls[] = $localeUrl;
                unset($localeUrls[$key]);
            }

            if (count($siblingUrls) === $localesCount) {
                break;
            }
        }

        return $siblingUrls;
    }

    /**
     * @param array $urls
     *
     * @return array
     */
    protected function findLocaleUrls(array $urls)
    {
        $localeUrls = [];
        foreach ($urls as $url) {
            $resourceArguments = $this->findResourceArguments($url);
            if (isset($localeUrls[$resourceArguments[static::RESOURCE_TYPE]])) {
                $localeUrls[$resourceArguments[static::RESOURCE_TYPE]][] = $resourceArguments[static::RESOURCE_VALUE];
                continue;
            }

            $localeUrls[$resourceArguments[static::RESOURCE_TYPE]] = [$resourceArguments[static::RESOURCE_VALUE]];
        }

        foreach ($localeUrls as $resourceType => $resourceIds) {
            $localeUrls[$resourceType] = $this->queryContainer
                ->queryUrlsByResourceTypeAndIds($resourceType, $resourceIds)
                ->find()
                ->getData();
        }

        return $localeUrls;
    }

    /**
     * @param array $urlIds
     *
     * @return array
     */
    protected function findUrlStorageEntitiesByIds(array $urlIds)
    {
        return $this->queryContainer->queryUrlStorageByIds($urlIds)->find()->toKeyIndex(static::FK_URL);
    }

    /**
     * @param array $urlIds
     *
     * @return array
     */
    protected function findUrls(array $urlIds)
    {
        return $this->queryContainer->queryUrls($urlIds)->find()->getData();
    }
}
