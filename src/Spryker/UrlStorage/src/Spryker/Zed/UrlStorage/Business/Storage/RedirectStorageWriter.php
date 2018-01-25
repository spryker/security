<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\UrlStorage\Business\Storage;

use Orm\Zed\UrlStorage\Persistence\SpyUrlRedirectStorage;
use Spryker\Shared\Kernel\Store;
use Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface;
use Spryker\Zed\UrlStorage\Persistence\UrlStorageQueryContainerInterface;

class RedirectStorageWriter implements RedirectStorageWriterInterface
{
    const ID_URL_REDIRECT = 'id_url_redirect';
    const FK_URL_REDIRECT = 'fkUrlRedirect';

    /**
     * @var \Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface
     */
    protected $utilSanitize;

    /**
     * @var \Spryker\Zed\UrlStorage\Persistence\UrlStorageQueryContainerInterface
     */
    protected $queryContainer;

    /**
     * @var \Spryker\Shared\Kernel\Store
     */
    protected $store;

    /**
     * @var bool
     */
    protected $isSendingToQueue = true;

    /**
     * @param \Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceInterface $utilSanitize
     * @param \Spryker\Zed\UrlStorage\Persistence\UrlStorageQueryContainerInterface $queryContainer
     * @param \Spryker\Shared\Kernel\Store $store
     * @param bool $isSendingToQueue
     */
    public function __construct(UrlStorageToUtilSanitizeServiceInterface $utilSanitize, UrlStorageQueryContainerInterface $queryContainer, Store $store, $isSendingToQueue)
    {
        $this->utilSanitize = $utilSanitize;
        $this->queryContainer = $queryContainer;
        $this->store = $store;
        $this->isSendingToQueue = $isSendingToQueue;
    }

    /**
     * @param array $redirectIds
     *
     * @return void
     */
    public function publish(array $redirectIds)
    {
        $redirectEntities = $this->findRedirectEntities($redirectIds);
        $redirectStorageEntities = $this->findRedirectStorageEntitiesByIds($redirectIds);

        $this->storeData($redirectEntities, $redirectStorageEntities);
    }

    /**
     * @param array $redirectIds
     *
     * @return void
     */
    public function unpublish(array $redirectIds)
    {
        $redirectStorageEntities = $this->findRedirectStorageEntitiesByIds($redirectIds);
        foreach ($redirectStorageEntities as $redirectStorageEntity) {
            $redirectStorageEntity->delete();
        }
    }

    /**
     * @param array $spyRedirectEntities
     * @param array $spyRedirectStorageEntities
     *
     * @return void
     */
    protected function storeData(array $spyRedirectEntities, array $spyRedirectStorageEntities)
    {
        foreach ($spyRedirectEntities as $spyRedirectEntity) {
            $idUrl = $spyRedirectEntity[static::ID_URL_REDIRECT];
            if (isset($spyRedirectStorageEntities[$idUrl])) {
                $this->storeDataSet($spyRedirectEntity, $spyRedirectStorageEntities[$idUrl]);
            } else {
                $this->storeDataSet($spyRedirectEntity);
            }
        }
    }

    /**
     * @param array $spyRedirectEntity
     * @param \Orm\Zed\UrlStorage\Persistence\SpyUrlRedirectStorage|null $spyUrlRedirectStorage
     *
     * @return void
     */
    protected function storeDataSet(array $spyRedirectEntity, SpyUrlRedirectStorage $spyUrlRedirectStorage = null)
    {
        if ($spyUrlRedirectStorage === null) {
            $spyUrlRedirectStorage = new SpyUrlRedirectStorage();
        }

        $spyUrlRedirectStorage->setFkUrlRedirect($spyRedirectEntity[static::ID_URL_REDIRECT]);
        $spyUrlRedirectStorage->setData($this->utilSanitize->arrayFilterRecursive($spyRedirectEntity));
        $spyUrlRedirectStorage->setStore($this->getStoreName());
        $spyUrlRedirectStorage->setIsSendingToQueue($this->isSendingToQueue);
        $spyUrlRedirectStorage->save();
    }

    /**
     * @param array $redirectIds
     *
     * @return array
     */
    protected function findRedirectEntities(array $redirectIds)
    {
        return $this->queryContainer->queryRedirects($redirectIds)->find()->getData();
    }

    /**
     * @param array $redirectIds
     *
     * @return array
     */
    protected function findRedirectStorageEntitiesByIds(array $redirectIds)
    {
        return $this->queryContainer->queryRedirectStorageByIds($redirectIds)->find()->toKeyIndex(static::FK_URL_REDIRECT);
    }

    /**
     * @return string
     */
    protected function getStoreName()
    {
        return $this->store->getStoreName();
    }
}
