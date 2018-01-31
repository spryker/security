<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\UrlStorage\Storage;

use Generated\Shared\Transfer\SpyUrlEntityTransfer;
use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Spryker\Client\UrlStorage\Dependency\Client\UrlStorageToStorageInterface;
use Spryker\Client\UrlStorage\Dependency\Service\UrlStorageToSynchronizationServiceInterface;
use Spryker\Shared\Kernel\Store;

class UrlStorageReader implements UrlStorageReaderInterface
{
    const URL = 'url';

    /**
     * @var \Spryker\Client\UrlStorage\Dependency\Client\UrlStorageToStorageInterface
     */
    protected $storageClient;

    /**
     * @var \Spryker\Client\UrlStorage\Dependency\Service\UrlStorageToSynchronizationServiceInterface
     */
    protected $synchronizationService;

    /**
     * @var \Spryker\Shared\Kernel\Store
     */
    protected $store;

    /**
     * @var \Spryker\Client\UrlStorage\Dependency\Plugin\UrlStorageResourceMapperPluginInterface[]
     */
    protected $urlStorageResourceMapperPlugins;

    /**
     * @param \Spryker\Client\UrlStorage\Dependency\Client\UrlStorageToStorageInterface $storageClient
     * @param \Spryker\Client\UrlStorage\Dependency\Service\UrlStorageToSynchronizationServiceInterface $synchronizationService
     * @param \Spryker\Shared\Kernel\Store $store
     * @param \Spryker\Client\UrlStorage\Dependency\Plugin\UrlStorageResourceMapperPluginInterface[] $resourceMapperPlugins
     */
    public function __construct(UrlStorageToStorageInterface $storageClient, UrlStorageToSynchronizationServiceInterface $synchronizationService, Store $store, array $resourceMapperPlugins)
    {
        $this->storageClient = $storageClient;
        $this->synchronizationService = $synchronizationService;
        $this->store = $store;
        $this->urlStorageResourceMapperPlugins = $resourceMapperPlugins;
    }

    /**
     * @param string $url
     * @param string $localeName
     *
     * @return array
     */
    public function matchUrl($url, $localeName)
    {
        $urlKey = $this->getUrlKey($url);
        $urlDetails = $this->storageClient->get($urlKey);
        if ($urlDetails === null) {
            return [];
        }

        $options = [
            'locale' => strtolower($localeName),
        ];
        $urlStorageResourceMapTransfer = $this->getUrlStorageResourceMapTransfer($urlDetails, $options);
        if ($urlStorageResourceMapTransfer === null) {
            return [];
        }

        $data = $this->storageClient->get($urlStorageResourceMapTransfer->getResourceKey());
        if ($data) {
            return [
                'type' => $urlStorageResourceMapTransfer->getType(),
                'data' => $data,
            ];
        }

        return [];
    }

    /**
     * @param string $url
     *
     * @return string
     */
    protected function getUrlKey($url)
    {
        $synchronizationDataTransfer = new SynchronizationDataTransfer();
        $synchronizationDataTransfer->setStore($this->store->getStoreName());
        $synchronizationDataTransfer->setReference(rawurldecode($url));

        return $this->synchronizationService->getStorageKeyBuilder(static::URL)->generateKey($synchronizationDataTransfer);
    }

    /**
     * @param array $urlDetails
     * @param array $options
     *
     * @return \Generated\Shared\Transfer\UrlStorageResourceMapTransfer|null
     */
    protected function getUrlStorageResourceMapTransfer(array $urlDetails, array $options = [])
    {
        $spyUrlTransfer = new SpyUrlEntityTransfer();
        $spyUrlTransfer->fromArray($urlDetails, true);

        foreach ($this->urlStorageResourceMapperPlugins as $urlStorageResourceMapperPlugin) {
            $pluginUrlStorageResourceMapTransfer = $urlStorageResourceMapperPlugin->map($spyUrlTransfer, $options);
            if (!empty($pluginUrlStorageResourceMapTransfer->getResourceKey())) {
                return $pluginUrlStorageResourceMapTransfer;
            }
        }

        return null;
    }
}
