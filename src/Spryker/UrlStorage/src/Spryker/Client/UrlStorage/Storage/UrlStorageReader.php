<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\UrlStorage\Storage;

use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Generated\Shared\Transfer\UrlStorageTransfer;
use Spryker\Client\UrlStorage\Dependency\Client\UrlStorageToStorageInterface;
use Spryker\Client\UrlStorage\Dependency\Service\UrlStorageToSynchronizationServiceInterface;
use Spryker\Client\UrlStorage\UrlStorageConfig;
use Spryker\Shared\Kernel\Store;

class UrlStorageReader implements UrlStorageReaderInterface
{
    public const URL = 'url';

    /**
     * @var \Spryker\Client\UrlStorage\Dependency\Client\UrlStorageToStorageInterface
     */
    protected $storageClient;

    /**
     * @var \Spryker\Client\UrlStorage\Dependency\Service\UrlStorageToSynchronizationServiceInterface
     */
    protected $synchronizationService;

    /**
     * @var \Spryker\Client\UrlStorage\Dependency\Plugin\UrlStorageResourceMapperPluginInterface[]
     */
    protected $urlStorageResourceMapperPlugins;

    /**
     * @param \Spryker\Client\UrlStorage\Dependency\Client\UrlStorageToStorageInterface $storageClient
     * @param \Spryker\Client\UrlStorage\Dependency\Service\UrlStorageToSynchronizationServiceInterface $synchronizationService
     * @param \Spryker\Client\UrlStorage\Dependency\Plugin\UrlStorageResourceMapperPluginInterface[] $resourceMapperPlugins
     */
    public function __construct(UrlStorageToStorageInterface $storageClient, UrlStorageToSynchronizationServiceInterface $synchronizationService, array $resourceMapperPlugins)
    {
        $this->storageClient = $storageClient;
        $this->synchronizationService = $synchronizationService;
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
        $urlDetails = $this->getUrlFromStorage($url);
        if (!$urlDetails) {
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
     * @return \Generated\Shared\Transfer\UrlStorageTransfer|null
     */
    public function findUrlStorageTransferByUrl($url)
    {
        $urlDetails = $this->getUrlFromStorage($url);
        if (!$urlDetails) {
            return null;
        }

        return (new UrlStorageTransfer())->fromArray($urlDetails, true);
    }

    /**
     * @param string $url
     *
     * @return array
     */
    protected function getUrlFromStorage($url)
    {
        if (UrlStorageConfig::isCollectorCompatibilityMode()) {
            return $this->getCollectorUrlData($url);
        }

        $urlKey = $this->getUrlKey($url);
        $urlStorageData = $this->storageClient->get($urlKey);

        return $urlStorageData;
    }

    /**
     * @param string $url
     *
     * @return array|null
     */
    protected function getCollectorUrlData(string $url)
    {
        /** @var \Spryker\Client\Url\UrlClientInterface $urlClient */
        $clientLocatorClassName = '\Spryker\Client\Kernel\Locator';
        $urlClient = $clientLocatorClassName::getInstance()->url()->client();
        $localeName = Store::getInstance()->getCurrentLocale();
        $urlCollectorStorageTransfer = $urlClient->findUrl($url, $localeName);

        if (!$urlCollectorStorageTransfer) {
            return null;
        }

        $primaryUrlTransfer = null;
        $urlStorageLocaleUrlCollection = [];
        foreach ($urlCollectorStorageTransfer->getLocaleUrls() as $localeUrlTransfer) {
            $localeUrl = $localeUrlTransfer->toArray();
            $urlStorageLocaleUrlCollection[] = $localeUrl;

            if ($localeUrlTransfer->getUrl() === $url) {
                $primaryUrlTransfer = $localeUrlTransfer;
            }
        }

        if (!$primaryUrlTransfer) {
            return null;
        }

        $urlData = $primaryUrlTransfer->toArray();
        $urlData['locale_urls'] = $urlStorageLocaleUrlCollection;

        return $urlData;
    }

    /**
     * @param string $url
     *
     * @return string
     */
    protected function getUrlKey($url)
    {
        $synchronizationDataTransfer = new SynchronizationDataTransfer();
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
        $spyUrlTransfer = new UrlStorageTransfer();
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
