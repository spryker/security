<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ZedRequest;

use Generated\Shared\Transfer\LocaleTransfer;
use Spryker\Client\Kernel\AbstractClient;
use Spryker\Shared\Kernel\Store;
use Spryker\Shared\Kernel\Transfer\TransferInterface;

/**
 * @method \Spryker\Client\ZedRequest\ZedRequestFactory getFactory()
 */
class ZedRequestClient extends AbstractClient implements ZedRequestClientInterface
{
    /**
     * @return \Spryker\Client\ZedRequest\Client\ZedClient|\Spryker\Shared\ZedRequest\Client\AbstractZedClientInterface
     */
    private function getClient()
    {
        return $this->getFactory()
            ->getCashedClient();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $url
     * @param \Spryker\Shared\Kernel\Transfer\TransferInterface $object
     * @param array|int|null $requestOptions
     *
     * @return \Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function call($url, TransferInterface $object, $requestOptions = null)
    {
        $localeName = Store::getInstance()->getCurrentLocale();
        $localeTransfer = new LocaleTransfer();
        $localeTransfer->setLocaleName($localeName);

        $this->getClient()->addMetaTransfer('locale', $localeTransfer);

        $this->applyMetaData($object);

        return $this->getClient()->call($url, $object, $requestOptions);
    }

    /**
     * @api
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    public function getLastResponseInfoMessages()
    {
        return $this->getFactory()
            ->createMessenger()
            ->getLastResponseInfoMessages();
    }

    /**
     * @api
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    public function getLastResponseErrorMessages()
    {
        return $this->getFactory()
            ->createMessenger()
            ->getLastResponseErrorMessages();
    }

    /**
     * @api
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    public function getLastResponseSuccessMessages()
    {
        return $this->getFactory()
            ->createMessenger()
            ->getLastResponseSuccessMessages();
    }

    /**
     * {@inheritdoc}
     *
     *
     * @api
     *
     * @return void
     */
    public function addFlashMessagesFromLastZedRequest()
    {
        $this->getFactory()
            ->createMessenger()
            ->addFlashMessagesFromLastZedRequest();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    public function getAllResponsesInfoMessages(): array
    {
        return $this->getFactory()
            ->createMessenger()
            ->getAllResponsesInfoMessages();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    public function getAllResponsesErrorMessages(): array
    {
        return $this->getFactory()
            ->createMessenger()
            ->getAllResponsesErrorMessages();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    public function getAllResponsesSuccessMessages(): array
    {
        return $this->getFactory()
            ->createMessenger()
            ->getAllResponsesSuccessMessages();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return void
     */
    public function addAllResponseMessagesToMessenger(): void
    {
        $this->getFactory()
            ->createMessenger()
            ->addAllResponseMessagesToMessenger();
    }

    /**
     * @param \Spryker\Shared\Kernel\Transfer\TransferInterface $requestTransfer
     *
     * @return void
     */
    protected function applyMetaData(TransferInterface $requestTransfer)
    {
        $plugins = $this->getFactory()->getMetaDataProviderPlugins();

        foreach ($plugins as $key => $plugin) {
            $this->getClient()->addMetaTransfer(
                $key,
                $plugin->getRequestMetaData($requestTransfer)
            );
        }
    }
}
