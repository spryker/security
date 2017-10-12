<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Messenger\Business\Model;

use Generated\Shared\Transfer\FlashMessagesTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Spryker\Zed\Messenger\Dependency\Plugin\TranslationPluginInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionMessageTray extends BaseMessageTray implements MessageTrayInterface
{
    /**
     * @var \Symfony\Component\HttpFoundation\Session\SessionInterface
     */
    protected $session;

    /**
     * @param \Symfony\Component\HttpFoundation\Session\SessionInterface $session
     * @param \Spryker\Zed\Messenger\Dependency\Plugin\TranslationPluginInterface $translationPlugin
     */
    public function __construct(SessionInterface $session, TranslationPluginInterface $translationPlugin)
    {
        parent::__construct($translationPlugin);
        $this->session = $session;
    }

    /**
     * @param \Generated\Shared\Transfer\MessageTransfer $message
     *
     * @return void
     */
    public function addSuccessMessage(MessageTransfer $message)
    {
        $this->addToSession(
            MessageTrayInterface::FLASH_MESSAGES_SUCCESS,
            $this->translate(
                $message->getValue(),
                $message->getParameters()
            )
        );
    }

    /**
     * @param \Generated\Shared\Transfer\MessageTransfer $message
     *
     * @return void
     */
    public function addInfoMessage(MessageTransfer $message)
    {
        $this->addToSession(
            MessageTrayInterface::FLASH_MESSAGES_INFO,
            $this->translate(
                $message->getValue(),
                $message->getParameters()
            )
        );
    }

    /**
     * @param \Generated\Shared\Transfer\MessageTransfer $message
     *
     * @return void
     */
    public function addErrorMessage(MessageTransfer $message)
    {
        $this->addToSession(
            MessageTrayInterface::FLASH_MESSAGES_ERROR,
            $this->translate(
                $message->getValue(),
                $message->getParameters()
            )
        );
    }

    /**
     * @return \Generated\Shared\Transfer\FlashMessagesTransfer
     */
    public function getMessages()
    {
        $flashMessagesTransfer = $this->createFlashMessageTransfer();

        $sessionFlashBag = $this->session->getFlashBag();

        $flashMessagesTransfer->setErrorMessages([$sessionFlashBag->get(MessageTrayInterface::FLASH_MESSAGES_ERROR)]);
        $flashMessagesTransfer->setInfoMessages([$sessionFlashBag->get(MessageTrayInterface::FLASH_MESSAGES_INFO)]);
        $flashMessagesTransfer->setSuccessMessages([$sessionFlashBag->get(MessageTrayInterface::FLASH_MESSAGES_SUCCESS)]);

        return $flashMessagesTransfer;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return void
     */
    protected function addToSession($key, $value)
    {
        $this->session->getFlashBag()->add($key, $value);
    }

    /**
     * @return \Generated\Shared\Transfer\FlashMessagesTransfer
     */
    protected function createFlashMessageTransfer()
    {
        return new FlashMessagesTransfer();
    }
}
