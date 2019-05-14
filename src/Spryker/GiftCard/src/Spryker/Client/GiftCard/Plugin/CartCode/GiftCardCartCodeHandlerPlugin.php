<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\GiftCard\Plugin\CartCode;

use ArrayObject;
use Generated\Shared\Transfer\CartCodeOperationMessageTransfer;
use Generated\Shared\Transfer\GiftCardTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Client\CartCodeExtension\Dependency\Plugin\CartCodeHandlerPluginInterface;
use Spryker\Client\Kernel\AbstractPlugin;

class GiftCardCartCodeHandlerPlugin extends AbstractPlugin implements CartCodeHandlerPluginInterface
{
    public const CART_GIFT_CARD_APPLY_SUCCESSFUL = 'cart.giftcard.apply.successful';
    public const CART_GIFT_CARD_APPLY_FAILED = 'cart.giftcard.apply.failed';

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function addCandidate(QuoteTransfer $quoteTransfer, $code): QuoteTransfer
    {
        if ($this->hasCandidate($quoteTransfer, $code)) {
            return $quoteTransfer;
        }

        $giftCard = new GiftCardTransfer();
        $giftCard->setCode($code);

        $quoteTransfer->addGiftCard($giftCard);

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function removeCode(QuoteTransfer $quoteTransfer, $code): QuoteTransfer
    {
        $this->removeGiftCard($quoteTransfer, $code);
        $this->removeGiftCardPayment($quoteTransfer, $code);

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function removeGiftCard(QuoteTransfer $quoteTransfer, $code): QuoteTransfer
    {
        $giftCardTransferCollection = $quoteTransfer->getGiftCards();

        foreach ($giftCardTransferCollection as $index => $giftCardTransfer) {
            if ($giftCardTransfer->getCode() === $code) {
                $giftCardTransferCollection->offsetUnset($index);
            }
        }

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string|null $code
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function removeGiftCardPayment(QuoteTransfer $quoteTransfer, ?string $code = null): QuoteTransfer
    {
        foreach ($quoteTransfer->getPayments() as $index => $payment) {
            if ($payment->getGiftCard() && $code === null || $payment->getGiftCard()->getCode() === $code) {
                $quoteTransfer->getPayments()->offsetUnset($index);
            }
        }

        $quoteTransfer->setPayment(null);

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\CartCodeOperationMessageTransfer
     */
    public function getCartCodeOperationResult(QuoteTransfer $quoteTransfer, $code): CartCodeOperationMessageTransfer
    {
        $cartCodeCalculationResultTransfer = new CartCodeOperationMessageTransfer();
        $cartCodeCalculationResultTransfer->setIsSuccess(false);

        $giftCardApplySuccessMessageTransfer = $this->getGiftCardApplySuccessMessage($quoteTransfer, $code);
        if ($giftCardApplySuccessMessageTransfer) {
            $cartCodeCalculationResultTransfer
                ->setIsSuccess(true)
                ->setMessage($giftCardApplySuccessMessageTransfer);

            return $cartCodeCalculationResultTransfer;
        }

        $giftCardApplyFailedMessageTransfer = $this->getGiftCardApplyFailedMessage($quoteTransfer, $code);
        if ($giftCardApplyFailedMessageTransfer) {
            $cartCodeCalculationResultTransfer->setMessage($giftCardApplyFailedMessageTransfer);

            return $cartCodeCalculationResultTransfer;
        }

        return $cartCodeCalculationResultTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function clearAllCodes(QuoteTransfer $quoteTransfer): QuoteTransfer
    {
        $quoteTransfer->setGiftCards(new ArrayObject());

        $this->removeGiftCardPayment($quoteTransfer);

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return bool
     */
    protected function hasCandidate(QuoteTransfer $quoteTransfer, string $code): bool
    {
        foreach ($quoteTransfer->getGiftCards() as $giftCard) {
            if ($giftCard->getCode() === $code) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\MessageTransfer|null
     */
    protected function getGiftCardApplySuccessMessage(QuoteTransfer $quoteTransfer, string $code): ?MessageTransfer
    {
        foreach ($quoteTransfer->getGiftCards() as $giftCard) {
            if ($giftCard->getCode() !== $code) {
                continue;
            }

            $messageTransfer = new MessageTransfer();
            $messageTransfer->setValue(static::CART_GIFT_CARD_APPLY_SUCCESSFUL);

            return $messageTransfer;
        }

        return null;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\MessageTransfer|null
     */
    protected function getGiftCardApplyFailedMessage(QuoteTransfer $quoteTransfer, string $code): ?MessageTransfer
    {
        foreach ($quoteTransfer->getNotApplicableGiftCardCodes() as $giftCardCode) {
            if ($giftCardCode !== $code) {
                continue;
            }

            $messageTransfer = new MessageTransfer();
            $messageTransfer->setValue(static::CART_GIFT_CARD_APPLY_FAILED);

            return $messageTransfer;
        }

        return null;
    }
}
