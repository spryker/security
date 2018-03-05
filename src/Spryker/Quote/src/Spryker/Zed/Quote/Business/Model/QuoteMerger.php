<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Quote\Business\Model;

use ArrayObject;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\QuoteMergeRequestTransfer;
use Generated\Shared\Transfer\QuoteTransfer;

class QuoteMerger implements QuoteMergerInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteMergeRequestTransfer $quoteMergeRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function merge(QuoteMergeRequestTransfer $quoteMergeRequestTransfer): QuoteTransfer
    {
        $targetQuote = $this->mergeItems($quoteMergeRequestTransfer->getTargetQuote(), $quoteMergeRequestTransfer->getSourceQuote());

        return $targetQuote;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $targetQuote
     * @param \Generated\Shared\Transfer\QuoteTransfer $sourceQuote
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function mergeItems(QuoteTransfer $targetQuote, QuoteTransfer $sourceQuote)
    {
        $existingItems = $targetQuote->getItems();
        $cartIndex = $this->createQuoteItemIndex($existingItems);

        foreach ($sourceQuote->getItems() as $itemTransfer) {
            $itemIdentifier = $this->getItemIdentifier($itemTransfer);
            if (isset($cartIndex[$itemIdentifier])) {
                $this->increaseExistingItem($existingItems, $cartIndex[$itemIdentifier], $itemTransfer);
            } else {
                $existingItems->append($itemTransfer);
            }
        }

        return $targetQuote;
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $cartItems
     *
     * @return array
     */
    protected function createQuoteItemIndex(ArrayObject $cartItems)
    {
        $cartIndex = [];
        foreach ($cartItems as $key => $itemTransfer) {
            $itemIdentifier = $this->getItemIdentifier($itemTransfer);
            $cartIndex[$itemIdentifier] = $key;
        }

        return $cartIndex;
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return string
     */
    protected function getItemIdentifier(ItemTransfer $itemTransfer)
    {
        return $itemTransfer->getGroupKey() ?: $itemTransfer->getSku();
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $existingItems
     * @param int $index
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function increaseExistingItem($existingItems, $index, $itemTransfer)
    {
        $existingItemTransfer = $existingItems[$index];
        $changedQuantity = $existingItemTransfer->getQuantity() + $itemTransfer->getQuantity();

        $existingItemTransfer->setQuantity($changedQuantity);
    }
}
