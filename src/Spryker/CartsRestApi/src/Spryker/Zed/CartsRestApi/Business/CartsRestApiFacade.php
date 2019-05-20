<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CartsRestApi\Business;

use Generated\Shared\Transfer\AssignGuestQuoteRequestTransfer;
use Generated\Shared\Transfer\QuoteCollectionTransfer;
use Generated\Shared\Transfer\QuoteCriteriaFilterTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\RestCartItemsAttributesTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @api
 *
 * @method \Spryker\Zed\CartsRestApi\Business\CartsRestApiBusinessFactory getFactory()
 * @method \Spryker\Zed\CartsRestApi\Persistence\CartsRestApiEntityManagerInterface getEntityManager()
 */
class CartsRestApiFacade extends AbstractFacade implements CartsRestApiFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @deprecated Will be removed in the next major.
     *
     * @return void
     */
    public function updateQuoteUuid(): void
    {
        $this->getFactory()->createQuoteUuidWriter()->updateQuotesUuid();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function findQuoteByUuid(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteReader()
            ->findQuoteByUuid($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteCriteriaFilterTransfer $quoteCriteriaFilterTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteCollectionTransfer
     */
    public function getQuoteCollection(QuoteCriteriaFilterTransfer $quoteCriteriaFilterTransfer): QuoteCollectionTransfer
    {
        return $this->getFactory()
            ->createQuoteReader()
            ->getQuoteCollection($quoteCriteriaFilterTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function updateQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteUpdater()
            ->updateQuote($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function createQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteCreator()
            ->createQuote($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function createSingleQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createSingleQuoteCreator()
            ->createSingleQuote($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function deleteQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteDeleter()
            ->deleteQuote($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function updateItem(RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteItemUpdater()
            ->changeItemQuantity($restCartItemsAttributesTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function addItem(RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteItemAdder()
            ->add($restCartItemsAttributesTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function deleteItem(RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteItemDeleter()
            ->remove($restCartItemsAttributesTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function addItemToGuestCart(RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createGuestQuoteItemAdder()
            ->addItemToGuestCart($restCartItemsAttributesTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\AssignGuestQuoteRequestTransfer $assignGuestQuoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function assignGuestCartToRegisteredCustomer(AssignGuestQuoteRequestTransfer $assignGuestQuoteRequestTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteUpdater()
            ->assignGuestCartToRegisteredCustomer($assignGuestQuoteRequestTransfer);
    }
}
