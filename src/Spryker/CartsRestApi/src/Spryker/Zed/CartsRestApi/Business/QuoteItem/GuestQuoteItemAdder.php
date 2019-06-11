<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CartsRestApi\Business\QuoteItem;

use Generated\Shared\Transfer\CartItemRequestTransfer;
use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\QuoteCriteriaFilterTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\RestCartItemsAttributesTransfer;
use Spryker\Zed\CartsRestApi\Business\Quote\QuoteCreatorInterface;
use Spryker\Zed\CartsRestApi\Business\Quote\QuoteReaderInterface;
use Spryker\Zed\CartsRestApi\Business\QuoteItem\Mapper\QuoteItemMapperInterface;
use Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToStoreFacadeInterface;

class GuestQuoteItemAdder implements GuestQuoteItemAdderInterface
{
    /**
     * @var \Spryker\Zed\CartsRestApi\Business\Quote\QuoteReaderInterface
     */
    protected $quoteReader;

    /**
     * @var \Spryker\Zed\CartsRestApi\Business\QuoteItem\QuoteItemAdderInterface
     */
    protected $quoteItemAdder;

    /**
     * @var \Spryker\Zed\CartsRestApi\Business\Quote\QuoteCreatorInterface
     */
    protected $quoteCreator;

    /**
     * @var \Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\CartsRestApi\Business\QuoteItem\Mapper\QuoteItemMapperInterface
     */
    protected $quoteItemMapper;

    /**
     * @param \Spryker\Zed\CartsRestApi\Business\Quote\QuoteReaderInterface $quoteReader
     * @param \Spryker\Zed\CartsRestApi\Business\QuoteItem\QuoteItemAdderInterface $quoteItemAdder
     * @param \Spryker\Zed\CartsRestApi\Business\Quote\QuoteCreatorInterface $quoteCreator
     * @param \Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\CartsRestApi\Business\QuoteItem\Mapper\QuoteItemMapperInterface $quoteItemMapper
     */
    public function __construct(
        QuoteReaderInterface $quoteReader,
        QuoteItemAdderInterface $quoteItemAdder,
        QuoteCreatorInterface $quoteCreator,
        CartsRestApiToStoreFacadeInterface $storeFacade,
        QuoteItemMapperInterface $quoteItemMapper
    ) {
        $this->quoteReader = $quoteReader;
        $this->quoteItemAdder = $quoteItemAdder;
        $this->quoteCreator = $quoteCreator;
        $this->storeFacade = $storeFacade;
        $this->quoteItemMapper = $quoteItemMapper;
    }

    /**
     * @deprecated Use addToGuestCart() instead.
     *
     * @param \Generated\Shared\Transfer\RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function addItemToGuestCart(RestCartItemsAttributesTransfer $restCartItemsAttributesTransfer): QuoteResponseTransfer
    {
        $restCartItemsAttributesTransfer
            ->requireSku()
            ->requireCustomerReference();

        $cartItemRequestTransfer = (new CartItemRequestTransfer())
            ->fromArray($restCartItemsAttributesTransfer->toArray(), true);

        return $this->addToGuestCart($cartItemRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CartItemRequestTransfer $cartItemRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function addToGuestCart(CartItemRequestTransfer $cartItemRequestTransfer): QuoteResponseTransfer
    {
        $cartItemRequestTransfer
            ->requireSku()
            ->requireCustomer();

        $cartItemRequestTransfer->getCustomer()->requireCustomerReference();

        $customerQuoteCollection = $this->quoteReader->getQuoteCollection(
            (new QuoteCriteriaFilterTransfer())
                ->setCustomerReference($cartItemRequestTransfer->getCustomer()->getCustomerReference())
        );

        $customerQuotes = $customerQuoteCollection->getQuotes();

        if (!$customerQuotes->count()) {
            return $this->createGuestQuote($cartItemRequestTransfer);
        }

        $cartItemRequestTransfer->setQuoteUuid($customerQuotes[0]->getUuid());

        return $this->addItem($cartItemRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CartItemRequestTransfer $cartItemRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function createGuestQuote(CartItemRequestTransfer $cartItemRequestTransfer): QuoteResponseTransfer
    {
        $quoteTransfer = $this->createQuoteTransfer();

        $customerTransfer = (new CustomerTransfer())
            ->setCustomerReference($cartItemRequestTransfer->getCustomer()->getCustomerReference());

        $quoteTransfer->setCustomer($customerTransfer);

        $quoteResponseTransfer = $this->quoteCreator->createQuote($quoteTransfer);

        if (!$quoteResponseTransfer->getIsSuccessful()) {
            return $quoteResponseTransfer;
        }

        $cartItemRequestTransfer->setQuoteUuid($quoteResponseTransfer->getQuoteTransfer()->getUuid());

        return $this->addItem($cartItemRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CartItemRequestTransfer $cartItemRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function addItem(CartItemRequestTransfer $cartItemRequestTransfer): QuoteResponseTransfer
    {
        return $this->quoteItemAdder->addToCart($cartItemRequestTransfer);
    }

    /**
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function createQuoteTransfer(): QuoteTransfer
    {
        $currentStore = $this->storeFacade->getCurrentStore();

        return (new QuoteTransfer())
            ->setStore($currentStore)
            ->setCurrency((new CurrencyTransfer())
                ->setCode($currentStore->getDefaultCurrencyIsoCode()));
    }
}
