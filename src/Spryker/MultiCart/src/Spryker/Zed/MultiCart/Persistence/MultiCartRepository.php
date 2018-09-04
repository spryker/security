<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MultiCart\Persistence;

use Generated\Shared\Transfer\FilterTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Orm\Zed\Quote\Persistence\Map\SpyQuoteTableMap;
use Propel\Runtime\ActiveQuery\Criteria;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;

/**
 * @method \Spryker\Zed\MultiCart\Persistence\MultiCartPersistenceFactory getFactory()
 */
class MultiCartRepository extends AbstractRepository implements MultiCartRepositoryInterface
{
    public const COL_ID_QUOTE = SpyQuoteTableMap::COL_ID_QUOTE;
    public const COL_IS_DEFAULT = SpyQuoteTableMap::COL_IS_DEFAULT;
    public const COL_NAME = SpyQuoteTableMap::COL_NAME;

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return array
     */
    public function findSimilarCustomerQuoteNames(QuoteTransfer $quoteTransfer): array
    {
        $customerReference = $quoteTransfer->getCustomer()->getCustomerReference();
        if ($quoteTransfer->getCustomerReference()) {
            $customerReference = $quoteTransfer->getCustomerReference();
        }
        $quoteQuery = $this->getFactory()
            ->createQuoteQuery()
            ->filterByName($quoteTransfer->getName() . '%', Criteria::LIKE)
            ->filterByCustomerReference($customerReference);
        if ($quoteTransfer->getIdQuote()) {
            $quoteQuery->filterByIdQuote($quoteTransfer->getIdQuote(), Criteria::NOT_EQUAL);
        }
        $quoteQuery->select([SpyQuoteTableMap::COL_NAME]);

        return $quoteQuery->find()->toArray();
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return bool
     */
    public function checkQuoteNameAvailability(QuoteTransfer $quoteTransfer): bool
    {
        $customerReference = $quoteTransfer->getCustomer()->getCustomerReference();
        if ($quoteTransfer->getCustomerReference()) {
            $customerReference = $quoteTransfer->getCustomerReference();
        }
        $quoteQuery = $this->getFactory()
            ->createQuoteQuery()
            ->filterByName($quoteTransfer->getName())
            ->filterByCustomerReference($customerReference);
        if ($quoteTransfer->getIdQuote()) {
            $quoteQuery->filterByIdQuote($quoteTransfer->getIdQuote(), Criteria::NOT_EQUAL);
        }
        $filterTransfer = new FilterTransfer();
        $filterTransfer->setOrderBy(SpyQuoteTableMap::COL_NAME);
        $filterTransfer->setOrderDirection(Criteria::DESC);

        return !$this->buildQueryFromCriteria($quoteQuery, $filterTransfer)->count();
    }

    /**
     * @param string $customerReference
     *
     * @return array
     */
    public function findCustomerQuoteData(string $customerReference): array
    {
        $quoteQuery = $this->getFactory()
            ->createQuoteQuery()
            ->filterByCustomerReference($customerReference);
        $quoteQuery->select([SpyQuoteTableMap::COL_ID_QUOTE, SpyQuoteTableMap::COL_IS_DEFAULT, SpyQuoteTableMap::COL_NAME]);

        return $quoteQuery->find()->toArray();
    }
}
