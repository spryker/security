<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteRequest\Persistence;

use Generated\Shared\Transfer\QuoteRequestTransfer;
use Generated\Shared\Transfer\QuoteRequestVersionTransfer;
use Orm\Zed\QuoteRequest\Persistence\SpyQuoteRequest;
use Orm\Zed\QuoteRequest\Persistence\SpyQuoteRequestVersion;
use Spryker\Zed\Kernel\Persistence\AbstractEntityManager;

/**
 * @method \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestPersistenceFactory getFactory()
 */
class QuoteRequestEntityManager extends AbstractEntityManager implements QuoteRequestEntityManagerInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestTransfer
     */
    public function createQuoteRequest(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestTransfer
    {
        $quoteRequestEntity = $this->getFactory()
            ->createQuoteRequestMapper()
            ->mapQuoteRequestTransferToQuoteRequestEntity($quoteRequestTransfer, new SpyQuoteRequest());

        $quoteRequestEntity->save();
        $quoteRequestTransfer->setIdQuoteRequest($quoteRequestEntity->getIdQuoteRequest());

        return $quoteRequestTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestTransfer
     */
    public function updateQuoteRequest(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestTransfer
    {
        $quoteRequestEntity = $this->getFactory()
            ->getQuoteRequestPropelQuery()
            ->filterByIdQuoteRequest($quoteRequestTransfer->getIdQuoteRequest())
            ->findOne();

        $quoteRequestEntity = $this->getFactory()
            ->createQuoteRequestMapper()
            ->mapQuoteRequestTransferToQuoteRequestEntity($quoteRequestTransfer, $quoteRequestEntity);

        $quoteRequestEntity->save();

        return $quoteRequestTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestVersionTransfer $quoteRequestVersionTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    public function createQuoteRequestVersion(QuoteRequestVersionTransfer $quoteRequestVersionTransfer): QuoteRequestVersionTransfer
    {
        $quoteRequestVersionEntity = $this->getFactory()
            ->createQuoteRequestVersionMapper()
            ->mapQuoteRequestVersionTransferToQuoteRequestVersionEntity($quoteRequestVersionTransfer, new SpyQuoteRequestVersion());

        $quoteRequestVersionEntity->save();
        $quoteRequestVersionTransfer->setIdQuoteRequestVersion($quoteRequestVersionEntity->getIdQuoteRequestVersion());

        return $quoteRequestVersionTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestVersionTransfer $quoteRequestVersionTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    public function updateQuoteRequestVersion(QuoteRequestVersionTransfer $quoteRequestVersionTransfer): QuoteRequestVersionTransfer
    {
        $quoteRequestVersionEntity = $this->getFactory()
            ->getQuoteRequestVersionPropelQuery()
            ->filterByIdQuoteRequestVersion($quoteRequestVersionTransfer->getIdQuoteRequestVersion())
            ->findOne();

        $quoteRequestVersionEntity = $this->getFactory()
            ->createQuoteRequestVersionMapper()
            ->mapQuoteRequestVersionTransferToQuoteRequestVersionEntity($quoteRequestVersionTransfer, $quoteRequestVersionEntity);

        $quoteRequestVersionEntity->save();

        return $quoteRequestVersionTransfer;
    }
}
