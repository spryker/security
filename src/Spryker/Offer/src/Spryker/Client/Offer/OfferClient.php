<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Offer;

use ArrayObject;
use Generated\Shared\Transfer\OfferListTransfer;
use Generated\Shared\Transfer\OfferResponseTransfer;
use Generated\Shared\Transfer\OfferTransfer;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\Offer\OfferFactory getFactory()
 */
class OfferClient extends AbstractClient implements OfferClientInterface
{
    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\OfferListTransfer $offerListTransfer
     *
     * @return \Generated\Shared\Transfer\OfferListTransfer
     */
    public function getOffers(OfferListTransfer $offerListTransfer): OfferListTransfer
    {
        $offerListTransfer = $this->getFactory()
            ->createZedStub()
            ->getOffers($offerListTransfer);

        $this->getFactory()
            ->createOfferHydrator()
            ->hydrateQuoteWithCustomer(
                $offerListTransfer->getOffers()
            );

        return $offerListTransfer;
    }

    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\OfferTransfer $offerTransfer
     *
     * @return \Generated\Shared\Transfer\OfferTransfer
     */
    public function getOfferById(OfferTransfer $offerTransfer): OfferTransfer
    {
        //todo: populate Customer form session to quote
        $offerTransfer = $this->getFactory()
            ->createZedStub()
            ->getOfferById($offerTransfer);

        $offerTransfers = $this->getFactory()
            ->createOfferHydrator()
            ->hydrateQuoteWithCustomer(
                new ArrayObject([$offerTransfer])
            );

        return $offerTransfers[0];
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\OfferTransfer $offerTransfer
     * @return \Generated\Shared\Transfer\OfferResponseTransfer
     */
    public function createOffer(OfferTransfer $offerTransfer): OfferResponseTransfer
    {
        $offerResponseTransfer = $this->getFactory()
            ->createZedStub()
            ->createOffer($offerTransfer);

        $offerTransfers = $this->getFactory()
            ->createOfferHydrator()
            ->hydrateQuoteWithCustomer(
                new ArrayObject([$offerResponseTransfer->getOffer()])
            );

        return $offerTransfers[0];
    }
}
