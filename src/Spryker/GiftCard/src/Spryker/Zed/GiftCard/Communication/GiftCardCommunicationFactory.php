<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\GiftCard\Communication;

use Exception;
use Spryker\Zed\Kernel\Communication\AbstractCommunicationFactory;

/**
 * @method \Spryker\Zed\GiftCard\GiftCardConfig getConfig()
 * @method \Spryker\Zed\GiftCard\Persistence\GiftCardQueryContainer getQueryContainer()
 */
class GiftCardCommunicationFactory extends AbstractCommunicationFactory
{
    /**
     * @throws \Exception
     *
     * @return void
     */
    public function createGiftCardTable()
    {
        //TODO add table view for giftcards zed backend
        //TODO implement
        throw new Exception('not implemented');
    }
}
