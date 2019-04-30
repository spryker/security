<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PersistentCartShare\Business;

use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\ResourceShareRequestTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\PersistentCartShare\Business\PersistentCartShareBusinessFactory getFactory()
 */
class PersistentCartShareFacade extends AbstractFacade implements PersistentCartShareFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ResourceShareRequestTransfer $resourceShareRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function getQuoteForPreview(ResourceShareRequestTransfer $resourceShareRequestTransfer): QuoteResponseTransfer
    {
        return $this->getFactory()
            ->createQuoteReader()
            ->getQuoteForPreview($resourceShareRequestTransfer);
    }
}
