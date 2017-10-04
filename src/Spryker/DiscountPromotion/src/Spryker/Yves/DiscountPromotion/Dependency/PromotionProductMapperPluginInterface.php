<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\DiscountPromotion\Dependency;

use Generated\Shared\Transfer\QuoteTransfer;
use Symfony\Component\HttpFoundation\Request;

interface PromotionProductMapperPluginInterface
{

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Generated\Shared\Transfer\StorageProductTransfer[]
     */
    public function mapPromotionItemsFromProductStorage(QuoteTransfer $quoteTransfer, Request $request);

}
