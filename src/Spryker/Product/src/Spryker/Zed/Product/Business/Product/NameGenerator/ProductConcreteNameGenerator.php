<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Product\Business\Product\NameGenerator;

use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;

class ProductConcreteNameGenerator implements ProductConcreteNameGeneratorInterface
{
    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @return string
     */
    public function getLocalizedProductConcreteName(ProductConcreteTransfer $productConcreteTransfer, LocaleTransfer $localeTransfer)
    {
        foreach ($productConcreteTransfer->getLocalizedAttributes() as $localizedAttribute) {
            if ($localizedAttribute->getLocale()->getIdLocale() === $localeTransfer->getIdLocale()) {
                return $localizedAttribute->getName();
            }
        }

        return $productConcreteTransfer->getSku();
    }
}
