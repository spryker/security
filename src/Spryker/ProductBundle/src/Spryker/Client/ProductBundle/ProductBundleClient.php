<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductBundle;

use ArrayObject;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\ProductBundle\ProductBundleFactory getFactory()
 */
class ProductBundleClient extends AbstractClient implements ProductBundleClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $items
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $bundleItems
     *
     * @return array
     */
    public function getGroupedBundleItems(ArrayObject $items, ArrayObject $bundleItems)
    {
        return $this->getFactory()
            ->createProductBundleGrouper()
            ->getGroupedBundleItems($items, $bundleItems);
    }
}
