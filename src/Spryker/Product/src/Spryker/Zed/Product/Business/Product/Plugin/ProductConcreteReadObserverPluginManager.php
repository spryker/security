<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Product\Business\Product\Plugin;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Spryker\Zed\Product\Business\Product\Observer\ProductConcreteReadObserverInterface;

class ProductConcreteReadObserverPluginManager implements ProductConcreteReadObserverInterface
{
    /**
     * @var \Spryker\Zed\Product\Dependency\Plugin\ProductConcretePluginReadInterface[]
     */
    protected $readCollection;

    /**
     * @param \Spryker\Zed\Product\Dependency\Plugin\ProductConcretePluginReadInterface[] $readCollection
     */
    public function __construct(array $readCollection)
    {
        $this->readCollection = $readCollection;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function read(ProductConcreteTransfer $productConcreteTransfer)
    {
        foreach ($this->readCollection as $productConcretePluginRead) {
            $productConcreteTransfer = $productConcretePluginRead->read($productConcreteTransfer);
        }

        return $productConcreteTransfer;
    }
}
