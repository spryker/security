<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Wishlist\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\Wishlist\Business\Model\Reader;
use Spryker\Zed\Wishlist\Business\Model\Writer;
use Spryker\Zed\Wishlist\Business\Transfer\WishlistTransferMapper;
use Spryker\Zed\Wishlist\WishlistDependencyProvider;

/**
 * @method \Spryker\Zed\Wishlist\Persistence\WishlistQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\Wishlist\WishlistConfig getConfig()
 */
class WishlistBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\Wishlist\Business\Model\ReaderInterface
     */
    public function createReader()
    {
        return new Reader(
            $this->getQueryContainer(),
            $this->getProductQueryContainer(),
            $this->createTransferMapper()
        );
    }

    /**
     * @return \Spryker\Zed\Wishlist\Business\Model\WriterInterface
     */
    public function createWriter()
    {
        return new Writer(
            $this->getQueryContainer(),
            $this->createReader(),
            $this->getProductFacade()
        );
    }

    /**
     * @return \Spryker\Zed\Wishlist\Business\Transfer\WishlistTransferMapperInterface
     */
    protected function createTransferMapper()
    {
        return new WishlistTransferMapper(
            $this->getItemExpanderPlugins()
        );
    }

    /**
     * @return \Spryker\Zed\Wishlist\Dependency\QueryContainer\WishlistToProductBridge
     */
    protected function getProductQueryContainer()
    {
        return $this->getProvidedDependency(WishlistDependencyProvider::QUERY_CONTAINER_PRODUCT);
    }

    /**
     * @return \Spryker\Zed\Wishlist\Dependency\Plugin\ItemExpanderPluginInterface[]
     */
    protected function getItemExpanderPlugins()
    {
        return $this->getProvidedDependency(WishlistDependencyProvider::PLUGINS_ITEM_EXPANDER);
    }

    /**
     * @return \Spryker\Zed\Wishlist\Dependency\Facade\WishlistToProductInterface
     */
    protected function getProductFacade()
    {
        return $this->getProvidedDependency(WishlistDependencyProvider::FACADE_PRODUCT);
    }
}
