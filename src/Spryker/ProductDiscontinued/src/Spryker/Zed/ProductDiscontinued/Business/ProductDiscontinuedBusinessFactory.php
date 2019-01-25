<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinued\Business;

use Psr\Log\LoggerInterface;
use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\ProductDiscontinued\Business\CartChangePreCheck\CartChangePreCheck;
use Spryker\Zed\ProductDiscontinued\Business\CartChangePreCheck\CartChangePreCheckInterface;
use Spryker\Zed\ProductDiscontinued\Business\Checkout\ProductDiscontinuedCheckoutPreConditionChecker;
use Spryker\Zed\ProductDiscontinued\Business\Checkout\ProductDiscontinuedCheckoutPreConditionCheckerInterface;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedPluginExecutor;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedPluginExecutorInterface;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedReader;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedReaderInterface;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedWriter;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedWriterInterface;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedDeactivator\ProductDiscontinuedDeactivator;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedDeactivator\ProductDiscontinuedDeactivatorInterface;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedNote\ProductDiscontinuedNoteWriter;
use Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedNote\ProductDiscontinuedNoteWriterInterface;
use Spryker\Zed\ProductDiscontinued\Business\ShoppingListCheck\ShoppingListAddItemPreCheck;
use Spryker\Zed\ProductDiscontinued\Business\ShoppingListCheck\ShoppingListAddItemPreCheckInterface;
use Spryker\Zed\ProductDiscontinued\Business\WishlistCheck\WishlistAddItemPreCheck;
use Spryker\Zed\ProductDiscontinued\Business\WishlistCheck\WishlistAddItemPreCheckInterface;
use Spryker\Zed\ProductDiscontinued\Dependency\Facade\ProductDiscontinuedToProductFacadeInterface;
use Spryker\Zed\ProductDiscontinued\ProductDiscontinuedDependencyProvider;

/**
 * @method \Spryker\Zed\ProductDiscontinued\ProductDiscontinuedConfig getConfig()
 * @method \Spryker\Zed\ProductDiscontinued\Persistence\ProductDiscontinuedEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\ProductDiscontinued\Persistence\ProductDiscontinuedRepositoryInterface getRepository()
 */
class ProductDiscontinuedBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedWriterInterface
     */
    public function createProductDiscontinuedWriter(): ProductDiscontinuedWriterInterface
    {
        return new ProductDiscontinuedWriter(
            $this->getEntityManager(),
            $this->getRepository(),
            $this->createProductDiscontinuedPluginExecutor(),
            $this->getConfig(),
            $this->getPreUnmarkProductDiscontinuePlugins()
        );
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedPluginExecutorInterface
     */
    public function createProductDiscontinuedPluginExecutor(): ProductDiscontinuedPluginExecutorInterface
    {
        return new ProductDiscontinuedPluginExecutor(
            $this->getPostProductDiscontinuePlugins(),
            $this->getPostDeleteProductDiscontinuedPlugins()
        );
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued\ProductDiscontinuedReaderInterface
     */
    public function createProductDiscontinuedReader(): ProductDiscontinuedReaderInterface
    {
        return new ProductDiscontinuedReader($this->getRepository());
    }

    /**
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedDeactivator\ProductDiscontinuedDeactivatorInterface
     */
    public function createProductDiscontinuedDeactivator(?LoggerInterface $logger = null): ProductDiscontinuedDeactivatorInterface
    {
        return new ProductDiscontinuedDeactivator(
            $this->getRepository(),
            $this->getEntityManager(),
            $this->getProductFacade(),
            $this->createProductDiscontinuedPluginExecutor(),
            $logger
        );
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\CartChangePreCheck\CartChangePreCheckInterface
     */
    public function createCartChangePreCheck(): CartChangePreCheckInterface
    {
        return new CartChangePreCheck($this->getRepository());
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\ShoppingListCheck\ShoppingListAddItemPreCheckInterface
     */
    public function createShoppingListAddItemPreCheck(): ShoppingListAddItemPreCheckInterface
    {
        return new ShoppingListAddItemPreCheck($this->getRepository());
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\WishlistCheck\WishlistAddItemPreCheckInterface
     */
    public function createWishlistAddItemPreCheck(): WishlistAddItemPreCheckInterface
    {
        return new WishlistAddItemPreCheck($this->getRepository());
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedNote\ProductDiscontinuedNoteWriterInterface
     */
    public function createProductDiscontinuedNoteWriter(): ProductDiscontinuedNoteWriterInterface
    {
        return new ProductDiscontinuedNoteWriter(
            $this->getEntityManager()
        );
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Business\Checkout\ProductDiscontinuedCheckoutPreConditionCheckerInterface
     */
    public function createProductDiscontinuedCheckoutPreConditionChecker(): ProductDiscontinuedCheckoutPreConditionCheckerInterface
    {
        return new ProductDiscontinuedCheckoutPreConditionChecker(
            $this->getRepository()
        );
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinued\Dependency\Facade\ProductDiscontinuedToProductFacadeInterface
     */
    public function getProductFacade(): ProductDiscontinuedToProductFacadeInterface
    {
        return $this->getProvidedDependency(ProductDiscontinuedDependencyProvider::FACADE_PRODUCT);
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinuedExtension\Dependency\Plugin\PostProductDiscontinuePluginInterface[]
     */
    public function getPostProductDiscontinuePlugins(): array
    {
        return $this->getProvidedDependency(ProductDiscontinuedDependencyProvider::PLUGINS_POST_PRODUCT_DISCONTINUE);
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinuedExtension\Dependency\Plugin\PostDeleteProductDiscontinuedPluginInterface[]
     */
    public function getPostDeleteProductDiscontinuedPlugins(): array
    {
        return $this->getProvidedDependency(ProductDiscontinuedDependencyProvider::PLUGINS_POST_DELETE_PRODUCT_DISCONTINUED);
    }

    /**
     * @return \Spryker\Zed\ProductDiscontinuedExtension\Dependency\Plugin\PreUnmarkProductDiscontinuedPluginInterface[]
     */
    public function getPreUnmarkProductDiscontinuePlugins(): array
    {
        return $this->getProvidedDependency(ProductDiscontinuedDependencyProvider::PLUGINS_PRE_UNMARK_PRODUCT_DISCONTINUED);
    }
}
