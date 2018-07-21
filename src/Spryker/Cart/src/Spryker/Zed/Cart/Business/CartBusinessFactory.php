<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Cart\Business;

use Spryker\Zed\Cart\Business\Model\Operation;
use Spryker\Zed\Cart\Business\Model\QuoteChangeObserver;
use Spryker\Zed\Cart\Business\Model\QuoteChangeObserverInterface;
use Spryker\Zed\Cart\Business\Model\QuoteValidator;
use Spryker\Zed\Cart\Business\StorageProvider\NonPersistentProvider;
use Spryker\Zed\Cart\Business\StorageProvider\StorageProviderInterface;
use Spryker\Zed\Cart\CartDependencyProvider;
use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;

/**
 * @method \Spryker\Zed\Cart\CartConfig getConfig()
 */
class CartBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\Cart\Business\Model\OperationInterface
     */
    public function createCartOperation()
    {
        $operation = new Operation(
            $this->createStorageProvider(),
            $this->getCalculatorFacade(),
            $this->getMessengerFacade(),
            $this->getItemExpanderPlugins(),
            $this->getCartPreCheckPlugins(),
            $this->getPostSavePlugins(),
            $this->getTerminationPlugins(),
            $this->getCartRemovalPreCheckPlugins()
        );

        $operation->setPreReloadLoadPlugins($this->getPreReloadItemsPlugins());

        return $operation;
    }

    /**
     * @return \Spryker\Zed\Cart\Business\Model\QuoteValidatorInterface
     */
    public function createQuoteValidator()
    {
        return new QuoteValidator(
            $this->createCartOperation(),
            $this->createQuoteChangeObserver(),
            $this->getMessengerFacade()
        );
    }

    /**
     * @return \Spryker\Zed\Cart\Business\StorageProvider\StorageProviderInterface
     */
    public function createStorageProvider(): StorageProviderInterface
    {
        return new NonPersistentProvider(
            $this->getCartAddItemStrategies(),
            $this->getCartRemoveItemStrategies()
        );
    }

    /**
     * @return \Spryker\Zed\Cart\Business\Model\QuoteChangeObserverInterface
     */
    public function createQuoteChangeObserver(): QuoteChangeObserverInterface
    {
        return new QuoteChangeObserver($this->getMessengerFacade(), $this->getQuoteChangeObserverPlugins());
    }

    /**
     * @return \Spryker\Zed\Cart\Dependency\Facade\CartToCalculationInterface
     */
    protected function getCalculatorFacade()
    {
        return $this->getProvidedDependency(CartDependencyProvider::FACADE_CALCULATION);
    }

    /**
     * @return \Spryker\Zed\Cart\Dependency\Facade\CartToMessengerInterface
     */
    protected function getMessengerFacade()
    {
        return $this->getProvidedDependency(CartDependencyProvider::FACADE_MESSENGER);
    }

    /**
     * @return \Spryker\Zed\Cart\Dependency\ItemExpanderPluginInterface[]
     */
    protected function getItemExpanderPlugins()
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_EXPANDER_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\Cart\Dependency\CartPreCheckPluginInterface[]
     */
    protected function getCartPreCheckPlugins()
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_PRE_CHECK_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\CartExtension\Dependency\Plugin\CartRemovalPreCheckPluginInterface[]
     */
    public function getCartRemovalPreCheckPlugins()
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_REMOVAL_PRE_CHECK_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\Cart\Dependency\PostSavePluginInterface[]
     */
    protected function getPostSavePlugins()
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_POST_SAVE_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\Cart\Dependency\PreReloadItemsPluginInterface[]
     */
    protected function getPreReloadItemsPlugins()
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_PRE_RELOAD_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\CartExtension\Dependency\Plugin\CartTerminationPluginInterface[]
     */
    protected function getTerminationPlugins()
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_TERMINATION_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\CartExtension\Dependency\Plugin\QuoteChangeObserverPluginInterface[]
     */
    protected function getQuoteChangeObserverPlugins(): array
    {
        return $this->getProvidedDependency(CartDependencyProvider::PLUGINS_QUOTE_CHANGE_OBSERVER);
    }

    /**
     * @return \Spryker\Zed\CartExtension\Dependency\Plugin\CartItemOperationStrategyInterface[]
     */
    protected function getCartAddItemStrategies(): array
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_ADD_ITEM_STRATEGIES);
    }

    /**
     * @return \Spryker\Zed\CartExtension\Dependency\Plugin\CartItemOperationStrategyInterface[]
     */
    protected function getCartRemoveItemStrategies(): array
    {
        return $this->getProvidedDependency(CartDependencyProvider::CART_REMOVE_ITEM_STRATEGIES);
    }
}
