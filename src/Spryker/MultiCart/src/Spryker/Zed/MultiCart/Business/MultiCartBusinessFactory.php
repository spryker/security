<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MultiCart\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\MultiCart\Business\Activator\QuoteActivator;
use Spryker\Zed\MultiCart\Business\Activator\QuoteActivatorInterface;
use Spryker\Zed\MultiCart\Business\Model\QuoteNameResolver;
use Spryker\Zed\MultiCart\Business\Model\QuoteNameResolverInterface;
use Spryker\Zed\MultiCart\Business\Quote\MultiQuoteCreator;
use Spryker\Zed\MultiCart\Business\Quote\MultiQuoteCreatorInterface;
use Spryker\Zed\MultiCart\Business\Quote\QuoteWriter;
use Spryker\Zed\MultiCart\Business\Quote\QuoteWriterInterface;
use Spryker\Zed\MultiCart\Business\Reader\QuoteCollectionReader;
use Spryker\Zed\MultiCart\Business\Reader\QuoteCollectionReaderInterface;
use Spryker\Zed\MultiCart\Business\ResponseExpander\QuoteResponseExpander;
use Spryker\Zed\MultiCart\Business\ResponseExpander\QuoteResponseExpanderInterface;
use Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToMessengerFacadeInterface;
use Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToPersistentCartFacadeInterface;
use Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToQuoteFacadeInterface;
use Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToStoreFacadeInterface;
use Spryker\Zed\MultiCart\MultiCartDependencyProvider;

/**
 * @method \Spryker\Zed\MultiCart\MultiCartConfig getConfig()
 * @method \Spryker\Zed\MultiCart\Persistence\MultiCartEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\MultiCart\Persistence\MultiCartRepositoryInterface getRepository()
 */
class MultiCartBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\MultiCart\Business\Activator\QuoteActivatorInterface
     */
    public function createQuoteActivator(): QuoteActivatorInterface
    {
        return new QuoteActivator(
            $this->getQuoteFacade(),
            $this->getMessengerFacade()
        );
    }

    /**
     * @return \Spryker\Zed\MultiCart\Business\Model\QuoteNameResolverInterface
     */
    public function createQuoteNameResolver(): QuoteNameResolverInterface
    {
        return new QuoteNameResolver(
            $this->getRepository()
        );
    }

    /**
     * @return \Spryker\Zed\MultiCart\Business\ResponseExpander\QuoteResponseExpanderInterface
     */
    public function createQuoteResponseExpander(): QuoteResponseExpanderInterface
    {
        return new QuoteResponseExpander(
            $this->getQuoteFacade(),
            $this->getStoreFacade()
        );
    }

    /**
     * @return \Spryker\Zed\MultiCart\Business\Reader\QuoteCollectionReaderInterface
     */
    public function createQuoteCollectionReader(): QuoteCollectionReaderInterface
    {
        return new QuoteCollectionReader($this->getQuoteFacade());
    }

    /**
     * @return \Spryker\Zed\MultiCart\Business\Quote\QuoteWriterInterface
     */
    public function createQuoteWriter(): QuoteWriterInterface
    {
        return new QuoteWriter(
            $this->getRepository(),
            $this->getEntityManager(),
            $this->getMessengerFacade()
        );
    }

    /**
     * @return \Spryker\Zed\MultiCart\Business\Quote\MultiQuoteCreatorInterface
     */
    public function createMultiQuoteCreator(): MultiQuoteCreatorInterface
    {
        return new MultiQuoteCreator(
            $this->getPersistentCartFacade()
        );
    }

    /**
     * @return \Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToQuoteFacadeInterface
     */
    protected function getQuoteFacade(): MultiCartToQuoteFacadeInterface
    {
        return $this->getProvidedDependency(MultiCartDependencyProvider::FACADE_QUOTE);
    }

    /**
     * @return \Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToMessengerFacadeInterface
     */
    protected function getMessengerFacade(): MultiCartToMessengerFacadeInterface
    {
        return $this->getProvidedDependency(MultiCartDependencyProvider::FACADE_MESSENGER);
    }

    /**
     * @return \Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToStoreFacadeInterface
     */
    public function getStoreFacade(): MultiCartToStoreFacadeInterface
    {
        return $this->getProvidedDependency(MultiCartDependencyProvider::FACADE_STORE);
    }

    /**
     * @return \Spryker\Zed\MultiCart\Dependency\Facade\MultiCartToPersistentCartFacadeInterface
     */
    public function getPersistentCartFacade(): MultiCartToPersistentCartFacadeInterface
    {
        return $this->getProvidedDependency(MultiCartDependencyProvider::FACADE_PERSISTENT_CART);
    }
}
