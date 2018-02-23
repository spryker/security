<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Client\Quote\StorageStrategy;

use Codeception\Test\Unit;
use Spryker\Client\Quote\Dependency\Client\QuoteToCustomerClientInterface;
use Spryker\Client\Quote\Exception\StorageStrategyNotFound;
use Spryker\Client\Quote\QuoteConfig;
use Spryker\Client\Quote\StorageStrategy\DatabaseStorageStrategy;
use Spryker\Client\Quote\StorageStrategy\SessionStorageStrategy;
use Spryker\Client\Quote\StorageStrategy\StorageStrategyProvider;
use Spryker\Client\Session\SessionClient;
use Spryker\Shared\Quote\QuoteConfig as SharedQuoteConfig;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Client
 * @group Quote
 * @group StorageStrategy
 * @group StorageStrategyProviderTest
 * Add your own group annotations below this line
 */
class StorageStrategyProviderTest extends Unit
{
    /**
     * @return void
     */
    public function testNotLoggedInCustomerCanUseSessionStorageOnly()
    {
        $customerClient = $this->createCustomerClientMock();
        $customerClient->method('isLoggedIn')->willReturn(false);

        $quoteConfig = $this->createQuoteConfigMock();
        $quoteConfig->method('getStorageStrategy')
            ->willReturn(SharedQuoteConfig::STORAGE_STRATEGY_DATABASE);

        $storageStrategyList = [
            $this->createSessionStorageStrategy(),
            $this->createDatabaseStorageStrategy($customerClient),
        ];

        $storageStrategyProvider = $this->createStorageStrategyProvider($quoteConfig, $storageStrategyList);
        $storageStrategy = $storageStrategyProvider->provideStorage();

        $this->assertInstanceOf(SessionStorageStrategy::class, $storageStrategy);
    }

    /**
     * @return void
     */
    public function testLoggedInCustomerCanUseSessionStorage()
    {
        $customerClient = $this->createCustomerClientMock();
        $customerClient->method('isLoggedIn')->willReturn(true);

        $quoteConfig = $this->createQuoteConfigMock();
        $quoteConfig->method('getStorageStrategy')
            ->willReturn(SharedQuoteConfig::STORAGE_STRATEGY_SESSION);

        $storageStrategyList = [
            $this->createSessionStorageStrategy(),
            $this->createDatabaseStorageStrategy($customerClient),
        ];

        $storageStrategyProvider = $this->createStorageStrategyProvider($quoteConfig, $storageStrategyList);
        $storageStrategy = $storageStrategyProvider->provideStorage();

        $this->assertInstanceOf(SessionStorageStrategy::class, $storageStrategy);
    }

    /**
     * @return void
     */
    public function testLoggedInCustomerCanUseDatabaseStorage()
    {
        $customerClient = $this->createCustomerClientMock();
        $customerClient->method('isLoggedIn')->willReturn(true);

        $quoteConfig = $this->createQuoteConfigMock();
        $quoteConfig->method('getStorageStrategy')
            ->willReturn(SharedQuoteConfig::STORAGE_STRATEGY_DATABASE);

        $storageStrategyList = [
            $this->createSessionStorageStrategy(),
            $this->createDatabaseStorageStrategy($customerClient),
        ];

        $storageStrategyProvider = $this->createStorageStrategyProvider($quoteConfig, $storageStrategyList);
        $storageStrategy = $storageStrategyProvider->provideStorage();

        $this->assertInstanceOf(DatabaseStorageStrategy::class, $storageStrategy);
    }

    /**
     * @return void
     */
    public function testUsingIncorrectStorageTypeLeadsToError()
    {
        $customerClient = $this->createCustomerClientMock();

        $quoteConfig = $this->createQuoteConfigMock();
        $quoteConfig->method('getStorageStrategy')
            ->willReturn('TestStorage');

        $storageStrategyList = [
            $this->createSessionStorageStrategy(),
            $this->createDatabaseStorageStrategy($customerClient),
        ];

        $this->expectException(StorageStrategyNotFound::class);

        $storageStrategyProvider = $this->createStorageStrategyProvider($quoteConfig, $storageStrategyList);
        $storageStrategyProvider->provideStorage();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Client\Quote\QuoteConfig
     */
    protected function createQuoteConfigMock()
    {
        return $this->getMockBuilder(QuoteConfig::class)
            ->getMock();
    }

    /**
     * @param \Spryker\Client\Quote\QuoteConfig $quoteConfig
     * @param \Spryker\Client\Quote\StorageStrategy\StorageStrategyInterface[] $storageStrategyList
     *
     * @return \Spryker\Client\Quote\StorageStrategy\StorageStrategyProviderInterface
     */
    protected function createStorageStrategyProvider(QuoteConfig $quoteConfig, array $storageStrategyList)
    {
        return new StorageStrategyProvider($quoteConfig, $storageStrategyList);
    }

    /**
     * @param \Spryker\Client\Quote\Dependency\Client\QuoteToCustomerClientInterface $customerClient
     *
     * @return \Spryker\Client\Quote\StorageStrategy\DatabaseStorageStrategy
     */
    protected function createDatabaseStorageStrategy(QuoteToCustomerClientInterface $customerClient)
    {
        return new DatabaseStorageStrategy($customerClient);
    }

    /**
     * @return \Spryker\Client\Quote\StorageStrategy\SessionStorageStrategy
     */
    protected function createSessionStorageStrategy()
    {
        $sessionContainer = new Session(new MockArraySessionStorage());
        $sessionClient = new SessionClient();
        $sessionClient->setContainer($sessionContainer);

        return new SessionStorageStrategy($sessionClient);
    }

    /**
     * @return \PHPUnit\Framework\MockObject\MockObject|\\Spryker\Client\Quote\Dependency\Client\QuoteToCustomerClientInterface
     */
    protected function createCustomerClientMock()
    {
        return $this->getMockBuilder(QuoteToCustomerClientInterface::class)
            ->getMock();
    }
}
