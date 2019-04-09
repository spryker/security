<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Client\Redis\Adapter;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\RedisConfigurationTransfer;
use ReflectionProperty;
use Spryker\Client\Redis\Adapter\Factory\RedisAdapterFactoryInterface;
use Spryker\Client\Redis\Adapter\RedisAdapterInterface;
use Spryker\Client\Redis\Adapter\RedisAdapterProvider;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Client
 * @group Redis
 * @group Adapter
 * @group RedisAdapterProviderTest
 * Add your own group annotations below this line
 */
class RedisAdapterProviderTest extends Unit
{
    protected const CONNECTION_KEY_SESSION = 'session connection key';
    protected const CONNECTION_KEY_STORAGE = 'storage connection key';

    /**
     * @var \Spryker\Client\Redis\Adapter\RedisAdapterProviderInterface
     */
    protected $connectionProvider;

    /**
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();

        $this->connectionProvider = new RedisAdapterProvider(
            $this->createClientAdapterFactoryMock()
        );
    }

    /**
     * @expectedException \Spryker\Client\Redis\Exception\ConnectionNotInitializedException
     *
     * @return void
     */
    public function testThrowsExceptionWhenConnectionNotInitialized(): void
    {
        $this->resetConnectionPool();

        $this->connectionProvider->getAdapter(static::CONNECTION_KEY_SESSION);
    }

    /**
     * @return void
     */
    public function testCanSetUpNewConnection(): void
    {
        $this->resetConnectionPool();

        $this->connectionProvider->setupConnection(static::CONNECTION_KEY_SESSION, new RedisConfigurationTransfer());
        $connection = $this->connectionProvider->getAdapter(static::CONNECTION_KEY_SESSION);

        $this->assertInstanceOf(RedisAdapterInterface::class, $connection);
    }

    /**
     * @return void
     */
    public function testCanPrepareDifferentConnectionsForDifferentConnectionKeys(): void
    {
        $this->resetConnectionPool();

        $this->connectionProvider->setupConnection(static::CONNECTION_KEY_SESSION, new RedisConfigurationTransfer());
        $this->connectionProvider->setupConnection(static::CONNECTION_KEY_STORAGE, new RedisConfigurationTransfer());

        $sessionConnection = $this->connectionProvider->getAdapter(static::CONNECTION_KEY_SESSION);
        $storageConnection = $this->connectionProvider->getAdapter(static::CONNECTION_KEY_STORAGE);

        $this->assertNotSame($sessionConnection, $storageConnection);
    }

    /**
     * @return void
     */
    public function testDoesNotSetUpNewConnectionForTheSameConnectionKey(): void
    {
        $this->resetConnectionPool();

        $configurationTransfer = new RedisConfigurationTransfer();

        $this->connectionProvider->setupConnection(static::CONNECTION_KEY_SESSION, $configurationTransfer);
        $connection1 = $this->connectionProvider->getAdapter(static::CONNECTION_KEY_SESSION);

        $this->connectionProvider->setupConnection(static::CONNECTION_KEY_SESSION, $configurationTransfer);

        $connection2 = $this->connectionProvider->getAdapter(static::CONNECTION_KEY_SESSION);

        $this->assertSame($connection1, $connection2);
    }

    /**
     * @return void
     */
    protected function resetConnectionPool(): void
    {
        $connectionPoolReflection = new ReflectionProperty(RedisAdapterProvider::class, 'clientPool');
        $connectionPoolReflection->setAccessible(true);
        $connectionPoolReflection->setValue(null, []);
    }

    /**
     * @return \PHPUnit\Framework\MockObject\MockObject|\Spryker\Client\Redis\Adapter\Factory\RedisAdapterFactoryInterface
     */
    protected function createClientAdapterFactoryMock()
    {
        $clientAdapterFactory = ($this->createMock(RedisAdapterFactoryInterface::class));
        $clientAdapterFactory->method('create')
            ->willReturnCallback(function () {
                    return $this->createMock(RedisAdapterInterface::class);
            });

        return $clientAdapterFactory;
    }
}
