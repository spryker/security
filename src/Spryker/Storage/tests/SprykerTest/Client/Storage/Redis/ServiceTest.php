<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Client\Storage\Redis;

use Codeception\Test\Unit;
use Predis\ClientInterface;
use Spryker\Client\Storage\Redis\Service;
use Spryker\Client\Storage\StorageClient;
use Spryker\Shared\Storage\StorageConstants;
use Symfony\Component\HttpFoundation\Request;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Client
 * @group Storage
 * @group Redis
 * @group ServiceTest
 * Add your own group annotations below this line
 */
class ServiceTest extends Unit
{
    /**
     * @var array
     */
    protected $fixtures = [
        'multi' => [
            'key1' => 'value1',
            'key2' => 'value2',
            'key3' => 'value3',
        ],
    ];

    /**
     * @var array
     */
    protected $expected = [
        'multi' => [
            'kv:key1' => 'value1',
            'kv:key2' => 'value2',
            'kv:key3' => 'value3',
        ],
    ];

    /**
     * @var \Spryker\Client\Storage\Redis\Service
     */
    protected $redisService;

    /**
     * @var \Predis\ClientInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientMock;

    /**
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();
        $this->setupServerVariable();
    }

    /**
     * @return void
     */
    protected function _before()
    {
        $this->clientMock = $this->getMockBuilder(ClientInterface::class)
            ->setMethods([
                'keys',
                'getProfile',
                'getOptions',
                'connect',
                'disconnect',
                'createCommand',
                'executeCommand',
                'getConnection',
                '__call',
            ])
            ->getMock();

        $this->redisService = new Service(
            $this->clientMock
        );
    }

    /**
     * @return void
     */
    public function testGetAllKeysTriggersRightCommand()
    {
        $this->clientMock->expects($this->once())->method('keys')->with($this->equalTo('kv:*'));

        $this->redisService->getAllKeys();
    }

    /**
     * @return void
     */
    public function testGetKeysPassesPatternCorrectly()
    {
        $this->clientMock->expects($this->once())->method('keys')->with($this->equalTo('kv:aPattern*'));

        $this->redisService->getKeys('aPattern*');
    }

    /**
     * @return void
     */
    public function testGetMultiWithEmptyKeys()
    {
        $requestedKeys = [];

        $this->assertSame($requestedKeys, $this->redisService->getMulti($requestedKeys));
    }

    /**
     * @return void
     */
    public function testGet()
    {
        $key = 'key';
        $value = 'value';

        $storageClient = new StorageClient();
        $storageClient->set($key, $value);

        $this->assertEquals($value, $storageClient->get($key));
    }

    /**
     * @return void
     */
    public function testGetMultiCached()
    {
        $storageClient = new StorageClient();
        $storageClient->setMulti($this->fixtures['multi']);

        //Check 0: Returns expected keys and values w/o cache
        $result = $storageClient->getMulti(array_keys($this->fixtures['multi']));
        $this->assertEquals($this->expected['multi'], $result);

        $request = $this->createRequest();
        $storageClient->persistCacheForRequest($request);

        //Reset cache
        $storageClient->setCachedKeys(null);
        $storageClient->resetCache();

        //Warm-up cache
        $storageClient->getMulti(['non-existing-key']);
        $cachedKeys = $storageClient->getCachedKeys();
        $this->assertNotEmpty($cachedKeys);

        //Check 1: Cache is used
        $cachedKeys = array_intersect_key($this->fixtures['multi'], $storageClient->getCachedKeys());
        $this->assertEquals(array_keys($this->fixtures['multi']), array_keys($cachedKeys));

        //Check 2: Returns expected keys and values
        $this->assertEquals($this->expected['multi'], $storageClient->getMulti(array_keys($this->fixtures['multi'])));
    }

    /**
     * @return void
     */
    public function testGetMultiReplaceStrategy()
    {
        $this->testMultiKeyStrategy(
            StorageConstants::STORAGE_CACHE_STRATEGY_REPLACE,
            $this->fixtures['multi'],
            $this->expected['multi']
        );
    }

    /**
     * @return void
     */
    public function testGetMultiIncrementalStrategy()
    {
        $this->testMultiKeyStrategy(
            StorageConstants::STORAGE_CACHE_STRATEGY_INCREMENTAL,
            $this->fixtures['multi'],
            $this->expected['multi']
        );
    }

    /**
     * @return void
     */
    public function testGetSingleReplaceStrategy()
    {
        $this->testSingleKeyStrategy(
            StorageConstants::STORAGE_CACHE_STRATEGY_INCREMENTAL,
            'test.replace.key',
            'test.replace.value'
        );
    }

    /**
     * @return void
     */
    public function testGetSingleIncrementalStrategy()
    {
        $this->testSingleKeyStrategy(
            StorageConstants::STORAGE_CACHE_STRATEGY_INCREMENTAL,
            'test.incremental.key',
            'test.incremental.value'
        );
    }

    /**
     * @param string $strategyName
     * @param array $fixtures
     * @param array $expected
     *
     * @return void
     */
    protected function testMultiKeyStrategy($strategyName, $fixtures, $expected)
    {
        $request = $this->createRequest();

        $storageClient = new StorageClient();
        $storageClient->setMulti($fixtures);
        $this->assertEquals($expected, $storageClient->getMulti(array_keys($fixtures)));

        $storageClient->persistCacheForRequest($request, $strategyName);
        $storageClient->setCachedKeys(null);
        $this->assertEquals($expected, $storageClient->getMulti(array_keys($fixtures)));
    }

    /**
     * @param string $strategyName
     * @param string $key
     * @param string $value
     *
     * @return void
     */
    protected function testSingleKeyStrategy($strategyName, $key, $value)
    {
        $request = $this->createRequest();

        $storageClient = new StorageClient();
        $storageClient->set($key, $value);
        $this->assertEquals($value, $storageClient->get($key));

        $storageClient->persistCacheForRequest($request, $strategyName);
        $storageClient->setCachedKeys(null);
        $this->assertEquals($value, $storageClient->get($key));
    }

    /**
     * @return void
     */
    protected function setupServerVariable()
    {
        $_SERVER['SERVER_NAME'] = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
        $_SERVER['REQUEST_URI'] = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/test/url';
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Request
     */
    protected function createRequest()
    {
        $request = new Request([], [], [], [], [], $_SERVER);

        return $request;
    }

    /**
     * @group YYY
     */
    public function testGetMultiShouldReturnDataInTheSameOrderAsInput()
    {
        $bufferedDataInjectedThroughTheAss = [
            'a' => 'A',
            'b' => 'B',
            'c' => 'C',
            'd' => 'D',
            'e' => 'E',
            'f' => 'F',
        ];
        StorageClient::$cachedKeys = [];
        $redisService = $this->getMockBuilder(Service::class)
            ->disableOriginalConstructor()
            ->setMethods(['getMulti'])
            ->getMock();
        $redisService->method('getMulti')->willReturnCallback(function ($arguments) {
            $result = [];
            foreach ($arguments as $key) {
                $result['kv:'.$key] = '_' . strtoupper($key);
            }
            return $result;
        });
        $storageClient = $this->getMockBuilder(StorageClient::class)
            ->setMethods(['loadCacheKeysAndValues', 'getService'])
            ->getMock();
        $storageClient->method('getService')->willReturn($redisService);
        $storageClientReflection = new \ReflectionClass($storageClient);
        $bufferedValuesRef = $storageClientReflection->getProperty('bufferedValues');
        $bufferedValuesRef->setAccessible(true);
        $bufferedValuesRef->setValue($bufferedDataInjectedThroughTheAss);
        /** @var StorageClient $storageClient */
        $result = $storageClientReflection->getMethod('getMulti')->invoke($storageClient, ['z', 'c', 'b', 'd']);

        $this->assertEquals(['kv:z' => '_Z', 'kv:c' => 'C', 'kv:b' => 'B', 'kv:d' => 'D'], $result);
    }
}
