<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Client\ContentStorage;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\ContentQueryTransfer;
use Spryker\Client\ContentStorage\ContentStorageClient;
use Spryker\Client\ContentStorage\ContentStorageDependencyProvider;
use Spryker\Client\ContentStorage\Dependency\Client\ContentStorageToStorageClientInterface;
use Spryker\Shared\ContentStorage\ContentStorageConfig;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Client
 * @group ContentStorage
 * @group ContentStorageClientTest
 * Add your own group annotations below this line
 */
class ContentStorageClientTest extends Unit
{
    /**
     * @var int
     */
    public const ID_CONTENT_ITEM = 1;

    /**
     * @var int
     */
    public const LOCALE = 'zh-CN';

    /**
     * @var \SprykerTest\Client\ContentStorage\ContentStorageClientTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testFindContentQueryByIdReturnsValidTransfer()
    {
        // Arrange
        $content = [
            ContentStorageConfig::TERM_KEY => 'KEY',
            ContentStorageConfig::CONTENT_KEY => ['CONTENT'],
        ];
        $this->setStorageReturn($content);

        // Act
        $systemUnderTest = $this->createContentStorageClient()
            ->findContentQueryById(static::ID_CONTENT_ITEM, static::LOCALE);

        // Assert
        $this->assertEquals(ContentQueryTransfer::class, get_class($systemUnderTest));
    }

    /**
     * @param array|null $returnedContent
     *
     * @return void
     */
    protected function setStorageReturn($returnedContent)
    {
        $contentToStorageBridge = $this->getMockBuilder(ContentStorageToStorageClientInterface::class)->getMock();
        $contentToStorageBridge->method('get')->willReturn($returnedContent);
        $this->tester->setDependency(ContentStorageDependencyProvider::CLIENT_STORAGE, $contentToStorageBridge);
    }

    /**
     * @return \Spryker\Client\ContentStorage\ContentStorageClientInterface
     */
    protected function createContentStorageClient()
    {
        return new ContentStorageClient();
    }
}
