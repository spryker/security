<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\GlossaryStorage\Communication\Plugin\Event\Listener;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\EventEntityTransfer;
use Generated\Shared\Transfer\KeyTranslationTransfer;
use Orm\Zed\Glossary\Persistence\Map\SpyGlossaryTranslationTableMap;
use Orm\Zed\Glossary\Persistence\SpyGlossaryTranslationQuery;
use Orm\Zed\GlossaryStorage\Persistence\SpyGlossaryStorageQuery;
use Spryker\Client\Kernel\Container;
use Spryker\Client\Queue\QueueDependencyProvider;
use Spryker\Zed\Glossary\Dependency\GlossaryEvents;
use Spryker\Zed\GlossaryStorage\Business\GlossaryStorageBusinessFactory;
use Spryker\Zed\GlossaryStorage\Business\GlossaryStorageFacade;
use Spryker\Zed\GlossaryStorage\Communication\Plugin\Event\Listener\GlossaryKeyStorageListener;
use Spryker\Zed\GlossaryStorage\Communication\Plugin\Event\Listener\GlossaryKeyStoragePublishListener;
use Spryker\Zed\GlossaryStorage\Communication\Plugin\Event\Listener\GlossaryKeyStorageUnpublishListener;
use Spryker\Zed\GlossaryStorage\Communication\Plugin\Event\Listener\GlossaryTranslationStorageListener;
use SprykerTest\Zed\GlossaryStorage\GlossaryStorageConfigMock;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group GlossaryStorage
 * @group Communication
 * @group Plugin
 * @group Event
 * @group Listener
 * @group GlossaryStorageListenerTest
 * Add your own group annotations below this line
 * @group QueueDependency
 */
class GlossaryStorageListenerTest extends Unit
{
    protected const ID_GLOSSARY = 1;

    /**
     * @var \SprykerTest\Zed\GlossaryStorage\GlossaryStorageCommunicationTester
     */
    protected $tester;

    /**
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();

        $this->tester->setDependency(QueueDependencyProvider::QUEUE_ADAPTERS, function (Container $container) {
            return [
                $container->getLocator()->rabbitMq()->client()->createQueueAdapter(),
            ];
        });
    }

    /**
     * @return void
     */
    public function testGlossaryKeyStorageListenerStoreData(): void
    {
        // Prepare
        $this->cleanUpGlossaryStorage(static::ID_GLOSSARY);
        $beforeCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey(static::ID_GLOSSARY)->count();

        $glossaryKeyStorageListener = new GlossaryKeyStorageListener();
        $glossaryKeyStorageListener->setFacade($this->getGlossaryStorageFacade());

        $eventTransfers = [
            (new EventEntityTransfer())->setId(static::ID_GLOSSARY),
        ];

        // Action
        $glossaryKeyStorageListener->handleBulk($eventTransfers, GlossaryEvents::GLOSSARY_KEY_PUBLISH);

        // Assert
        $this->assertGlossaryStorage(static::ID_GLOSSARY, $beforeCount);
    }

    /**
     * @return void
     */
    public function testGlossaryKeyStoragePublishListener(): void
    {
        // Prepare
        $this->cleanUpGlossaryStorage(static::ID_GLOSSARY);
        $beforeCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey(static::ID_GLOSSARY)->count();

        $glossaryKeyStorageListener = new GlossaryKeyStoragePublishListener();
        $glossaryKeyStorageListener->setFacade($this->getGlossaryStorageFacade());

        $eventTransfers = [
            (new EventEntityTransfer())->setId(static::ID_GLOSSARY),
        ];

        // Action
        $glossaryKeyStorageListener->handleBulk($eventTransfers, GlossaryEvents::GLOSSARY_KEY_PUBLISH);

        // Assert
        $this->assertGlossaryStorage(static::ID_GLOSSARY, $beforeCount);
    }

    /**
     * @return void
     */
    public function testGlossaryKeyStorageUnpublishListener(): void
    {
        // Prepare
        $glossaryKeyStorageListener = new GlossaryKeyStorageUnpublishListener();
        $glossaryKeyStorageListener->setFacade($this->getGlossaryStorageFacade());

        $eventTransfers = [
            (new EventEntityTransfer())->setId(static::ID_GLOSSARY),
        ];

        // Action
        $glossaryKeyStorageListener->handleBulk($eventTransfers, GlossaryEvents::GLOSSARY_KEY_UNPUBLISH);

        // Assert
        $this->assertSame(0, SpyGlossaryStorageQuery::create()->filterByFkGlossaryKey(static::ID_GLOSSARY)->count());
    }

    /**
     * @return void
     */
    public function testGlossaryTranslationStorageListenerStoreData(): void
    {
        // Prepare
        $this->cleanUpGlossaryStorage(static::ID_GLOSSARY);
        $beforeCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey(static::ID_GLOSSARY)->count();

        $glossaryTranslationStorageListener = new GlossaryTranslationStorageListener();
        $glossaryTranslationStorageListener->setFacade($this->getGlossaryStorageFacade());

        $eventTransfers = [
            (new EventEntityTransfer())->setForeignKeys([
                SpyGlossaryTranslationTableMap::COL_FK_GLOSSARY_KEY => static::ID_GLOSSARY,
            ]),
        ];

        // Action
        $glossaryTranslationStorageListener->handleBulk($eventTransfers, GlossaryEvents::ENTITY_SPY_GLOSSARY_TRANSLATION_CREATE);

        // Assert
        $this->assertGlossaryStorage(static::ID_GLOSSARY, $beforeCount);
    }

    /**
     * @return void
     */
    public function testGlossaryTranslationStorageListenerDeletesDataForInactiveTranslations(): void
    {
        // Prepare
        $glossaryTranslationStorageListener = new GlossaryTranslationStorageListener();
        $glossaryTranslationStorageListener->setFacade($this->getGlossaryStorageFacade());
        $idGlossaryKey = $this->tester->haveTranslation([
            KeyTranslationTransfer::GLOSSARY_KEY => 'test-key',
            KeyTranslationTransfer::LOCALES => [
                'en_US' => 'English',
                'de_DE' => 'Deutsch',
            ],
        ]);

        $eventTransfers = [
            (new EventEntityTransfer())->setForeignKeys([
                SpyGlossaryTranslationTableMap::COL_FK_GLOSSARY_KEY => $idGlossaryKey,
            ]),
        ];

        $glossaryTranslationStorageListener->handleBulk($eventTransfers, GlossaryEvents::ENTITY_SPY_GLOSSARY_TRANSLATION_CREATE);

        $beforeCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey($idGlossaryKey)->count();

        // Action
        $this->createGlossaryTranslationQuery()
            ->filterByFkGlossaryKey($idGlossaryKey)
            ->findOne()
            ->setIsActive(false)
            ->save();

        $glossaryTranslationStorageListener->handleBulk($eventTransfers, GlossaryEvents::ENTITY_SPY_GLOSSARY_KEY_UPDATE);

        // Assert
        $glossaryStorageCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey($idGlossaryKey)->count();
        $this->assertLessThan($beforeCount, $glossaryStorageCount);
    }

    /**
     * @return void
     */
    public function testGlossaryTranslationStorageListenerDeletesDataForEmptyTranslations(): void
    {
        // Prepare
        $glossaryTranslationStorageListener = new GlossaryTranslationStorageListener();
        $glossaryTranslationStorageListener->setFacade($this->getGlossaryStorageFacade());
        $idGlossaryKey = $this->tester->haveTranslation([
            KeyTranslationTransfer::GLOSSARY_KEY => 'test-key',
            KeyTranslationTransfer::LOCALES => [
                'en_US' => 'English',
                'de_DE' => 'Deutsch',
            ],
        ]);

        $eventTransfers = [
            (new EventEntityTransfer())->setForeignKeys([
                SpyGlossaryTranslationTableMap::COL_FK_GLOSSARY_KEY => $idGlossaryKey,
            ]),
        ];

        $glossaryTranslationStorageListener->handleBulk($eventTransfers, GlossaryEvents::ENTITY_SPY_GLOSSARY_TRANSLATION_CREATE);

        $beforeCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey($idGlossaryKey)->count();

        // Action
        $this->tester->haveTranslation([
            KeyTranslationTransfer::GLOSSARY_KEY => 'test-key',
            KeyTranslationTransfer::LOCALES => [
                'en_US' => '',
                'de_DE' => 'Deutsch',
            ],
        ]);

        $glossaryTranslationStorageListener->handleBulk($eventTransfers, GlossaryEvents::ENTITY_SPY_GLOSSARY_KEY_UPDATE);

        // Assert
        $glossaryStorageCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey($idGlossaryKey)->count();
        $this->assertLessThan($beforeCount, $glossaryStorageCount);
    }

    /**
     * @param int $idGlossaryKey
     *
     * @return void
     */
    protected function cleanUpGlossaryStorage(int $idGlossaryKey): void
    {
        SpyGlossaryStorageQuery::create()->filterByFkGlossaryKey($idGlossaryKey)->delete();
    }

    /**
     * @param int $idGlossaryKey
     * @param int $beforeCount
     *
     * @return void
     */
    protected function assertGlossaryStorage(int $idGlossaryKey, int $beforeCount): void
    {
        $glossaryStorageCount = $this->createGlossaryStorageQuery()->filterByFkGlossaryKey($idGlossaryKey)->count();
        $this->assertGreaterThan($beforeCount, $glossaryStorageCount);
        $spyGlossaryStorage = $this->createGlossaryStorageQuery()
            ->orderByFkGlossaryKey()
            ->filterByLocale('en_US')
            ->findOneByFkGlossaryKey($idGlossaryKey);
        $this->assertNotNull($spyGlossaryStorage);
        $this->assertSame('cart.remove.items.success', $spyGlossaryStorage->getData()['GlossaryKey']['key']);
        $this->assertSame('Products were removed successfully', $spyGlossaryStorage->getData()['value']);
    }

    /**
     * @return \Spryker\Zed\GlossaryStorage\Business\GlossaryStorageFacade
     */
    protected function getGlossaryStorageFacade(): GlossaryStorageFacade
    {
        $factory = new GlossaryStorageBusinessFactory();
        $factory->setConfig(new GlossaryStorageConfigMock());

        $facade = new GlossaryStorageFacade();
        $facade->setFactory($factory);

        return $facade;
    }

    /**
     * @return \Orm\Zed\Glossary\Persistence\SpyGlossaryTranslationQuery
     */
    protected function createGlossaryTranslationQuery(): SpyGlossaryTranslationQuery
    {
        return SpyGlossaryTranslationQuery::create()::create();
    }

    /**
     * @return \Orm\Zed\GlossaryStorage\Persistence\SpyGlossaryStorageQuery
     */
    protected function createGlossaryStorageQuery(): SpyGlossaryStorageQuery
    {
        return SpyGlossaryStorageQuery::create();
    }
}
