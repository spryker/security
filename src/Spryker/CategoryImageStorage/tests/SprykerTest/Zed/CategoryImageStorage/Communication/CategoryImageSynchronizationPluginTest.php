<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\CategoryImageStorage\Communication;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\CategoryTransfer;
use Generated\Shared\Transfer\EventEntityTransfer;
use Orm\Zed\CategoryImage\Persistence\Map\SpyCategoryImageSetTableMap;
use Orm\Zed\CategoryImage\Persistence\Map\SpyCategoryImageSetToCategoryImageTableMap;
use Orm\Zed\CategoryImage\Persistence\Map\SpyCategoryImageTableMap;
use Orm\Zed\CategoryImage\Persistence\SpyCategoryImageQuery;
use Orm\Zed\CategoryImage\Persistence\SpyCategoryImageSetQuery;
use Orm\Zed\CategoryImageStorage\Persistence\SpyCategoryImageStorageQuery;
use Spryker\Client\Kernel\Container;
use Spryker\Client\Queue\QueueDependencyProvider;
use Spryker\Zed\CategoryImage\Dependency\CategoryImageEvents;
use Spryker\Zed\CategoryImageStorage\Communication\Plugin\Event\Listener\CategoryImagePublishStorageListener;
use Spryker\Zed\CategoryImageStorage\Communication\Plugin\Event\Listener\CategoryImageSetCategoryImageStorageListener;
use Spryker\Zed\CategoryImageStorage\Communication\Plugin\Event\Listener\CategoryImageSetStorageListener;
use Spryker\Zed\CategoryImageStorage\Communication\Plugin\Event\Listener\CategoryImageStorageListener;
use SprykerTest\Zed\CategoryImage\Helper\CategoryImageDataHelper;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group CategoryImageStorage
 * @group Communication
 * @group CategoryImageSynchronizationPluginTest
 * Add your own group annotations below this line
 */
class CategoryImageSynchronizationPluginTest extends Unit
{
    /**
     * @var \SprykerTest\Zed\CategoryImageStorage\CategoryImageStorageCommunicationTester
     */
    protected $tester;

    /**
     * @var \Generated\Shared\Transfer\CategoryTransfer
     */
    protected $categoryTransfer;

    /**
     * {@inheritdoc}
     */
    public function setUp()
    {
        parent::setUp();

        $this->tester->setDependency(QueueDependencyProvider::QUEUE_ADAPTERS, function (Container $container) {
            return [
                $container->getLocator()->rabbitMq()->client()->createQueueAdapter(),
            ];
        });

        $this->setUpData();
    }

    /**
     * @void
     *
     * @return void
     */
    public function testCategoryImagePublishStorageListenerStoreData(): void
    {
        SpyCategoryImageStorageQuery::create()->filterByFkCategory($this->categoryTransfer->getIdCategory())->delete();
        $beforeCount = SpyCategoryImageStorageQuery::create()->count();
        $categoryImagePublishStorageListener = new CategoryImagePublishStorageListener();
        $categoryImagePublishStorageListener->setFacade($this->tester->getFacade());

        $eventTransfers = [
            (new EventEntityTransfer())->setId($this->categoryTransfer->getIdCategory()),
        ];
        $categoryImagePublishStorageListener->handleBulk($eventTransfers, CategoryImageEvents::CATEGORY_IMAGE_CATEGORY_PUBLISH);

        $this->assertCategoryImageStorage($beforeCount);
    }

    /**
     * @return void
     */
    public function testCategoryImageSetToCategoryImageStorageListenerStoreData(): void
    {
        $beforeCount = SpyCategoryImageStorageQuery::create()->count();
        $categoryImageSetCategoryImageStorageListener = new CategoryImageSetCategoryImageStorageListener();
        $categoryImageSetCategoryImageStorageListener->setFacade($this->tester->getFacade());
        $categoryImageSetIds = $this->getCategoryImageSetIdsForCategory($this->categoryTransfer);

        $eventTransfers = [];
        foreach ($categoryImageSetIds as $idCategoryImageSet) {
            $eventTransfers[] = (new EventEntityTransfer())->setForeignKeys([
                SpyCategoryImageSetToCategoryImageTableMap::COL_FK_CATEGORY_IMAGE_SET => $idCategoryImageSet,
            ]);
        }

        $categoryImageSetCategoryImageStorageListener->handleBulk($eventTransfers, CategoryImageEvents::CATEGORY_IMAGE_CATEGORY_PUBLISH);

        $this->assertCategoryImageStorage($beforeCount);
    }

    /**
     * @return void
     */
    public function testCategoryImageSetStorageListenerStoreData(): void
    {
        SpyCategoryImageStorageQuery::create()->filterByFkCategory($this->categoryTransfer->getIdCategory())->delete();
        $beforeCount = SpyCategoryImageStorageQuery::create()->count();
        $categoryImageSetStorageListener = new CategoryImageSetStorageListener();
        $categoryImageSetStorageListener->setFacade($this->tester->getFacade());

        $eventTransfers = [
            (new EventEntityTransfer())->setForeignKeys([
                SpyCategoryImageSetTableMap::COL_FK_CATEGORY => $this->categoryTransfer->getIdCategory(),
            ]),
        ];
        $categoryImageSetStorageListener->handleBulk($eventTransfers, CategoryImageEvents::CATEGORY_IMAGE_CATEGORY_PUBLISH);

        $this->assertCategoryImageStorage($beforeCount);
    }

    /**
     * @return void
     */
    public function testCategoryImageStorageListenerStoreData(): void
    {
        SpyCategoryImageStorageQuery::create()->filterByFkCategory($this->categoryTransfer->getIdCategory())->delete();
        $beforeCount = SpyCategoryImageStorageQuery::create()->count();
        $categoryImagePublishStorageListener = new CategoryImageStorageListener();
        $categoryImagePublishStorageListener->setFacade($this->tester->getFacade());
        $idCategoryImageColletion = $this->getIdCategoryImageCollectionForCategory($this->categoryTransfer);

        $eventTransfers = [];
        foreach ($idCategoryImageColletion as $idCategoryImage) {
            $eventTransfers[] = (new EventEntityTransfer())->setId($idCategoryImage);
        }

        $categoryImagePublishStorageListener->handleBulk($eventTransfers, CategoryImageEvents::CATEGORY_IMAGE_CATEGORY_PUBLISH);

        $this->assertCategoryImageStorage($beforeCount);
    }

    /**
     * @return void
     */
    protected function setUpData(): void
    {
        $this->categoryTransfer = $this->tester->haveCategory();
        $this->tester->haveCategoryImageSetForCategory($this->categoryTransfer);
    }

    /**
     * @param int $beforeCount
     *
     * @return void
     */
    protected function assertCategoryImageStorage($beforeCount)
    {
        $afterCount = SpyCategoryImageStorageQuery::create()->count();
        $this->assertGreaterThan($beforeCount, $afterCount);
        $categoryImageStorage = SpyCategoryImageStorageQuery::create()
            ->orderByIdCategoryImageStorage()
            ->findOneByFkCategory($this->categoryTransfer->getIdCategory());
        $this->assertNotNull($categoryImageStorage);
        $data = $categoryImageStorage->getData();
        $this->assertSame(CategoryImageDataHelper::IMAGE_SET_NAME, $data['image_sets'][0]['name']);
    }

    /**
     * @param \Generated\Shared\Transfer\CategoryTransfer $categoryTransfer
     *
     * @return array
     */
    protected function getCategoryImageSetIdsForCategory(CategoryTransfer $categoryTransfer): array
    {
        return SpyCategoryImageSetQuery::create()
            ->filterByFkCategory($categoryTransfer->getIdCategory())
            ->select(SpyCategoryImageSetTableMap::COL_ID_CATEGORY_IMAGE_SET)
            ->find()
            ->getData();
    }

    /**
     * @param \Generated\Shared\Transfer\CategoryTransfer $categoryTransfer
     *
     * @return array
     */
    protected function getIdCategoryImageCollectionForCategory(CategoryTransfer $categoryTransfer): array
    {
        return SpyCategoryImageQuery::create()
            ->joinSpyCategoryImageSetToCategoryImage()
            ->useSpyCategoryImageSetToCategoryImageQuery()
            ->joinSpyCategoryImageSet()
            ->useSpyCategoryImageSetQuery()
            ->filterByFkCategory($categoryTransfer->getIdCategory())
            ->endUse()
            ->endUse()
            ->select(SpyCategoryImageTableMap::COL_ID_CATEGORY_IMAGE)
            ->find()
            ->getData();
    }
}
