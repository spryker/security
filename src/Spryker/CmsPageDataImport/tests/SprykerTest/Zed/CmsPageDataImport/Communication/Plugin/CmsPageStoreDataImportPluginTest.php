<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\CmsPageDataImport\Communication\Plugin;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\DataImporterConfigurationTransfer;
use Generated\Shared\Transfer\DataImporterReaderConfigurationTransfer;
use Generated\Shared\Transfer\DataImporterReportTransfer;
use Spryker\Zed\CmsPageDataImport\CmsPageDataImportConfig;
use Spryker\Zed\CmsPageDataImport\Communication\Plugin\CmsPageStoreDataImportPlugin;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group CmsPageDataImport
 * @group Communication
 * @group Plugin
 * @group CmsPageStoreDataImportPluginTest
 * Add your own group annotations below this line
 */
class CmsPageStoreDataImportPluginTest extends Unit
{
    /**
     * @var \SprykerTest\Zed\CmsPageDataImport\CmsPageDataImportCommunicationTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testImportImportsCmsPage(): void
    {
        $this->tester->ensureDatabaseTableCmsPageStoreIsEmpty();

        $dataImporterReaderConfigurationTransfer = new DataImporterReaderConfigurationTransfer();
        $dataImporterReaderConfigurationTransfer->setFileName(codecept_data_dir() . 'import/cms_page_store.csv');

        $dataImportConfigurationTransfer = new DataImporterConfigurationTransfer();
        $dataImportConfigurationTransfer->setReaderConfiguration($dataImporterReaderConfigurationTransfer);

        $cmsPageStoreDataImportPlugin = new CmsPageStoreDataImportPlugin();
        $dataImporterReportTransfer = $cmsPageStoreDataImportPlugin->import($dataImportConfigurationTransfer);

        $this->assertInstanceOf(DataImporterReportTransfer::class, $dataImporterReportTransfer);

        $this->tester->assertDatabaseTableCmsPageStoreContainsData();
    }

    /**
     * @return void
     */
    public function testGetImportTypeReturnsTypeOfImporter(): void
    {
        $cmsPageStoreDataImportPlugin = new CmsPageStoreDataImportPlugin();
        $this->assertSame(CmsPageDataImportConfig::IMPORT_TYPE_CMS_PAGE_STORE, $cmsPageStoreDataImportPlugin->getImportType());
    }
}
