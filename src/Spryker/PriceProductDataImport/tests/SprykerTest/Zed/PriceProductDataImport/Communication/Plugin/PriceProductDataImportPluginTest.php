<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace SprykerTest\Zed\PriceProductDataImport\Communication\Plugin;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\DataImporterConfigurationTransfer;
use Generated\Shared\Transfer\DataImporterReaderConfigurationTransfer;
use Generated\Shared\Transfer\DataImporterReportTransfer;
use Spryker\Zed\PriceProductDataImport\Communication\Plugin\PriceProductDataImportPlugin;
use Spryker\Zed\PriceProductDataImport\PriceProductDataImportConfig;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group PriceProductDataImport
 * @group Communication
 * @group Plugin
 * @group PriceProductDataImportPluginTest
 * Add your own group annotations below this line
 */
class PriceProductDataImportPluginTest extends Unit
{
    /**
     * @var \SprykerTest\Zed\PriceProductDataImport\PriceProductDataImportCommunicationTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testImportImportsPriceProduct(): void
    {
        $this->markTestSkipped('Need to fix transaction issue first.');
        $this->tester->ensureDatabaseTableIsEmpty();

        $dataImporterReaderConfigurationTransfer = new DataImporterReaderConfigurationTransfer();
        $dataImporterReaderConfigurationTransfer->setFileName(codecept_data_dir() . 'import/product_price.csv');

        $dataImportConfigurationTransfer = new DataImporterConfigurationTransfer();
        $dataImportConfigurationTransfer->setReaderConfiguration($dataImporterReaderConfigurationTransfer);

        $priceProductDataImportPlugin = new PriceProductDataImportPlugin();
        $dataImporterReportTransfer = $priceProductDataImportPlugin->import($dataImportConfigurationTransfer);

        $this->assertInstanceOf(DataImporterReportTransfer::class, $dataImporterReportTransfer);

        $this->tester->assertDatabaseTableContainsData();
    }

    /**
     * @return void
     */
    public function testGetImportTypeReturnsTypeOfImporter(): void
    {
        $priceProductDataImportPlugin = new PriceProductDataImportPlugin();
        $this->assertSame(PriceProductDataImportConfig::IMPORT_TYPE_PRODUCT_PRICE, $priceProductDataImportPlugin->getImportType());
    }
}
