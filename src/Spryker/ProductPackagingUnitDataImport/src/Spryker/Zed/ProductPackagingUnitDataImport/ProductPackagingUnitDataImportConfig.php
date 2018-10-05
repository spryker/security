<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace Spryker\Zed\ProductPackagingUnitDataImport;

use Generated\Shared\Transfer\DataImporterConfigurationTransfer;
use Spryker\Zed\DataImport\DataImportConfig;

class ProductPackagingUnitDataImportConfig extends DataImportConfig
{
    public const IMPORT_TYPE_PRODUCT_PACKAGING_UNIT = 'product-packaging-unit';

    public const IMPORT_TYPE_PRODUCT_PACKAGING_UNIT_TYPE = 'product-packaging-unit-type';

    /**
     * @return \Generated\Shared\Transfer\DataImporterConfigurationTransfer
     */
    public function getProductPackagingUnitDataImporterConfiguration(): DataImporterConfigurationTransfer
    {
        return $this->buildImporterConfiguration(
            implode(DIRECTORY_SEPARATOR, [$this->getModuleDataImportDirectory(), 'product_packaging_unit.csv']),
            static::IMPORT_TYPE_PRODUCT_PACKAGING_UNIT
        );
    }

    /**
     * @return \Generated\Shared\Transfer\DataImporterConfigurationTransfer
     */
    public function getProductPackagingUnitTypeDataImporterConfiguration(): DataImporterConfigurationTransfer
    {
        return $this->buildImporterConfiguration(
            implode(DIRECTORY_SEPARATOR, [$this->getModuleDataImportDirectory(), 'product_packaging_unit_type.csv']),
            static::IMPORT_TYPE_PRODUCT_PACKAGING_UNIT_TYPE
        );
    }

    /**
     * @return string
     */
    protected function getModuleDataImportDirectory(): string
    {
        return implode(DIRECTORY_SEPARATOR, [
            $this->getModuleRoot(),
            'data',
            'import',
        ]);
    }

    /**
     * @return string
     */
    protected function getModuleRoot(): string
    {
        return realpath(implode(DIRECTORY_SEPARATOR, [
            __DIR__,
            '..',
            '..',
            '..',
            '..',
        ]));
    }
}
