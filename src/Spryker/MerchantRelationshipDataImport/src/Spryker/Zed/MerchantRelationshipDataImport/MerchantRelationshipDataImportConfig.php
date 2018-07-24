<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace  Spryker\Zed\MerchantRelationshipDataImport;

use Generated\Shared\Transfer\DataImporterConfigurationTransfer;
use Spryker\Zed\DataImport\DataImportConfig;

class MerchantRelationshipDataImportConfig extends DataImportConfig
{
    public const IMPORT_TYPE_MERCHANT_RELATIONSHIP = 'merchant-relationship';

    /**
     * @return \Generated\Shared\Transfer\DataImporterConfigurationTransfer
     */
    public function getMerchantRelationshipDataImporterConfiguration(): DataImporterConfigurationTransfer
    {
        $moduleDataImportDirectory = $this->getModuleRoot() . 'data' . DIRECTORY_SEPARATOR . 'import' . DIRECTORY_SEPARATOR;

        return $this->buildImporterConfiguration($moduleDataImportDirectory . 'merchant_relationship.csv', static::IMPORT_TYPE_MERCHANT_RELATIONSHIP);
    }

    /**
     * @return string
     */
    protected function getModuleRoot(): string
    {
        $moduleRoot = realpath(
            __DIR__
            . DIRECTORY_SEPARATOR . '..'
            . DIRECTORY_SEPARATOR . '..'
            . DIRECTORY_SEPARATOR . '..'
            . DIRECTORY_SEPARATOR . '..'
        );

        return $moduleRoot . DIRECTORY_SEPARATOR;
    }
}
