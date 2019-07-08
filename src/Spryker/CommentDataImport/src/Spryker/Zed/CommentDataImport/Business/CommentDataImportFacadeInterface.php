<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace Spryker\Zed\CommentDataImport\Business;

use Generated\Shared\Transfer\DataImporterConfigurationTransfer;
use Generated\Shared\Transfer\DataImporterReportTransfer;

interface CommentDataImportFacadeInterface
{
    /**
     * Specification:
     * - Imports Comments data.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\DataImporterConfigurationTransfer|null $dataImporterConfigurationTransfer
     *
     * @return \Generated\Shared\Transfer\DataImporterReportTransfer
     */
    public function importComment(?DataImporterConfigurationTransfer $dataImporterConfigurationTransfer = null): DataImporterReportTransfer;
}
