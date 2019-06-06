<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductScheduleGui\Dependency\Facade;

use Generated\Shared\Transfer\PriceProductScheduleCsvValidationResultTransfer;
use Generated\Shared\Transfer\PriceProductScheduledListImportRequestTransfer;
use Generated\Shared\Transfer\PriceProductScheduleListImportResponseTransfer;
use Generated\Shared\Transfer\PriceProductScheduleListResponseTransfer;
use Generated\Shared\Transfer\PriceProductScheduleListTransfer;
use Spryker\Zed\PriceProductScheduleGui\Communication\File\UploadedFile;

class PriceProductScheduleGuiToPriceProductScheduleFacadeBridge implements PriceProductScheduleGuiToPriceProductScheduleFacadeInterface
{
    /**
     * @var \Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleFacadeInterface
     */
    protected $priceProductScheduleFacade;

    /**
     * @param \Spryker\Zed\PriceProductSchedule\Business\PriceProductScheduleFacadeInterface $priceProductScheduleFacade
     */
    public function __construct($priceProductScheduleFacade)
    {
        $this->priceProductScheduleFacade = $priceProductScheduleFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduledListImportRequestTransfer $priceProductScheduledListImportRequest
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleListImportResponseTransfer
     */
    public function importPriceProductSchedules(
        PriceProductScheduledListImportRequestTransfer $priceProductScheduledListImportRequest
    ): PriceProductScheduleListImportResponseTransfer {
        return $this->priceProductScheduleFacade->importPriceProductSchedules(
            $priceProductScheduledListImportRequest
        );
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleListTransfer $priceProductScheduleListTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleListResponseTransfer
     */
    public function createPriceProductScheduleList(
        PriceProductScheduleListTransfer $priceProductScheduleListTransfer
    ): PriceProductScheduleListResponseTransfer {
        return $this->priceProductScheduleFacade->createPriceProductScheduleList($priceProductScheduleListTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleListTransfer $priceProductScheduleListTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleListResponseTransfer
     */
    public function updatePriceProductScheduleList(
        PriceProductScheduleListTransfer $priceProductScheduleListTransfer
    ): PriceProductScheduleListResponseTransfer {
        return $this->priceProductScheduleFacade->updatePriceProductScheduleList($priceProductScheduleListTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleListTransfer $priceProductScheduleListTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleListResponseTransfer
     */
    public function findPriceProductScheduleList(
        PriceProductScheduleListTransfer $priceProductScheduleListTransfer
    ): PriceProductScheduleListResponseTransfer {
        return $this->priceProductScheduleFacade->findPriceProductScheduleList($priceProductScheduleListTransfer);
    }

    /**
     * @param \Spryker\Zed\PriceProductScheduleGui\Communication\File\UploadedFile $uploadedFile
     * @param \Generated\Shared\Transfer\PriceProductScheduledListImportRequestTransfer $productScheduledListImportRequestTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduledListImportRequestTransfer
     */
    public function readPriceProductScheduleImportTransfersFromCsvFile(
        UploadedFile $uploadedFile,
        PriceProductScheduledListImportRequestTransfer $productScheduledListImportRequestTransfer
    ): PriceProductScheduledListImportRequestTransfer {
        return $this->priceProductScheduleFacade->readPriceProductScheduleImportTransfersFromCsvFile(
            $uploadedFile,
            $productScheduledListImportRequestTransfer
        );
    }

    /**
     * @param \Spryker\Zed\PriceProductScheduleGui\Communication\File\UploadedFile $uploadedFile
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleCsvValidationResultTransfer
     */
    public function validateCsvFile(UploadedFile $uploadedFile): PriceProductScheduleCsvValidationResultTransfer
    {
        return $this->priceProductScheduleFacade->validateCsvFile($uploadedFile);
    }
}
