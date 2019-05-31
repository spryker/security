<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule\ImportDataValidator;

use Generated\Shared\Transfer\PriceProductScheduleImportTransfer;
use Generated\Shared\Transfer\PriceProductScheduleListImportErrorTransfer;

class PriceDataValidator extends AbstractImportDataValidator
{
    protected const ERROR_MESSAGE_GROSS_AND_NET_VALUE = 'Gross and Net Amount must be a positive integer.';

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleImportTransfer $priceProductScheduleImportTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleListImportErrorTransfer|null
     */
    public function validatePriceProductScheduleImportTransfer(
        PriceProductScheduleImportTransfer $priceProductScheduleImportTransfer
    ): ?PriceProductScheduleListImportErrorTransfer {
        if ($this->isGrossPriceValid($priceProductScheduleImportTransfer) === false
            || $this->isNetPriceValid($priceProductScheduleImportTransfer) === false) {
            return $this->createPriceProductScheduleListImportErrorTransfer(
                $priceProductScheduleImportTransfer,
                static::ERROR_MESSAGE_GROSS_AND_NET_VALUE
            );
        }

        return null;
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleImportTransfer $priceProductScheduleImportTransfer
     *
     * @return bool
     */
    protected function isGrossPriceValid(PriceProductScheduleImportTransfer $priceProductScheduleImportTransfer): bool
    {
        return $priceProductScheduleImportTransfer->getGrossAmount() === null
            || (is_numeric($priceProductScheduleImportTransfer->getGrossAmount())
                && !is_float($priceProductScheduleImportTransfer->getGrossAmount())
                && $priceProductScheduleImportTransfer->getGrossAmount() > 0);
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleImportTransfer $priceProductScheduleImportTransfer
     *
     * @return bool
     */
    protected function isNetPriceValid(PriceProductScheduleImportTransfer $priceProductScheduleImportTransfer): bool
    {
        return $priceProductScheduleImportTransfer->getNetAmount() === null
            || is_numeric($priceProductScheduleImportTransfer->getNetAmount())
            && !is_float($priceProductScheduleImportTransfer->getNetAmount())
            && $priceProductScheduleImportTransfer->getNetAmount() > 0;
    }
}
