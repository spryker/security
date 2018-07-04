<?php

/**
 * MIT License
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */
namespace Spryker\Zed\PriceProductDataImport\Business\Model\Step;

use Orm\Zed\Currency\Persistence\Map\SpyCurrencyTableMap;
use Orm\Zed\Currency\Persistence\SpyCurrencyQuery;
use Spryker\Zed\DataImport\Business\Exception\EntityNotFoundException;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\DataImportStepInterface;
use Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface;
use Spryker\Zed\PriceProductDataImport\Business\Model\DataSet\PriceProductDataSet;

class CurrencyToIdCurrencyStep implements DataImportStepInterface
{
    /**
     * @var array
     */
    protected $idCurrencyCache = [];

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @throws \Spryker\Zed\DataImport\Business\Exception\EntityNotFoundException
     *
     * @return void
     */
    public function execute(DataSetInterface $dataSet): void
    {
        $currencyCode = $dataSet[PriceProductDataSet::KEY_CURRENCY];
        if (!isset($this->idCurrencyCache[$currencyCode])) {
            $currencyQuery = new SpyCurrencyQuery();
            $idCurrency = $currencyQuery
                ->select(SpyCurrencyTableMap::COL_ID_CURRENCY)
                ->findOneByCode($currencyCode);

            if (!$idCurrency) {
                throw new EntityNotFoundException(sprintf('Could not find currency by code "%s"', $currencyCode));
            }

            $this->idCurrencyCache[$currencyCode] = $idCurrency;
        }

        $dataSet[PriceProductDataSet::ID_CURRENCY] = $this->idCurrencyCache[$currencyCode];
    }
}