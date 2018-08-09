<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace Spryker\Zed\MerchantRelationshipProductListDataImport\Business\Model\Step;

use Orm\Zed\MerchantRelationship\Persistence\Map\SpyMerchantRelationshipTableMap;
use Orm\Zed\MerchantRelationship\Persistence\SpyMerchantRelationshipQuery;
use Spryker\Zed\DataImport\Business\Exception\EntityNotFoundException;
use Spryker\Zed\DataImport\Business\Exception\InvalidDataException;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\DataImportStepInterface;
use Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface;
use Spryker\Zed\MerchantRelationshipProductListDataImport\Business\Model\DataSet\MerchantRelationshipProductListDataSetInterface;

class MerchantRelationshipKeyToIdMerchantRelationshipStep implements DataImportStepInterface
{
    /**
     * @var int[]
     */
    protected $idMerchantRelationshipCache = [];

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @throws \Spryker\Zed\DataImport\Business\Exception\InvalidDataException
     * @throws \Spryker\Zed\DataImport\Business\Exception\EntityNotFoundException
     *
     * @return void
     */
    public function execute(DataSetInterface $dataSet): void
    {
        $merchantRelationshipKey = $dataSet[MerchantRelationshipProductListDataSetInterface::MERCHANT_RELATION_KEY];
        if (!$merchantRelationshipKey) {
            throw new InvalidDataException(sprintf('"%s" is required.', MerchantRelationshipProductListDataSetInterface::MERCHANT_RELATION_KEY));
        }

        if (!isset($this->idMerchantRelationshipCache[$merchantRelationshipKey])) {
            /** @var \Orm\Zed\MerchantRelationship\Persistence\SpyMerchantRelationshipQuery $merchantRelationshipQuery */
            $merchantRelationshipQuery = SpyMerchantRelationshipQuery::create()->select(SpyMerchantRelationshipTableMap::COL_ID_MERCHANT_RELATIONSHIP);
            /** @var int|null $idMerchantRelationship */
            $idMerchantRelationship = $merchantRelationshipQuery->findOneByMerchantRelationshipKey($merchantRelationshipKey);

            if (!$idMerchantRelationship) {
                throw new EntityNotFoundException(sprintf('Could not find Merchant Relationship by key "%s"', $merchantRelationshipKey));
            }
            $this->idMerchantRelationshipCache[$merchantRelationshipKey] = $idMerchantRelationship;
        }
        $dataSet[MerchantRelationshipProductListDataSetInterface::ID_MERCHANT_RELATIONSHIP] = $this->idMerchantRelationshipCache[$merchantRelationshipKey];
    }
}
