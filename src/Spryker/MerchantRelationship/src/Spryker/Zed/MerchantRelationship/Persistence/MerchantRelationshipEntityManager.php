<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationship\Persistence;

use Generated\Shared\Transfer\MerchantRelationshipTransfer;
use Orm\Zed\MerchantRelationship\Persistence\SpyMerchantRelationshipToCompanyBusinessUnit;
use Propel\Runtime\Collection\ObjectCollection;
use Spryker\Zed\Kernel\Persistence\AbstractEntityManager;

/**
 * @method \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipPersistenceFactory getFactory()
 */
class MerchantRelationshipEntityManager extends AbstractEntityManager implements MerchantRelationshipEntityManagerInterface
{
    /**
     * Specification:
     * - Finds a merchant relationship by merchant relationship ID.
     * - Deletes the merchant relationship.
     *
     * @param int $idMerchantRelationship
     *
     * @return void
     */
    public function deleteMerchantRelationshipById(int $idMerchantRelationship): void
    {
        $this->getFactory()
            ->createMerchantRelationshipQuery()
            ->filterByIdMerchantRelationship($idMerchantRelationship)
            ->delete();
    }

    /**
     * Specification:
     * - Creates a merchant relationship.
     * - Finds a merchant relationship by MerchantRelationshipTransfer::idMerchantRelationship in the transfer.
     * - Updates fields in a merchant relationship entity.
     * - Persists the entity to DB.
     *
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer
     */
    public function saveMerchantRelationship(MerchantRelationshipTransfer $merchantRelationshipTransfer): MerchantRelationshipTransfer
    {
        $spyMerchantRelationship = $this->getFactory()
            ->createMerchantRelationshipQuery()
            ->filterByIdMerchantRelationship($merchantRelationshipTransfer->getIdMerchantRelationship())
            ->findOneOrCreate();

        $spyMerchantRelationship = $this->getFactory()
            ->createMerchantRelationshipMapper()
            ->mapMerchantRelationshipTransferToEntity($merchantRelationshipTransfer, $spyMerchantRelationship);

        $spyMerchantRelationship->save();

        $merchantRelationshipTransfer->setIdMerchantRelationship($spyMerchantRelationship->getIdMerchantRelationship());

        return $merchantRelationshipTransfer;
    }

    /**
     * {@inheritdoc}
     *
     * @param int[] $assignedCompanyBusinessUnitIds
     * @param int $idMerchantRelationship
     *
     * @return void
     */
    public function addAssignedCompanyBusinessUnits(array $assignedCompanyBusinessUnitIds, int $idMerchantRelationship): void
    {
        $entityCollection = new ObjectCollection();
        $entityCollection->setModel(SpyMerchantRelationshipToCompanyBusinessUnit::class);
        foreach ($assignedCompanyBusinessUnitIds as $idAssignedCompanyBusinessUnit) {
            $spyMerchantRelationshipToCompanyBusinessUnit = new SpyMerchantRelationshipToCompanyBusinessUnit();
            $spyMerchantRelationshipToCompanyBusinessUnit
                ->setFkCompanyBusinessUnit($idAssignedCompanyBusinessUnit)
                ->setFkMerchantRelationship($idMerchantRelationship);

            $entityCollection->append($spyMerchantRelationshipToCompanyBusinessUnit);
        }

        $entityCollection->save();
    }

    /**
     * {@inheritdoc}
     *
     * @param int[] $assignedCompanyBusinessUnitIds
     * @param int $idMerchantRelationship
     *
     * @return void
     */
    public function removeAssignedCompanyBusinessUnits(array $assignedCompanyBusinessUnitIds, int $idMerchantRelationship): void
    {
        if (empty($assignedCompanyBusinessUnitIds)) {
            return;
        }

        $this->getFactory()
            ->createMerchantRelationshipToCompanyBusinessUnitQuery()
            ->filterByFkMerchantRelationship($idMerchantRelationship)
            ->filterByFkCompanyBusinessUnit_In($assignedCompanyBusinessUnitIds)
            ->delete();
    }
}
