<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationship\Business\Model;

use Generated\Shared\Transfer\MerchantRelationshipTransfer;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;
use Spryker\Zed\MerchantRelationship\Business\KeyGenerator\MerchantRelationshipKeyGeneratorInterface;
use Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipEntityManagerInterface;
use Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipRepositoryInterface;

class MerchantRelationshipWriter implements MerchantRelationshipWriterInterface
{
    use TransactionTrait;

    /**
     * @var \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipEntityManagerInterface
     */
    protected $entityManager;

    /**
     * @var \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipRepositoryInterface
     */
    protected $repository;

    /**
     * @var \Spryker\Zed\MerchantRelationship\Business\KeyGenerator\MerchantRelationshipKeyGeneratorInterface
     */
    protected $merchantRelationshipKeyGenerator;

    /**
     * @var \Spryker\Zed\MerchantRelationshipExtension\Dependency\Plugin\MerchantRelationshipPreDeletePluginInterface[]
     */
    protected $merchantRelationshipPreDeletePlugins;

    /**
     * @param \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipEntityManagerInterface $entityManager
     * @param \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipRepositoryInterface $repository
     * @param \Spryker\Zed\MerchantRelationship\Business\KeyGenerator\MerchantRelationshipKeyGeneratorInterface $merchantRelationshipKeyGenerator
     * @param \Spryker\Zed\MerchantRelationshipExtension\Dependency\Plugin\MerchantRelationshipPreDeletePluginInterface[] $merchantRelationshipPreDeletePlugins
     */
    public function __construct(
        MerchantRelationshipEntityManagerInterface $entityManager,
        MerchantRelationshipRepositoryInterface $repository,
        MerchantRelationshipKeyGeneratorInterface $merchantRelationshipKeyGenerator,
        array $merchantRelationshipPreDeletePlugins
    ) {
        $this->entityManager = $entityManager;
        $this->repository = $repository;
        $this->merchantRelationshipKeyGenerator = $merchantRelationshipKeyGenerator;
        $this->merchantRelationshipPreDeletePlugins = $merchantRelationshipPreDeletePlugins;
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer
     */
    public function create(MerchantRelationshipTransfer $merchantRelationTransfer): MerchantRelationshipTransfer
    {
        $merchantRelationTransfer
            ->requireFkMerchant()
            ->requireFkCompanyBusinessUnit();

        if (empty($merchantRelationTransfer->getMerchantRelationshipKey())) {
            $merchantRelationTransfer->setMerchantRelationshipKey(
                $this->merchantRelationshipKeyGenerator
                    ->generateMerchantRelationshipKey()
            );
        }

        $merchantRelationTransfer = $this->entityManager->saveMerchantRelationship($merchantRelationTransfer);
        $this->saveAssignedCompanyBusinessUnits($merchantRelationTransfer);

        return $merchantRelationTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer
     */
    public function update(MerchantRelationshipTransfer $merchantRelationTransfer): MerchantRelationshipTransfer
    {
        $merchantRelationTransfer->requireIdMerchantRelationship()
            ->requireFkMerchant()
            ->requireFkCompanyBusinessUnit();

        if (empty($merchantRelationTransfer->getMerchantRelationshipKey())) {
            $merchantRelationTransfer->setMerchantRelationshipKey(
                $this->merchantRelationshipKeyGenerator
                    ->generateMerchantRelationshipKey()
            );
        }

        $merchantRelationTransfer = $this->entityManager->saveMerchantRelationship($merchantRelationTransfer);
        $this->saveAssignedCompanyBusinessUnits($merchantRelationTransfer);

        return $merchantRelationTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationTransfer
     *
     * @return void
     */
    public function delete(MerchantRelationshipTransfer $merchantRelationTransfer): void
    {
        $merchantRelationTransfer->requireIdMerchantRelationship();

        $this->getTransactionHandler()->handleTransaction(function () use ($merchantRelationTransfer) {
            $this->executeMerchantRelationshipPreDeletePluginsTransaction($merchantRelationTransfer);
        });
        $this->entityManager->deleteMerchantRelationshipById($merchantRelationTransfer->getIdMerchantRelationship());
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationTransfer
     *
     * @return void
     */
    protected function saveAssignedCompanyBusinessUnits(MerchantRelationshipTransfer $merchantRelationTransfer): void
    {
        $currentIdAssignedCompanyBusinessUnits = $this->repository
            ->getIdAssignedBusinessUnitsByMerchantRelationshipId($merchantRelationTransfer->getIdMerchantRelationship());
        $requestedIdAssignedCompanyBusinessUnits = $this->getIdAssignedCompanyBusinessUnits($merchantRelationTransfer);

        $idAssignedCompanyBusinessUnitsToSave = array_diff($requestedIdAssignedCompanyBusinessUnits, $currentIdAssignedCompanyBusinessUnits);
        $idAssignedCompanyBusinessUnitsToDelete = array_diff($currentIdAssignedCompanyBusinessUnits, $requestedIdAssignedCompanyBusinessUnits);

        $this->entityManager->addAssignedCompanyBusinessUnits(
            $idAssignedCompanyBusinessUnitsToSave,
            $merchantRelationTransfer->getIdMerchantRelationship()
        );
        $this->entityManager->removeAssignedCompanyBusinessUnits(
            $idAssignedCompanyBusinessUnitsToDelete,
            $merchantRelationTransfer->getIdMerchantRelationship()
        );
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationTransfer
     *
     * @return int[]
     */
    protected function getIdAssignedCompanyBusinessUnits($merchantRelationTransfer): array
    {
        if (!$merchantRelationTransfer->getAssigneeCompanyBusinessUnits()) {
            return [];
        }

        $companyBusinessUnits = $merchantRelationTransfer->getAssigneeCompanyBusinessUnits()->getCompanyBusinessUnits();
        if (!$companyBusinessUnits) {
            return [];
        }

        $ids = [];
        foreach ($companyBusinessUnits as $companyBusinessUnit) {
            $ids[] = $companyBusinessUnit->getIdCompanyBusinessUnit();
        }

        return $ids;
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationTransfer
     *
     * @return void
     */
    protected function executeMerchantRelationshipPreDeletePluginsTransaction(MerchantRelationshipTransfer $merchantRelationTransfer): void
    {
        foreach ($this->merchantRelationshipPreDeletePlugins as $merchantRelationshipPreDeletePlugin) {
            $merchantRelationshipPreDeletePlugin->execute($merchantRelationTransfer);
        }
    }
}
