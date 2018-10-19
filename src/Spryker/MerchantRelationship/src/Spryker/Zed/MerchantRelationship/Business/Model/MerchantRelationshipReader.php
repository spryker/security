<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationship\Business\Model;

use Generated\Shared\Transfer\MerchantRelationshipTransfer;
use Spryker\Zed\MerchantRelationship\Business\Exception\MerchantRelationshipNotFoundException;
use Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipRepositoryInterface;

class MerchantRelationshipReader implements MerchantRelationshipReaderInterface
{
    /**
     * @var \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipRepositoryInterface
     */
    protected $repository;

    /**
     * @param \Spryker\Zed\MerchantRelationship\Persistence\MerchantRelationshipRepositoryInterface $repository
     */
    public function __construct(MerchantRelationshipRepositoryInterface $repository)
    {
        $this->repository = $repository;
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @throws \Spryker\Zed\MerchantRelationship\Business\Exception\MerchantRelationshipNotFoundException
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer
     */
    public function getMerchantRelationshipById(MerchantRelationshipTransfer $merchantRelationshipTransfer): MerchantRelationshipTransfer
    {
        $merchantRelationshipTransfer->requireIdMerchantRelationship();

        $merchantRelationshipTransfer = $this->repository->getMerchantRelationshipById(
            $merchantRelationshipTransfer->getIdMerchantRelationship()
        );
        if (!$merchantRelationshipTransfer) {
            throw new MerchantRelationshipNotFoundException();
        }

        return $merchantRelationshipTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer|null
     */
    public function findMerchantRelationshipByKey(MerchantRelationshipTransfer $merchantRelationshipTransfer): ?MerchantRelationshipTransfer
    {
        $merchantRelationshipTransfer->requireMerchantRelationshipKey();

        $merchantRelationshipTransfer = $this->repository->findMerchantRelationshipByKey(
            $merchantRelationshipTransfer->getMerchantRelationshipKey()
        );

        if (!$merchantRelationshipTransfer) {
            return null;
        }

        return $merchantRelationshipTransfer;
    }

    /**
     * @param int $idMerchantRelationship
     *
     * @return int[]
     */
    public function getIdAssignedBusinessUnitsByMerchantRelationshipId(int $idMerchantRelationship): array
    {
        return $this->repository->getIdAssignedBusinessUnitsByMerchantRelationshipId($idMerchantRelationship);
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer|null
     */
    public function findMerchantRelationshipById(MerchantRelationshipTransfer $merchantRelationshipTransfer): ?MerchantRelationshipTransfer
    {
        $merchantRelationshipTransfer->requireIdMerchantRelationship();

        return $this->repository->getMerchantRelationshipById(
            $merchantRelationshipTransfer->getIdMerchantRelationship()
        );
    }
}
