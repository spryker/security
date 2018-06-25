<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationship\Persistence;

use Generated\Shared\Transfer\MerchantRelationshipTransfer;

interface MerchantRelationshipRepositoryInterface
{
    /**
     * Specification:
     * - Returns a MerchantRelationshipTransfer by merchant relationship id.
     * - Returns null in case a record is not found.
     *
     * @api
     *
     * @param int $idMerchantRelationship
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipTransfer|null
     */
    public function getMerchantRelationshipById(int $idMerchantRelationship): ?MerchantRelationshipTransfer;

    /**
     * Specification:
     * - Returns ids of all assigned company business units by merchant relationship id.
     *
     * @param int $idMerchantRelationship
     *
     * @return int[]
     */
    public function getIdAssignedBusinessUnitsByMerchantRelationshipId(int $idMerchantRelationship): array;

    /**
     * Specification:
     * - Returns collection of MerchantRelationshipTransfer where business unit is assigned to.
     *
     * @param int $idBusinessUnit
     *
     * @return MerchantRelationshipTransfer[]
     */
    public function getMerchantRelationshipCollectionByIdAssignedBusinessUnit(int $idBusinessUnit): array;

    /**
     * @param string $candidate
     *
     * @return bool
     */
    public function hasKey(string $candidate): bool;

    /**
     * @return int
     */
    public function getMaxMerchantRelationshipId(): int;
}
