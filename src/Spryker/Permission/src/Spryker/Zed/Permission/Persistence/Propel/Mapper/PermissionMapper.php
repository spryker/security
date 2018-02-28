<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Permission\Persistence\Propel\Mapper;

use Generated\Shared\Transfer\PermissionCollectionTransfer;
use Generated\Shared\Transfer\PermissionTransfer;
use Orm\Zed\Permission\Persistence\SpyPermission;
use Traversable;

class PermissionMapper
{
    /**
     * @param \Traversable|\Orm\Zed\Permission\Persistence\SpyPermission[] $permissionEntityCollection
     * @param \Generated\Shared\Transfer\PermissionCollectionTransfer $permissionCollectionTransfer
     *
     * @return \Generated\Shared\Transfer\PermissionCollectionTransfer
     */
    public function mapPermissionEntityCollectionToTransferCollection(
        Traversable $permissionEntityCollection,
        PermissionCollectionTransfer $permissionCollectionTransfer
    ) {
        foreach ($permissionEntityCollection as $permissionEntity) {
            $permissionTransfer = $this->mapPermissionEntityToTransfer($permissionEntity, new PermissionTransfer());
            $permissionCollectionTransfer->addPermission($permissionTransfer);
        }

        return $permissionCollectionTransfer;
    }

    /**
     * @param \Orm\Zed\Permission\Persistence\SpyPermission $permissionEntity
     * @param \Generated\Shared\Transfer\PermissionTransfer $permissionTransfer
     *
     * @return \Generated\Shared\Transfer\PermissionTransfer
     */
    public function mapPermissionEntityToTransfer(
        SpyPermission $permissionEntity,
        PermissionTransfer $permissionTransfer
    ) {
        return $permissionTransfer->fromArray($permissionEntity->toArray(), true);
    }
}
