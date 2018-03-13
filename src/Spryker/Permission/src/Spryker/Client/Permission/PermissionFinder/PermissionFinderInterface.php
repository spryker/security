<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Permission\PermissionFinder;

use Generated\Shared\Transfer\PermissionCollectionTransfer;

interface PermissionFinderInterface
{
    /**
     * Specification:
     * - Configures a permission by its transfer
     *
     * @param string $permissionKey
     *
     * @return \Spryker\Shared\PermissionExtension\Dependency\Plugin\ExecutablePermissionPluginInterface
     */
    public function findPermissionPlugin($permissionKey);

    /**
     * @return \Generated\Shared\Transfer\PermissionCollectionTransfer
     */
    public function getRegisteredPermissionCollection(): PermissionCollectionTransfer;
}
