<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteApproval\Dependency\Facade;

interface QuoteApprovalToPermissionFacadeInterface
{
    /**
     * @param string $permissionKey
     * @param int|string $identifier
     * @param int|string|array|null $context
     *
     * @return bool
     */
    public function can($permissionKey, $identifier, $context = null): bool;
}
