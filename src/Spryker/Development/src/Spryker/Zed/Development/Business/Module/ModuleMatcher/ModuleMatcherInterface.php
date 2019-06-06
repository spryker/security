<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business\Module\ModuleMatcher;

use Generated\Shared\Transfer\ModuleFilterTransfer;
use Generated\Shared\Transfer\ModuleTransfer;

/**
 * @deprecated Use `spryker/module-finder` instead.
 */
interface ModuleMatcherInterface
{
    /**
     * @param \Generated\Shared\Transfer\ModuleTransfer $moduleTransfer
     * @param \Generated\Shared\Transfer\ModuleFilterTransfer $moduleFilterTransfer
     *
     * @return bool
     */
    public function matches(ModuleTransfer $moduleTransfer, ModuleFilterTransfer $moduleFilterTransfer): bool;
}
