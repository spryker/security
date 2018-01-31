<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business\Dependency;

interface ManagerInterface
{
    /**
     * @param string $moduleName
     *
     * @return array
     */
    public function parseIncomingDependencies($moduleName);

    /**
     * @return array
     */
    public function collectAllModules();
}
