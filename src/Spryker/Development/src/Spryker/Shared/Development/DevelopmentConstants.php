<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Development;

/**
 * Declares global environment configuration keys. Do not use it for other class constants.
 */
interface DevelopmentConstants
{
    const COMPOSER_REQUIRE_VERSION = 'COMPOSER_REQUIRE_VERSION';
    const COMPOSER_REQUIRE_VERSION_EXTERNAL = 'COMPOSER_REQUIRE_VERSION_EXTERNAL';
    const COMPOSER_BRANCH_ALIAS = 'COMPOSER_BRANCH_ALIAS';

    /**
     * @see \Spryker\Shared\Kernel\KernelConstants::PROJECT_NAMESPACE
     */
    const PROJECT_NAMESPACES = 'PROJECT_NAMESPACES';

    /**
     * @see \Spryker\Shared\Kernel\KernelConstants::CORE_NAMESPACES
     */
    const CORE_NAMESPACES = 'CORE_NAMESPACES';

    /**
     * Specification:
     * - Sets the permission mode for generated files/directories.
     */
    const PERMISSION_MODE = 'DEVELOPMENT:PERMISSION_MODE';
}
