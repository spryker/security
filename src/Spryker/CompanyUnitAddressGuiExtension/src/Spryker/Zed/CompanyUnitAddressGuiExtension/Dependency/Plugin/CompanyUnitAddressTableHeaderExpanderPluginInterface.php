<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyUnitAddressGuiExtension\Dependency\Plugin;

interface CompanyUnitAddressTableHeaderExpanderPluginInterface
{
    /**
     * Specification:
     * - Expands array of header columns
     *
     * @api
     *
     * @return array
     */
    public function expandHeader(): array;
}
