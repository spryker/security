<?php
/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\GlueApplication\Dependency\Client;

use Generated\Shared\Transfer\StoreTransfer;

interface GlueApplicationToStoreClientInterface
{
    /**
     * @return \Generated\Shared\Transfer\StoreTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function getCurrentStore(): StoreTransfer;
}
