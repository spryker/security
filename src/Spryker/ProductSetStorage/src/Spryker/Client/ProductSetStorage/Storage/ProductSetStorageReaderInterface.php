<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductSetStorage\Storage;

interface ProductSetStorageReaderInterface
{
    /**
     * @param int $idProductSet
     * @param string $localeName
     *
     * @return \Generated\Shared\Transfer\ProductSetDataStorageTransfer|null
     */
    public function getProductSetByIdProductSet($idProductSet, $localeName);
}
