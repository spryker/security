<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSearchConfigStorage\Business\Storage;

interface ProductSearchConfigStorageWriterInterface
{
    /**
     * @return void
     */
    public function publish();

    /**
     * @return void
     */
    public function unpublish();
}
