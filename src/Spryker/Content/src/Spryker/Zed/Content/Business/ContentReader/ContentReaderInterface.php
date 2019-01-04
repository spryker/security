<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Content\Business\ContentReader;

use Generated\Shared\Transfer\ContentTransfer;

interface ContentReaderInterface
{
    /**
     * @param int $id
     *
     * @return \Generated\Shared\Transfer\ContentTransfer|null
     */
    public function findContentById(int $id): ?ContentTransfer;

    /**
     * @param string $uuid
     *
     * @return \Generated\Shared\Transfer\ContentTransfer|null
     */
    public function findContentByUUID(string $uuid): ?ContentTransfer;
}
