<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\FileManager\Business\Model;

interface FileRollbackInterface
{
    /**
     * @param int $fileId
     * @param int $fileInfoId
     *
     * @return void
     */
    public function rollback(int $fileId, int $fileInfoId);
}
