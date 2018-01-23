<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\FileManager\Business\Model;

interface FileRollbackInterface
{
    /**
     * @param int $idFile
     * @param int $idFileInfo
     *
     * @return void
     */
    public function rollback(int $idFile, int $idFileInfo);
}
