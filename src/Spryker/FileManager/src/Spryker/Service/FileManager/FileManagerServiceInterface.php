<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\FileManager;

interface FileManagerServiceInterface
{
    /**
     * Specification:
     * - Reads the file
     *
     * @api
     *
     * @param string $fileName
     *
     * @return \Generated\Shared\Transfer\FileManagerDataTransfer
     */
    public function read(string $fileName);

    /**
     * Specification:
     * - Retrieves a read-stream for the file
     *
     * @api
     *
     * @param string $fileName
     *
     * @return mixed
     */
    public function readStream(string $fileName);
}
