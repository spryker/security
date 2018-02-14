<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\FileManager;

use Spryker\Service\Kernel\AbstractBundleConfig;
use Spryker\Shared\FileManager\FileManagerConstants;

class FileManagerServiceConfig extends AbstractBundleConfig
{
    /**
     * @return mixed
     */
    public function getStorageName()
    {
        return $this->get(FileManagerConstants::STORAGE_NAME);
    }
}
