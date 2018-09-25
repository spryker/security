<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\IndexGenerator;

use Spryker\Shared\Kernel\KernelConstants;
use Spryker\Zed\Kernel\AbstractBundleConfig;

class IndexGeneratorConfig extends AbstractBundleConfig
{
    /**
     * @return string[]
     */
    public function getExcludedTables(): array
    {
        return [];
    }

    /**
     * @return string
     */
    public function getTargetDirectory(): string
    {
        $projectNamespace = $this->get(KernelConstants::PROJECT_NAMESPACE);
        $targetPropelSchemaDirectory = implode(DIRECTORY_SEPARATOR, [
            APPLICATION_SOURCE_DIR,
            $projectNamespace,
            'Zed',
            'IndexGenerator',
            'Persistence',
            'Propel',
            'Schema',
        ]);

        return $targetPropelSchemaDirectory;
    }

    /**
     * @return string
     */
    public function getPathToMergedSchemas(): string
    {
        return implode(DIRECTORY_SEPARATOR, [APPLICATION_SOURCE_DIR, 'Orm', 'Propel', APPLICATION_STORE, 'Schema']);
    }
}
