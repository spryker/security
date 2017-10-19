<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Transfer\Business\Model\Generator;

class EntityTransferDefinitionLoader extends TransferDefinitionLoader
{
    const KEY_TABLE = 'table';
    const ENTITY_SCHEMA_SUFFIX = '.schema.xml';
    const PREFIX_LENGTH = 4;

    /**
     * @param string $fileName
     *
     * @return string
     */
    protected function getBundleFromPathName($fileName)
    {
        return '';
    }

    /**
     * @param array $definition
     * @param string $bundle
     * @param string $containingBundle
     *
     * @return void
     */
    protected function addDefinition(array $definition, $bundle, $containingBundle)
    {
        if (isset($definition[static::KEY_TABLE][0])) {
            foreach ($definition[static::KEY_TABLE] as $table) {
                $table[self::KEY_BUNDLE] = $bundle;
                $table[self::KEY_CONTAINING_BUNDLE] = $containingBundle;

                $this->transferDefinitions[] = $table;
            }
        } else {
            $table = $definition[static::KEY_TABLE];

            $table[self::KEY_BUNDLE] = $bundle;
            $table[self::KEY_CONTAINING_BUNDLE] = $containingBundle;
            $this->transferDefinitions[] = $table;
        }
    }
}
