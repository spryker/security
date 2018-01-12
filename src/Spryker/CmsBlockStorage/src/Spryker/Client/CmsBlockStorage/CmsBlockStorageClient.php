<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\CmsBlockStorage;

use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\CmsBlockStorage\CmsBlockStorageFactory getFactory()
 */
class CmsBlockStorageClient extends AbstractClient implements CmsBlockStorageClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string[] $blockNames
     * @param string $localeName
     *
     * @return array
     */
    public function findBlocksByNames($blockNames, $localeName)
    {
        return $this->getFactory()
            ->createCmsBlockStorage()
            ->getBlocksByNames($blockNames, $localeName);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $options
     * @param string $localName
     *
     * @return array
     */
    public function findBlockNamesByOptions(array $options, $localName)
    {
        return $this->getFactory()
            ->createCmsBlockStorage()
            ->getBlockNamesByOptions($options, $localName);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $name
     *
     * @return string
     */
    public function generateBlockNameKey($name)
    {
        return $this->getFactory()
            ->createCmsBlockStorage()
            ->generateBlockNameKey($name);
    }
}
