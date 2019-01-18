<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ContentStorage;

use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\ContentStorage\ContentStorageFactory getFactory()
 */
class ContentStorageClient extends AbstractClient implements ContentStorageClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idContent
     * @param string $localeName
     *
     * @return array|null
     */
    public function findContentById(int $idContent, string $localeName): ?array
    {
        return $this->getFactory()
            ->createContentStorage()
            ->findContentById($idContent, $localeName);
    }
}
