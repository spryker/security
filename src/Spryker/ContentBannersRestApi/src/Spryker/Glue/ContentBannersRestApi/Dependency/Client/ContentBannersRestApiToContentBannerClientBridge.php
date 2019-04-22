<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ContentBannersRestApi\Dependency\Client;

use Generated\Shared\Transfer\ContentBannerTypeTransfer;

class ContentBannersRestApiToContentBannerClientBridge implements ContentBannersRestApiToContentBannerClientInterface
{
    /**
     * @var \Spryker\Client\ContentBanner\ContentBannerClientInterface
     */
    protected $contentBannerClient;

    /**
     * @param \Spryker\Client\ContentBanner\ContentBannerClientInterface $contentBannerClient
     */
    public function __construct($contentBannerClient)
    {
        $this->contentBannerClient = $contentBannerClient;
    }

    /**
     * @param int $idContent
     * @param string $localeName
     *
     * @return \Generated\Shared\Transfer\ContentBannerTypeTransfer|null
     */
    public function executeBannerTypeById(int $idContent, string $localeName): ?ContentBannerTypeTransfer
    {
        return $this->contentBannerClient->executeBannerTypeById($idContent, $localeName);
    }
}
