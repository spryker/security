<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsContentWidget\Business\ContentWidget;

use Generated\Shared\Transfer\CmsContentWidgetConfigurationListTransfer;
use Generated\Shared\Transfer\CmsContentWidgetConfigurationTransfer;
use Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface;

class ContentWidgetConfigurationListProvider implements ContentWidgetConfigurationListProviderInterface
{
    /**
     * @var \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface[]
     */
    protected $contentWidgetConfigurationProviders = [];

    /**
     * @param \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface[] $contentWidgetConfigurationProviders
     */
    public function __construct(array $contentWidgetConfigurationProviders)
    {
        $this->contentWidgetConfigurationProviders = $contentWidgetConfigurationProviders;
    }

    /**
     * @return \Generated\Shared\Transfer\CmsContentWidgetConfigurationListTransfer
     */
    public function getContentWidgetConfigurationList()
    {
        $cmsContentConfigurationList = new CmsContentWidgetConfigurationListTransfer();
        foreach ($this->contentWidgetConfigurationProviders as $contentWidgetConfigurationProvider) {
            $cmsContentWidgetConfigurationTransfer = $this->mapCmsContentWidgetConfigurationTransfer(
                $contentWidgetConfigurationProvider->getFunctionName(),
                $contentWidgetConfigurationProvider
            );
            $cmsContentConfigurationList->addCmsContentWidgetConfiguration($cmsContentWidgetConfigurationTransfer);
        }

        return $cmsContentConfigurationList;
    }

    /**
     * @param string $functionName
     * @param \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface $contentWidgetConfigurationProvider
     *
     * @return \Generated\Shared\Transfer\CmsContentWidgetConfigurationTransfer
     */
    protected function mapCmsContentWidgetConfigurationTransfer(
        $functionName,
        CmsContentWidgetConfigurationProviderInterface $contentWidgetConfigurationProvider
    ) {
        $cmsContentWidgetConfigurationTransfer = new CmsContentWidgetConfigurationTransfer();
        $cmsContentWidgetConfigurationTransfer->setFunctionName($functionName);
        $cmsContentWidgetConfigurationTransfer->setTemplates($contentWidgetConfigurationProvider->getAvailableTemplates());
        $cmsContentWidgetConfigurationTransfer->setUsageInformation($contentWidgetConfigurationProvider->getUsageInformation());

        return $cmsContentWidgetConfigurationTransfer;
    }
}
